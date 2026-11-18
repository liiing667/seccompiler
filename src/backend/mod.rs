// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! This module defines the data structures used for the intermmediate representation (IR),
//! as well as the logic for compiling the filter into BPF code, the final form of the filter.

mod bpf;
mod condition;
mod filter;
mod rule;

pub use condition::SeccompCondition;
pub use filter::SeccompFilter;
pub use rule::SeccompRule;

#[cfg(feature = "json")]
use serde::Deserialize;

use core::fmt::Formatter;
use std::fmt::Display;

// See /usr/include/linux/seccomp.h
use libc::{
    SECCOMP_RET_ALLOW, SECCOMP_RET_DATA, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
    SECCOMP_RET_KILL_THREAD, SECCOMP_RET_LOG, SECCOMP_RET_TRACE, SECCOMP_RET_TRAP,
    SECCOMP_RET_USER_NOTIF,
};

use bpf::{ARG_NUMBER_MAX, AUDIT_ARCH_AARCH64, AUDIT_ARCH_RISCV64, AUDIT_ARCH_X86_64, BPF_MAX_LEN};

pub use bpf::{sock_filter, BpfProgram, BpfProgramRef};

/// Backend Result type.
type Result<T> = std::result::Result<T, Error>;

/// Backend-related errors.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Attempting to associate an empty vector of conditions to a rule.
    EmptyRule,
    /// Filter exceeds the maximum number of instructions that a BPF program can have.
    ///
    /// `length` is the total length of the laid-out program and `location` identifies the part of
    /// the filter whose instructions pushed the program over the [`BPF_MAX_LEN`] budget.
    FilterTooLarge {
        /// Total length, in BPF instructions, of the laid-out program.
        length: usize,
        /// Part of the filter that caused the budget to be exceeded.
        location: CodegenLocation,
    },
    /// Filter and default actions are equal.
    IdenticalActions,
    /// Argument index of a `SeccompCondition` exceeds the maximum linux syscall index.
    InvalidArgumentNumber,
    /// Invalid TargetArch.
    InvalidTargetArch(String),
    /// A jump offset cannot be encoded or does not point inside the program.
    ///
    /// Conditional jump offsets must fit in a `u8` and every jump target must stay within the
    /// program. `offset` is the offending offset, `index` the position of the jump instruction in
    /// the laid-out program and `location` the part of the filter the jump belongs to.
    JumpOutOfRange {
        /// Offending relative jump offset, in BPF instructions.
        offset: usize,
        /// Index of the jump instruction in the laid-out program.
        index: usize,
        /// Part of the filter that produced the jump.
        location: CodegenLocation,
    },
}

/// Position of a piece of generated BPF code within the logical structure of a filter.
///
/// Every error reported by the layout phase carries one of these locations so that the rule,
/// syscall chain or fixed prologue/epilogue responsible for a boundary violation can be
/// identified without reproducing the whole program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodegenLocation {
    /// Fixed architecture validation prologue.
    ArchValidation,
    /// Instruction loading the syscall number.
    SyscallNumberLoad,
    /// Syscall number comparison of a rule chain. Holds the syscall number.
    SyscallChain(i64),
    /// Rule entry/exit jumps. Holds the syscall number and the index of the rule in its chain.
    Rule {
        /// Syscall number the rule belongs to. `None` when a rule is compiled on its own.
        syscall: Option<i64>,
        /// Zero-based index of the rule within the syscall chain.
        rule_index: usize,
    },
    /// Condition of a rule. Holds the syscall number, the rule index and the condition index.
    Condition {
        /// Syscall number the rule belongs to. `None` when a rule is compiled on its own.
        syscall: Option<i64>,
        /// Zero-based index of the rule within the syscall chain.
        rule_index: usize,
        /// Zero-based index of the condition within the rule.
        condition_index: usize,
    },
    /// Helper jumps inserted to bridge jumps longer than a `u8` offset.
    HelperJump {
        /// Syscall number the rule belongs to. `None` when a rule is compiled on its own.
        syscall: Option<i64>,
        /// Zero-based index of the rule within the syscall chain.
        rule_index: usize,
    },
    /// Return action of a matched rule.
    MatchReturn(i64),
    /// Default action reached when a syscall number matches but no rule does.
    ChainMismatchReturn(i64),
    /// Final default action reached when no syscall number matches.
    DefaultReturn,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            EmptyRule => {
                write!(f, "The condition vector of a rule cannot be empty.")
            }
            FilterTooLarge { length, location } => write!(
                f,
                "The seccomp filter contains too many BPF instructions: {} (max {}). The budget \
                 was exceeded while generating {}.",
                length, BPF_MAX_LEN, location
            ),
            IdenticalActions => write!(f, "`match_action` and `mismatch_action` are equal."),
            InvalidArgumentNumber => {
                write!(
                    f,
                    "The seccomp rule contains an invalid argument index. Maximum index value: {}",
                    ARG_NUMBER_MAX
                )
            }
            InvalidTargetArch(arch) => write!(f, "Invalid target arch: {}.", arch),
            JumpOutOfRange {
                offset,
                index,
                location,
            } => write!(
                f,
                "BPF jump at instruction {} cannot be encoded with the offset {} (conditional \
                 jumps are limited to a u8 range and targets must stay inside the program), \
                 while generating {}.",
                index, offset, location
            ),
        }
    }
}

impl Display for CodegenLocation {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            CodegenLocation::ArchValidation => write!(f, "the architecture validation prologue"),
            CodegenLocation::SyscallNumberLoad => write!(f, "the syscall number load"),
            CodegenLocation::SyscallChain(syscall) => {
                write!(f, "the rule chain of syscall {}", syscall)
            }
            CodegenLocation::Rule {
                syscall,
                rule_index,
            } => write!(
                f,
                "rule {}{}",
                rule_index,
                syscall
                    .map(|syscall| format!(" of syscall {}", syscall))
                    .unwrap_or_default()
            ),
            CodegenLocation::Condition {
                syscall,
                rule_index,
                condition_index,
            } => write!(
                f,
                "condition {} of rule {}{}",
                condition_index,
                rule_index,
                syscall
                    .map(|syscall| format!(" of syscall {}", syscall))
                    .unwrap_or_default()
            ),
            CodegenLocation::HelperJump {
                syscall,
                rule_index,
            } => write!(
                f,
                "a helper jump of rule {}{}",
                rule_index,
                syscall
                    .map(|syscall| format!(" of syscall {}", syscall))
                    .unwrap_or_default()
            ),
            CodegenLocation::MatchReturn(syscall) => {
                write!(f, "the match action of syscall {}", syscall)
            }
            CodegenLocation::ChainMismatchReturn(syscall) => {
                write!(f, "the mismatch action of syscall {}", syscall)
            }
            CodegenLocation::DefaultReturn => write!(f, "the final default action"),
        }
    }
}

/// Supported target architectures.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TargetArch {
    /// x86_64 arch
    x86_64,
    /// aarch64 arch
    aarch64,
    /// riscv64 arch
    riscv64,
}

impl TargetArch {
    /// Get the arch audit value. Used for the runtime arch check embedded in the BPF filter.
    fn get_audit_value(self) -> u32 {
        match self {
            TargetArch::x86_64 => AUDIT_ARCH_X86_64,
            TargetArch::aarch64 => AUDIT_ARCH_AARCH64,
            TargetArch::riscv64 => AUDIT_ARCH_RISCV64,
        }
    }
}

impl TryFrom<&str> for TargetArch {
    type Error = Error;
    fn try_from(input: &str) -> Result<Self> {
        match input.to_lowercase().as_str() {
            "x86_64" => Ok(TargetArch::x86_64),
            "aarch64" => Ok(TargetArch::aarch64),
            "riscv64" => Ok(TargetArch::riscv64),
            _ => Err(Error::InvalidTargetArch(input.to_string())),
        }
    }
}

/// Comparison to perform when matching a condition.
#[cfg_attr(
    feature = "json",
    derive(Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeccompCmpOp {
    /// Argument value is equal to the specified value.
    Eq,
    /// Argument value is greater than or equal to the specified value.
    Ge,
    /// Argument value is greater than specified value.
    Gt,
    /// Argument value is less than or equal to the specified value.
    Le,
    /// Argument value is less than specified value.
    Lt,
    /// Masked bits of argument value are equal to masked bits of specified value.
    MaskedEq(u64),
    /// Argument value is not equal to specified value.
    Ne,
}

/// Seccomp argument value length.
#[cfg_attr(feature = "json", derive(Deserialize), serde(rename_all = "lowercase"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeccompCmpArgLen {
    /// Argument value length is 4 bytes.
    Dword,
    /// Argument value length is 8 bytes.
    Qword,
}

/// Actions that a seccomp filter can return for a syscall.
#[cfg_attr(
    feature = "json",
    derive(Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeccompAction {
    /// Allows syscall.
    Allow,
    /// Returns from syscall with specified error number.
    Errno(u32),
    /// Kills calling thread.
    KillThread,
    /// Kills calling process.
    KillProcess,
    /// Allows syscall after logging it.
    Log,
    /// Notifies tracing process of the caller with respective number.
    Trace(u32),
    /// Sends `SIGSYS` to the calling process.
    Trap,
    /// Notifies user-space.
    UserNotif,
}

impl From<SeccompAction> for u32 {
    /// Return codes of the BPF program for each action.
    ///
    /// # Arguments
    ///
    /// * `action` - The [`SeccompAction`] that the kernel will take.
    ///
    /// [`SeccompAction`]: enum.SeccompAction.html
    fn from(action: SeccompAction) -> Self {
        match action {
            SeccompAction::Allow => SECCOMP_RET_ALLOW,
            SeccompAction::Errno(x) => SECCOMP_RET_ERRNO | (x & SECCOMP_RET_DATA),
            SeccompAction::KillThread => SECCOMP_RET_KILL_THREAD,
            SeccompAction::KillProcess => SECCOMP_RET_KILL_PROCESS,
            SeccompAction::Log => SECCOMP_RET_LOG,
            SeccompAction::Trace(x) => SECCOMP_RET_TRACE | (x & SECCOMP_RET_DATA),
            SeccompAction::Trap => SECCOMP_RET_TRAP,
            SeccompAction::UserNotif => SECCOMP_RET_USER_NOTIF,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_arch() {
        assert!(TargetArch::try_from("invalid").is_err());
        assert!(TargetArch::try_from("x8664").is_err());

        assert_eq!(TargetArch::try_from("x86_64").unwrap(), TargetArch::x86_64);
        assert_eq!(TargetArch::try_from("X86_64").unwrap(), TargetArch::x86_64);

        assert_eq!(
            TargetArch::try_from("aarch64").unwrap(),
            TargetArch::aarch64
        );
        assert_eq!(
            TargetArch::try_from("aARch64").unwrap(),
            TargetArch::aarch64
        );

        assert_eq!(
            TargetArch::try_from("riscv64").unwrap(),
            TargetArch::riscv64
        );
        assert_eq!(
            TargetArch::try_from("RiScV64").unwrap(),
            TargetArch::riscv64
        );
    }
}
