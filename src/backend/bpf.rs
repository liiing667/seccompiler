// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Define constants, helpers and types used for BPF codegen.

use super::TargetArch;

/// Program made up of a sequence of BPF instructions.
pub type BpfProgram = Vec<sock_filter>;

/// Reference to program made up of a sequence of BPF instructions.
pub type BpfProgramRef<'a> = &'a [sock_filter];

// The maximum number of a syscall argument.
// A syscall can have at most 6 arguments.
// Arguments are numbered from 0 to 5.
pub const ARG_NUMBER_MAX: u8 = 5;

// The maximum number of BPF statements that a condition will be translated into.
// This is not a linux requirement but is based on the current BPF compilation logic.
// This is used in the backend code for preallocating vectors and for detecting unjumpable offsets.
pub const CONDITION_MAX_LEN: u8 = 6;

// The maximum seccomp-BPF program length allowed by the linux kernel.
pub const BPF_MAX_LEN: usize = 4096;

// The largest encodable offset of a conditional jump (`jt`/`jf` are `u8`).
const CONDITIONAL_JUMP_MAX_OFFSET: usize = u8::MAX as usize;

// `struct seccomp_data` offsets and sizes of fields in bytes:
//
// ```c
// struct seccomp_data {
//     int nr;
//     __u32 arch;
//     __u64 instruction_pointer;
//     __u64 args[6];
// };
// ```
pub const SECCOMP_DATA_NR_OFFSET: u8 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u8 = 4;
pub const SECCOMP_DATA_ARGS_OFFSET: u8 = 16;
pub const SECCOMP_DATA_ARG_SIZE: u8 = 8;

// Builds a `jump` BPF instruction.
//
// # Arguments
//
// * `code` - The operation code.
// * `jt` - The jump offset in case the operation returns `true`.
// * `jf` - The jump offset in case the operation returns `false`.
// * `k` - The operand.
#[inline(always)]
pub(crate) fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

/// A BPF instruction whose jump offsets are still expressed as `usize` values.
///
/// The layout phase of the compiler produces a sequence of these instructions. Offsets are only
/// narrowed to the wire format (`u8` for conditional jumps, the `k` field for unconditional jumps)
/// during the emission phase, after every jump has been proven reachable and the whole program
/// has been proven to fit within [`BPF_MAX_LEN`]. This keeps all arithmetic in `usize` and makes
/// it impossible to silently wrap an offset into a smaller type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PlannedInstruction {
    /// Instruction that never changes the program counter (loads, ALU ops, returns).
    Statement {
        /// The operation code.
        code: u16,
        /// The operand.
        k: u32,
    },
    /// Conditional jump. `jt`/`jf` are relative offsets in number of instructions.
    ConditionalJump {
        /// The operation code.
        code: u16,
        /// The operand.
        k: u32,
        /// The jump offset in case the operation returns `true`.
        jt: usize,
        /// The jump offset in case the operation returns `false`.
        jf: usize,
    },
    /// Unconditional jump. The relative offset is carried in the `k` field of the wire format.
    Jump {
        /// Relative offset in number of instructions.
        offset: usize,
    },
}

/// Builds a planned statement.
#[inline(always)]
pub(crate) fn planned_stmt(code: u16, k: u32) -> PlannedInstruction {
    PlannedInstruction::Statement { code, k }
}

/// Builds a planned conditional jump.
#[inline(always)]
pub(crate) fn planned_cond_jump(code: u16, k: u32, jt: usize, jf: usize) -> PlannedInstruction {
    PlannedInstruction::ConditionalJump { code, k, jt, jf }
}

/// Builds a planned unconditional jump.
#[inline(always)]
pub(crate) fn planned_jump(offset: usize) -> PlannedInstruction {
    PlannedInstruction::Jump { offset }
}

/// Builds the planned version of the architecture validation sequence.
pub(crate) fn build_planned_arch_validation_sequence(
    target_arch: TargetArch,
) -> Vec<PlannedInstruction> {
    let audit_arch_value = target_arch.get_audit_value();
    vec![
        planned_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET as u32),
        planned_cond_jump(BPF_JMP | BPF_JEQ | BPF_K, audit_arch_value, 1, 0),
        planned_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_KILL_PROCESS),
    ]
}

/// Verifies that every jump of a planned program is reachable and encodable.
///
/// Each jump target must stay inside the program and every conditional jump offset must fit in a
/// `u8`, while unconditional jump offsets must fit in the `k` (`u32`) field.
///
/// Returns the index of the first offending instruction together with the offending offset,
/// if any.
pub(crate) fn find_invalid_jump(program: &[PlannedInstruction]) -> Option<(usize, usize)> {
    program.iter().enumerate().find_map(|(index, instruction)| {
        let check = |offset: usize| {
            // A jump moves the program counter relative to the instruction following the jump,
            // hence the `index + 1` base.
            let target = index.checked_add(1)?.checked_add(offset)?;
            (target < program.len()).then_some(())
        };

        let offending_offset: Option<usize> = match instruction {
            PlannedInstruction::Statement { .. } => None,
            PlannedInstruction::ConditionalJump { jt, jf, .. } => {
                if *jt > CONDITIONAL_JUMP_MAX_OFFSET || check(*jt).is_none() {
                    Some(*jt)
                } else if *jf > CONDITIONAL_JUMP_MAX_OFFSET || check(*jf).is_none() {
                    Some(*jf)
                } else {
                    None
                }
            }
            PlannedInstruction::Jump { offset } => {
                if *offset > u32::MAX as usize || check(*offset).is_none() {
                    Some(*offset)
                } else {
                    None
                }
            }
        };

        offending_offset.map(|offset| (index, offset))
    })
}

/// Emits a validated planned program into the final [`sock_filter`] representation.
///
/// The caller must have previously checked the length budget and the jump offsets with
/// [`find_invalid_jump`]; the narrowing conversions below are therefore infallible.
pub(crate) fn emit_program(program: Vec<PlannedInstruction>) -> BpfProgram {
    program
        .into_iter()
        .map(|instruction| match instruction {
            PlannedInstruction::Statement { code, k } => bpf_stmt(code, k),
            PlannedInstruction::ConditionalJump { code, k, jt, jf } => {
                bpf_jump(
                    code, k,
                    // Safe because the layout validation proved both offsets fit in a `u8`.
                    jt as u8, jf as u8,
                )
            }
            PlannedInstruction::Jump { offset } => bpf_stmt(BPF_JMP | BPF_JA, offset as u32),
        })
        .collect()
}

// Builds a "statement" BPF instruction.
//
// # Arguments
//
// * `code` - The operation code.
// * `k` - The operand.
#[inline(always)]
pub(crate) fn bpf_stmt(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

// Builds a sequence of BPF instructions that validate the underlying architecture.
#[cfg(test)]
#[inline(always)]
pub(crate) fn build_arch_validation_sequence(target_arch: TargetArch) -> Vec<sock_filter> {
    let audit_arch_value = target_arch.get_audit_value();
    vec![
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET as u32),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, audit_arch_value, 1, 0),
        bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_KILL_PROCESS),
    ]
}

// BPF Instruction classes.
// See /usr/include/linux/bpf_common.h .
// Load operation.
pub const BPF_LD: u16 = 0x00;
// ALU operation.
pub const BPF_ALU: u16 = 0x04;
// Jump operation.
pub const BPF_JMP: u16 = 0x05;
// Return operation.
pub const BPF_RET: u16 = 0x06;

// BPF ld/ldx fields.
// See /usr/include/linux/bpf_common.h .
// Operand size is a word.
pub const BPF_W: u16 = 0x00;
// Load from data area (where `seccomp_data` is).
pub const BPF_ABS: u16 = 0x20;

// BPF alu fields.
// See /usr/include/linux/bpf_common.h .
pub const BPF_AND: u16 = 0x50;

// BPF jmp fields.
// See /usr/include/linux/bpf_common.h .
// Unconditional jump.
pub const BPF_JA: u16 = 0x00;
// Jump with comparisons.
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
// Test against the value in the K register.
pub const BPF_K: u16 = 0x00;

// Architecture identifier for x86_64 LE.
// See /usr/include/linux/audit.h .
// Defined as:
// `#define AUDIT_ARCH_X86_64	(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)`
pub const AUDIT_ARCH_X86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;

// Architecture identifier for aarch64 LE.
// Defined as:
// `#define AUDIT_ARCH_AARCH64	(EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)`
pub const AUDIT_ARCH_AARCH64: u32 = 183 | 0x8000_0000 | 0x4000_0000;

// Architecture identifier for riscv64 LE.
// Defined as:
// `#define AUDIT_ARCH_RISCV64  (EM_RISCV|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)`
pub const AUDIT_ARCH_RISCV64: u32 = 243 | 0x8000_0000 | 0x4000_0000;

/// BPF instruction structure definition.
// See /usr/include/linux/filter.h .
// We cannot use the `libc::sock_filter` definition since it doesn't implement `Debug` and
// `PartialEq`.
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct sock_filter {
    /// Code of the instruction.
    pub code: ::std::os::raw::c_ushort,
    /// Jump if true offset.
    pub jt: ::std::os::raw::c_uchar,
    /// Jump if false offset.
    pub jf: ::std::os::raw::c_uchar,
    /// Immediate value.
    pub k: ::std::os::raw::c_uint,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_functions() {
        // Compares the output of the BPF instruction generating functions to hardcoded
        // instructions.
        assert_eq!(
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16),
            sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 16,
            }
        );
        assert_eq!(
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 10, 2, 5),
            sock_filter {
                code: 0x15,
                jt: 2,
                jf: 5,
                k: 10,
            }
        );
    }

    #[test]
    fn test_find_invalid_jump_accepts_valid_program() {
        // A conditional jump reaching the last instruction and an unconditional jump in range.
        let program = vec![
            planned_cond_jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 3, 0),
            planned_jump(2),
            planned_stmt(BPF_LD | BPF_W | BPF_ABS, 0),
            planned_stmt(BPF_LD | BPF_W | BPF_ABS, 0),
            planned_stmt(BPF_RET | BPF_K, 0),
        ];
        assert_eq!(find_invalid_jump(&program), None);

        // Offsets of exactly u8::MAX are encodable as long as the target exists.
        let mut max_program = vec![planned_cond_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            0,
            u8::MAX as usize,
            0,
        )];
        max_program.extend((0..=u8::MAX as usize).map(|_| planned_stmt(BPF_RET | BPF_K, 0)));
        assert_eq!(find_invalid_jump(&max_program), None);
    }

    #[test]
    fn test_find_invalid_jump_detects_u8_overflow() {
        // Conditional jump offset larger than u8::MAX cannot be encoded without wrapping.
        let program = vec![
            planned_cond_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, u8::MAX as usize + 1, 0),
            planned_stmt(BPF_RET | BPF_K, 0),
        ];
        assert_eq!(find_invalid_jump(&program), Some((0, u8::MAX as usize + 1)));
    }

    #[test]
    fn test_find_invalid_jump_detects_escaping_target() {
        // A jump (even with a small offset) must not escape past the end of the program.
        let escaping = vec![
            planned_cond_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 5),
            planned_stmt(BPF_RET | BPF_K, 0),
        ];
        assert_eq!(find_invalid_jump(&escaping), Some((0, 5)));

        let escaping_ja = vec![planned_jump(10), planned_stmt(BPF_RET | BPF_K, 0)];
        assert_eq!(find_invalid_jump(&escaping_ja), Some((0, 10)));
    }

    #[test]
    fn test_emit_program_narrows_validated_offsets() {
        let planned = vec![
            planned_cond_jump(BPF_JMP | BPF_JEQ | BPF_K, 7, 1, 0),
            planned_jump(2),
            planned_stmt(BPF_RET | BPF_K, 1),
            planned_stmt(BPF_RET | BPF_K, 2),
        ];
        assert_eq!(
            emit_program(planned),
            vec![
                bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 7, 1, 0),
                bpf_stmt(BPF_JMP | BPF_JA, 2),
                bpf_stmt(BPF_RET | BPF_K, 1),
                bpf_stmt(BPF_RET | BPF_K, 2),
            ]
        );
    }
}
