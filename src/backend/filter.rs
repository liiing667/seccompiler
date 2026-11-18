// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::collections::BTreeMap;

use crate::backend::bpf::*;
use crate::backend::rule::SeccompRule;
use crate::backend::{CodegenLocation, Error, Result, SeccompAction, TargetArch};

/// Filter containing rules assigned to syscall numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeccompFilter {
    /// Map of syscall numbers and corresponding rule chains.
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    /// Default action to apply to syscalls that do not match the filter.
    mismatch_action: SeccompAction,
    /// Filter action to apply to syscalls that match the filter.
    match_action: SeccompAction,
    /// Target architecture of the generated BPF filter.
    target_arch: TargetArch,
}

impl SeccompFilter {
    /// Creates a new filter with a set of rules, an on-match and default action.
    ///
    /// # Arguments
    ///
    /// * `rules` - Map containing syscall numbers and their respective [`SeccompRule`]s.
    /// * `mismatch_action` - [`SeccompAction`] taken for all syscalls that do not match the filter.
    /// * `match_action` - [`SeccompAction`] taken for system calls that match the filter.
    /// * `target_arch` - Target architecture of the generated BPF filter.
    ///
    /// # Example
    ///
    /// ```
    /// use seccompiler::{
    ///     SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    /// };
    /// use std::convert::TryInto;
    ///
    /// let filter = SeccompFilter::new(
    ///     vec![
    ///         (libc::SYS_accept4, vec![]),
    ///         (
    ///             libc::SYS_fcntl,
    ///             vec![
    ///                 SeccompRule::new(vec![
    ///                     SeccompCondition::new(
    ///                         1,
    ///                         SeccompCmpArgLen::Dword,
    ///                         SeccompCmpOp::Eq,
    ///                         libc::F_SETFD as u64,
    ///                     )
    ///                     .unwrap(),
    ///                     SeccompCondition::new(
    ///                         2,
    ///                         SeccompCmpArgLen::Dword,
    ///                         SeccompCmpOp::Eq,
    ///                         libc::FD_CLOEXEC as u64,
    ///                     )
    ///                     .unwrap(),
    ///                 ])
    ///                 .unwrap(),
    ///                 SeccompRule::new(vec![SeccompCondition::new(
    ///                     1,
    ///                     SeccompCmpArgLen::Dword,
    ///                     SeccompCmpOp::Eq,
    ///                     libc::F_GETFD as u64,
    ///                 )
    ///                 .unwrap()])
    ///                 .unwrap(),
    ///             ],
    ///         ),
    ///     ]
    ///     .into_iter()
    ///     .collect(),
    ///     SeccompAction::Trap,
    ///     SeccompAction::Allow,
    ///     std::env::consts::ARCH.try_into().unwrap(),
    /// );
    /// ```
    ///
    /// [`SeccompRule`]: struct.SeccompRule.html
    /// [`SeccompAction`]: enum.SeccompAction.html
    pub fn new(
        rules: BTreeMap<i64, Vec<SeccompRule>>,
        mismatch_action: SeccompAction,
        match_action: SeccompAction,
        target_arch: TargetArch,
    ) -> Result<Self> {
        let instance = Self {
            rules,
            mismatch_action,
            match_action,
            target_arch,
        };

        instance.validate()?;

        Ok(instance)
    }

    /// Performs semantic checks on the SeccompFilter.
    fn validate(&self) -> Result<()> {
        // Doesn't make sense to have equal default and on-match actions.
        if self.mismatch_action == self.match_action {
            return Err(Error::IdenticalActions);
        }

        Ok(())
    }

    /// Lays out a chain of rules into the planned program, enforcing the length budget.
    ///
    /// # Arguments
    ///
    /// * `syscall_number` - The syscall to which the rules apply.
    /// * `chain` - The chain of rules for the specified syscall.
    /// * `match_action` - The on-match action of the filter.
    /// * `mismatch_action` - The action taken when the syscall matches but no rule does.
    /// * `program` - The expanding, planned BPF program.
    ///
    /// Every appended instruction is checked against the [`BPF_MAX_LEN`] budget before it is
    /// pushed, so an over-long filter is rejected during the layout phase, before any
    /// `sock_filter` is produced.
    fn layout_syscall_chain(
        syscall_number: i64,
        chain: Vec<SeccompRule>,
        match_action: SeccompAction,
        mismatch_action: SeccompAction,
        program: &mut Vec<(CodegenLocation, PlannedInstruction)>,
    ) -> Result<()> {
        let chain_location = CodegenLocation::SyscallChain(syscall_number);

        // The chain starts with a comparison checking the loaded syscall number against the
        // syscall number of the chain.
        SeccompFilter::push_planned(
            program,
            chain_location.clone(),
            planned_cond_jump(
                BPF_JMP | BPF_JEQ | BPF_K,
                // Safe because linux system call numbers are nowhere near the u32::MAX value.
                syscall_number.try_into().unwrap(),
                0,
                1,
            ),
        )?;

        if chain.is_empty() {
            SeccompFilter::push_planned(program, chain_location.clone(), planned_jump(1))?;
            SeccompFilter::push_planned(program, chain_location.clone(), planned_jump(2))?;
            // If the chain is empty, we only need to append the on-match action.
            SeccompFilter::push_planned(
                program,
                chain_location,
                planned_stmt(BPF_RET | BPF_K, u32::from(match_action)),
            )?;
        } else {
            // The rules of the chain are laid out, each followed by the on-match action.
            for (rule_index, rule) in chain.into_iter().enumerate() {
                let rule_location = CodegenLocation::Rule {
                    syscall: Some(syscall_number),
                    rule_index,
                };
                let planned_rule = SeccompRule::layout(rule, rule_location);
                for (location, block) in planned_rule {
                    for instruction in block {
                        SeccompFilter::push_planned(program, location.clone(), instruction)?;
                    }
                }

                // Last statement of a rule is the on-match action of the filter.
                SeccompFilter::push_planned(
                    program,
                    CodegenLocation::MatchReturn(syscall_number),
                    planned_stmt(BPF_RET | BPF_K, u32::from(match_action.clone())),
                )?;
            }
        }

        // The default action is appended, if the syscall number comparison matched and then all
        // rules fail to match, the default action is reached.
        SeccompFilter::push_planned(
            program,
            CodegenLocation::ChainMismatchReturn(syscall_number),
            planned_stmt(BPF_RET | BPF_K, mismatch_action.into()),
        )
    }

    /// Appends one planned instruction, rejecting the program as soon as the
    /// [`BPF_MAX_LEN`] budget is exceeded and recording the location responsible.
    fn push_planned(
        program: &mut Vec<(CodegenLocation, PlannedInstruction)>,
        location: CodegenLocation,
        instruction: PlannedInstruction,
    ) -> Result<()> {
        // The check runs before pushing, so the budget violation is attributed to the block that
        // would overflow rather than to a later, unrelated instruction.
        if program.len() + 1 >= BPF_MAX_LEN {
            return Err(Error::FilterTooLarge {
                length: program.len() + 1,
                location,
            });
        }
        program.push((location, instruction));
        Ok(())
    }

    /// Verifies the jump offsets of a fully laid-out program, reporting the location of the
    /// first invalid jump.
    fn validate_jumps(program: &[(CodegenLocation, PlannedInstruction)]) -> Result<()> {
        let instructions: Vec<PlannedInstruction> = program
            .iter()
            .map(|(_, instruction)| instruction.clone())
            .collect();
        if let Some((index, offset)) = find_invalid_jump(&instructions) {
            let (location, _) = &program[index];
            return Err(Error::JumpOutOfRange {
                offset,
                index,
                location: location.clone(),
            });
        }
        Ok(())
    }

    /// Emits the final BPF program in a single pass, after the layout and validation phases have
    /// proven the length budget and every jump offset.
    fn emit(program: Vec<(CodegenLocation, PlannedInstruction)>) -> BpfProgram {
        emit_program(
            program
                .into_iter()
                .map(|(_, instruction)| instruction)
                .collect(),
        )
    }
}

impl TryFrom<SeccompFilter> for BpfProgram {
    type Error = Error;
    fn try_from(filter: SeccompFilter) -> Result<Self> {
        // Phase 1: layout. Builds the whole program as planned instructions (jump offsets kept in
        // `usize`) while proving, instruction by instruction, that the length budget is respected.
        let mut program: Vec<(CodegenLocation, PlannedInstruction)> = Vec::new();

        // Precursory architecture check.
        for instruction in build_planned_arch_validation_sequence(filter.target_arch) {
            SeccompFilter::push_planned(
                &mut program,
                CodegenLocation::ArchValidation,
                instruction,
            )?;
        }

        // If no rules are set up, the filter will always return the default action, so let's
        // short-circuit the function.
        if filter.rules.is_empty() {
            SeccompFilter::push_planned(
                &mut program,
                CodegenLocation::DefaultReturn,
                planned_stmt(BPF_RET | BPF_K, u32::from(filter.mismatch_action)),
            )?;

            // Phase 2: prove all jumps are reachable and encodable.
            SeccompFilter::validate_jumps(&program)?;

            // Phase 3: emit the final program in a single pass.
            return Ok(SeccompFilter::emit(program));
        }

        // The called syscall number is loaded.
        SeccompFilter::push_planned(
            &mut program,
            CodegenLocation::SyscallNumberLoad,
            planned_stmt(BPF_LD | BPF_W | BPF_ABS, u32::from(SECCOMP_DATA_NR_OFFSET)),
        )?;

        let mismatch_action = filter.mismatch_action;
        let match_action = filter.match_action;

        // For each syscall, lays out its rule chain while enforcing the length budget.
        filter
            .rules
            .into_iter()
            .try_for_each(|(syscall_number, chain)| {
                SeccompFilter::layout_syscall_chain(
                    syscall_number,
                    chain,
                    match_action.clone(),
                    mismatch_action.clone(),
                    &mut program,
                )
            })?;

        // The default action is once again appended, it is reached if all syscall number
        // comparisons fail.
        SeccompFilter::push_planned(
            &mut program,
            CodegenLocation::DefaultReturn,
            planned_stmt(BPF_RET | BPF_K, mismatch_action.into()),
        )?;

        // Phase 2: prove every jump target is reachable and every offset is encodable.
        SeccompFilter::validate_jumps(&program)?;

        // Phase 3: emit the final program in a single pass.
        Ok(SeccompFilter::emit(program))
    }
}

#[cfg(test)]
mod tests {
    use super::SeccompFilter;
    use crate::backend::bpf::*;
    use crate::backend::condition::SeccompCondition as Cond;
    use crate::backend::SeccompCmpArgLen as ArgLen;
    use crate::backend::SeccompCmpOp::*;
    use crate::backend::{CodegenLocation, Error, SeccompAction, SeccompRule, TargetArch};
    use std::collections::BTreeMap;
    use std::convert::TryInto;
    use std::env::consts::ARCH;

    fn create_test_bpf_filter(arg_len: ArgLen) -> SeccompFilter {
        SeccompFilter::new(
            vec![
                (
                    1,
                    vec![
                        SeccompRule::new(vec![
                            Cond::new(2, arg_len.clone(), Le, 14).unwrap(),
                            Cond::new(2, arg_len.clone(), Ne, 10).unwrap(),
                        ])
                        .unwrap(),
                        SeccompRule::new(vec![
                            Cond::new(2, arg_len.clone(), Gt, 20).unwrap(),
                            Cond::new(2, arg_len.clone(), Lt, 30).unwrap(),
                        ])
                        .unwrap(),
                        SeccompRule::new(vec![Cond::new(2, arg_len.clone(), Ge, 42).unwrap()])
                            .unwrap(),
                    ],
                ),
                (
                    9,
                    vec![SeccompRule::new(vec![
                        Cond::new(1, arg_len, MaskedEq(0b100), 36).unwrap()
                    ])
                    .unwrap()],
                ),
                (10, vec![]),
            ]
            .into_iter()
            .collect(),
            SeccompAction::Trap,
            SeccompAction::Allow,
            ARCH.try_into().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_seccomp_filter_validate() {
        // Filter has identical on-match and default actions.
        assert_eq!(
            SeccompFilter::new(
                BTreeMap::new(),
                SeccompAction::Allow,
                SeccompAction::Allow,
                ARCH.try_into().unwrap()
            )
            .unwrap_err(),
            Error::IdenticalActions
        );
    }

    #[test]
    fn test_seccomp_filter_too_large() {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for _ in 1..1000 {
            rules
                .entry(1)
                .or_default()
                .append(&mut vec![SeccompRule::new(vec![Cond::new(
                    2,
                    ArgLen::Dword,
                    Le,
                    14,
                )
                .unwrap()])
                .unwrap()]);
        }

        let filter = SeccompFilter::new(
            rules.into_iter().collect(),
            SeccompAction::Allow,
            SeccompAction::Trap,
            ARCH.try_into().unwrap(),
        )
        .unwrap();

        let err = TryInto::<BpfProgram>::try_into(filter).unwrap_err();
        // The layout phase rejects the program while it is being built, before any bytecode is
        // emitted, and points at the rule chain responsible for the overflow.
        assert!(matches!(
            err,
            Error::FilterTooLarge {
                length,
                location: CodegenLocation::Rule {
                    syscall: Some(1),
                    rule_index: 818
                }
            } if length == BPF_MAX_LEN
        ));
    }

    #[test]
    fn test_empty_filter_output() {
        // An empty filter should just validate the architecture and return the mismatch_action.
        let mut expected_program = Vec::new();
        expected_program.extend(build_arch_validation_sequence(ARCH.try_into().unwrap()));
        expected_program.extend(vec![bpf_stmt(BPF_RET, 0x7fff_0000)]);

        let filter = SeccompFilter::new(
            BTreeMap::new(),
            SeccompAction::Allow,
            SeccompAction::Trap,
            ARCH.try_into().unwrap(),
        )
        .unwrap();
        let prog: BpfProgram = filter.try_into().unwrap();

        assert_eq!(expected_program, prog);
    }

    #[test]
    fn test_filter_bpf_output_dword() {
        // Compares translated filter with hardcoded BPF program.
        let filter = create_test_bpf_filter(ArgLen::Dword);

        let mut instructions = Vec::new();
        instructions.extend(build_arch_validation_sequence(ARCH.try_into().unwrap()));
        instructions.extend(vec![
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 6),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 10, 3, 0),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 14, 1, 0),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 6),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGE | BPF_K, 30, 3, 0),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 20, 0, 1),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 4),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGE | BPF_K, 42, 0, 1),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 9, 0, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 5),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 24),
            bpf_stmt(BPF_ALU | BPF_AND | BPF_K, 0b100),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 36 & 0b100, 0, 1),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 10, 0, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 2),
            bpf_stmt(BPF_RET | BPF_K, 0x7fff_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
        ]);

        let bpfprog: BpfProgram = filter.try_into().unwrap();

        assert_eq!(bpfprog, instructions);
    }

    #[test]
    fn test_filter_bpf_output_qword() {
        let filter = create_test_bpf_filter(ArgLen::Qword);

        let mut instructions = Vec::new();
        instructions.extend(build_arch_validation_sequence(ARCH.try_into().unwrap()));
        instructions.extend(vec![
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 11),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 36),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 10, 6, 0),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 36),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 0, 4, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 14, 1, 0),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 12),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 36),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 0, 9, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGE | BPF_K, 30, 6, 0),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 36),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 0, 3, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 20, 0, 1),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 7),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 36),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 0, 3, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGE | BPF_K, 42, 0, 1),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 9, 0, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 8),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 28),
            bpf_stmt(BPF_ALU | BPF_AND | BPF_K, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 4),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 24),
            bpf_stmt(BPF_ALU | BPF_AND | BPF_K, 0b100),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 36 & 0b100, 0, 1),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 10, 0, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 2),
            bpf_stmt(BPF_RET | BPF_K, 0x7fff_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
        ]);

        let bpfprog: BpfProgram = filter.try_into().unwrap();
        assert_eq!(bpfprog, instructions);
    }

    // Minimal classic-BPF interpreter, covering the instruction subset emitted by the compiler.
    // It lets the synthetic long-rule fixtures prove semantic correctness instead of only shape.
    fn run_bpf(program: &[sock_filter], nr: i32, args: [u64; 6]) -> u32 {
        let target_arch: TargetArch = ARCH.try_into().unwrap();
        let arch = target_arch.get_audit_value();
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&(nr as u32).to_le_bytes());
        data.extend_from_slice(&arch.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        for arg in args {
            data.extend_from_slice(&arg.to_le_bytes());
        }

        let mut accumulator: u32 = 0;
        let mut pc = 0usize;
        loop {
            let instruction = &program[pc];
            match instruction.code {
                code if code == (BPF_LD | BPF_W | BPF_ABS) => {
                    let offset = instruction.k as usize;
                    accumulator = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
                    pc += 1;
                }
                code if code == (BPF_ALU | BPF_AND | BPF_K) => {
                    accumulator &= instruction.k;
                    pc += 1;
                }
                code if code == (BPF_JMP | BPF_JA) => {
                    pc = pc + 1 + instruction.k as usize;
                }
                code if code == (BPF_RET | BPF_K) => return instruction.k,
                _ => {
                    let taken = match instruction.code & 0xF0 {
                        BPF_JEQ => accumulator == instruction.k,
                        BPF_JGT => accumulator > instruction.k,
                        BPF_JGE => accumulator >= instruction.k,
                        other => panic!("unsupported jump class in test interpreter: {}", other),
                    };
                    let offset = if taken {
                        instruction.jt as usize
                    } else {
                        instruction.jf as usize
                    };
                    pc = pc + 1 + offset;
                }
            }
            assert!(pc < program.len(), "jump escaped past the program");
        }
    }

    // Checks that every jump of an emitted program stays inside the program and that conditional
    // jumps never use an offset wider than a `u8` (the wrap-around the layout phase must prevent).
    fn assert_jumps_encodable(program: &[sock_filter]) {
        for (index, instruction) in program.iter().enumerate() {
            if instruction.code == (BPF_JMP | BPF_JA) {
                assert!((index + 1 + instruction.k as usize) < program.len());
            } else if instruction.code & 0x07 == BPF_JMP {
                assert!(u32::from(instruction.jt) <= u32::from(u8::MAX));
                assert!(u32::from(instruction.jf) <= u32::from(u8::MAX));
                assert!(index + 1 + usize::from(instruction.jt) < program.len());
                assert!(index + 1 + usize::from(instruction.jf) < program.len());
            }
        }
    }

    #[test]
    fn test_long_rule_helper_jumps_and_semantics() {
        // A rule with more 6-instruction qword conditions than a single u8 jump span can cover.
        // The layout phase must insert helper jumps, and the emitted program must remain
        // semantically correct.
        let condition_count = 43usize;
        let conditions = (0..condition_count)
            .map(|_| {
                Cond::new(
                    0,
                    ArgLen::Qword,
                    MaskedEq(u64::MAX),
                    // The same value for every AND-chained condition keeps the fixture matching a
                    // single concrete argument value.
                    0xdead_beef_cafe_babe,
                )
                .unwrap()
            })
            .collect();

        let rules = vec![(100i64, vec![SeccompRule::new(conditions).unwrap()])];
        let filter = SeccompFilter::new(
            rules.into_iter().collect(),
            SeccompAction::Allow,
            SeccompAction::Trap,
            ARCH.try_into().unwrap(),
        )
        .unwrap();

        let program: BpfProgram = filter.try_into().unwrap();
        assert!(program.len() < BPF_MAX_LEN);
        assert_jumps_encodable(&program);
        // 43 six-instruction conditions cannot be bridged with u8 offsets alone, so helper jumps
        // are required. A rule without helper jumps only contains its two entry jumps; every
        // helper insertion adds three more unconditional jumps (opcode BPF_JMP | BPF_JA).
        let unconditional_jumps = program
            .iter()
            .filter(|instruction| instruction.code == (BPF_JMP | BPF_JA))
            .count();
        assert!(unconditional_jumps > 2);

        let trap = u32::from(SeccompAction::Trap);
        let allow = u32::from(SeccompAction::Allow);

        // All conditions satisfied: the rule matches and the on-match action is returned.
        let matching_args = [0xdead_beef_cafe_babe, 0, 0, 0, 0, 0];
        assert_eq!(run_bpf(&program, 100, matching_args), trap);
        // One condition fails: execution leaves the rule and reaches the chain mismatch action.
        assert_eq!(run_bpf(&program, 100, [0, 0, 0, 0, 0, 0]), allow);
        // Unknown syscall: the final default action is reached.
        assert_eq!(run_bpf(&program, 101, [0, 0, 0, 0, 0, 0]), allow);
    }

    #[test]
    fn test_many_rules_long_chain() {
        // Many rules, each with a qword condition, force offsets beyond a u8 across the whole
        // chain while keeping the program within the kernel length budget.
        let rules = vec![(
            200i64,
            (0..80)
                .map(|index| {
                    SeccompRule::new(vec![Cond::new(
                        0,
                        ArgLen::Qword,
                        Eq,
                        u64::try_from(index).unwrap() + 1,
                    )
                    .unwrap()])
                    .unwrap()
                })
                .collect(),
        )];
        let filter = SeccompFilter::new(
            rules.into_iter().collect(),
            SeccompAction::Allow,
            SeccompAction::Trap,
            ARCH.try_into().unwrap(),
        )
        .unwrap();

        let program: BpfProgram = filter.try_into().unwrap();
        assert!(program.len() < BPF_MAX_LEN);
        assert_jumps_encodable(&program);

        let trap = u32::from(SeccompAction::Trap);
        let allow = u32::from(SeccompAction::Allow);

        // First, middle and last rules match; non-matching values fall through to the default.
        assert_eq!(run_bpf(&program, 200, [1, 0, 0, 0, 0, 0]), trap);
        assert_eq!(run_bpf(&program, 200, [41, 0, 0, 0, 0, 0]), trap);
        assert_eq!(run_bpf(&program, 200, [80, 0, 0, 0, 0, 0]), trap);
        assert_eq!(run_bpf(&program, 200, [1_000, 0, 0, 0, 0, 0]), allow);
    }

    #[test]
    fn test_length_budget_error_is_locatable() {
        // Empty chains cost a fixed number of instructions, so the exact syscall chain crossing
        // the BPF_MAX_LEN boundary is deterministic.
        let rules: BTreeMap<i64, Vec<SeccompRule>> =
            (0..900).map(|index| (1000 + index, vec![])).collect();
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Trap,
            ARCH.try_into().unwrap(),
        )
        .unwrap();

        let err = TryInto::<BpfProgram>::try_into(filter).unwrap_err();
        // Prologue (3) + syscall load (1), then five instructions per empty chain. The push that
        // would produce the 4096th instruction is the second push of chain number 819.
        let failing_chain = 1000 + 818;
        assert_eq!(
            err,
            Error::FilterTooLarge {
                length: BPF_MAX_LEN,
                location: CodegenLocation::SyscallChain(failing_chain)
            }
        );
    }

    #[test]
    fn test_short_filter_bytecode_is_unchanged() {
        // The two-phase compiler must emit byte-identical bytecode for ordinary short policies.
        let filter = create_test_bpf_filter(ArgLen::Dword);
        let mut expected = Vec::new();
        expected.extend(build_arch_validation_sequence(ARCH.try_into().unwrap()));
        expected.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0));
        expected.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1));

        let program: BpfProgram = filter.try_into().unwrap();
        assert_eq!(program[..expected.len()], expected[..]);
    }
}
