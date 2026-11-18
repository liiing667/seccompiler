// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use crate::backend::bpf::*;
use crate::backend::condition::SeccompCondition;
use crate::backend::{CodegenLocation, Error, Result};

/// Rule that a filter attempts to match for a syscall.
///
/// If all conditions match then rule gets matched.
/// A syscall can have many rules associated. If either of them matches, the `match_action` of the
/// [`SeccompFilter`] is triggered.
///
/// [`SeccompFilter`]: struct.SeccompFilter.html
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeccompRule {
    /// Conditions of rule that need to match in order for the rule to get matched.
    conditions: Vec<SeccompCondition>,
}

impl SeccompRule {
    /// Creates a new rule. Rules with 0 conditions are not allowed; to match a syscall regardless
    /// of argument values, map the syscall number to an empty vector of rules when constructing
    /// the [`SeccompFilter`](super::SeccompFilter) instead.
    ///
    /// # Arguments
    ///
    /// * `conditions` - Vector of [`SeccompCondition`]s that the syscall must match.
    ///
    /// # Example
    ///
    /// ```
    /// use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompRule};
    ///
    /// let rule = SeccompRule::new(vec![
    ///     SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 1).unwrap(),
    ///     SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 1).unwrap(),
    /// ])
    /// .unwrap();
    /// ```
    ///
    /// [`SeccompCondition`]: struct.SeccompCondition.html
    pub fn new(conditions: Vec<SeccompCondition>) -> Result<Self> {
        let instance = Self { conditions };
        instance.validate()?;

        Ok(instance)
    }

    /// Performs semantic checks on the SeccompRule.
    fn validate(&self) -> Result<()> {
        // Rules with no conditions are not allowed. Syscalls mappings to empty rule vectors are to
        // be used instead, for matching only on the syscall number.
        if self.conditions.is_empty() {
            return Err(Error::EmptyRule);
        }

        Ok(())
    }

    /// Lays out a condition of the rule into an accumulator of planned instructions.
    ///
    /// The length of the rule and the `usize` offset to the next rule are updated.
    ///
    /// # Arguments
    ///
    /// * `condition` - The condition added to the rule.
    /// * `location` - Location identifying the condition being generated.
    /// * `accumulator` - Accumulator of planned BPF statements, built in reverse order.
    /// * `offset` - Offset (in number of BPF statements) to the next rule.
    pub(crate) fn layout_condition(
        condition: SeccompCondition,
        location: &CodegenLocation,
        accumulator: &mut Vec<(CodegenLocation, Vec<PlannedInstruction>)>,
        offset: &mut usize,
    ) {
        // Detects whether prepending the current condition would produce an offset that cannot be
        // encoded once it is narrowed to a `u8` (BPF conditional jumps span at most 255
        // instructions). The check uses `usize` arithmetic, so it can never wrap.
        if offset.saturating_add(usize::from(CONDITION_MAX_LEN) + 1) > u8::MAX as usize {
            // Three helper jumps are prepended and the offset is reset to 1.
            //
            // - The first jump continues the evaluation of the condition chain by jumping to
            //   the next condition or the action of the rule if the last condition was matched.
            // - The second, jumps out of the rule, to the next rule or the default action of
            //   the filter in case of the last rule in the rule chain of a syscall.
            // - The third jumps out of the rule chain of the syscall, to the rule chain of the
            //   next syscall number to be checked or the default action of the filter in the
            //   case of the last rule chain.
            let helper_location = match location {
                CodegenLocation::Rule {
                    syscall,
                    rule_index,
                }
                | CodegenLocation::Condition {
                    syscall,
                    rule_index,
                    ..
                } => CodegenLocation::HelperJump {
                    syscall: *syscall,
                    rule_index: *rule_index,
                },
                other => other.clone(),
            };
            let helper_jumps = vec![
                planned_jump(2),
                planned_jump(*offset + 1),
                planned_jump(*offset + 1),
            ];
            accumulator.push((helper_location, helper_jumps));
            *offset = 1;
        }

        let condition_bpf = condition.into_bpf(*offset);
        *offset += condition_bpf.len();
        accumulator.push((location.clone(), condition_bpf));
    }

    /// Lays out the whole rule into planned BPF instructions, keeping track of the origin of
    /// every block for error reporting.
    ///
    /// # Arguments
    ///
    /// * `rule` - The rule to translate.
    /// * `location` - Location identifying the rule (syscall number and rule index).
    pub(crate) fn layout(
        rule: SeccompRule,
        location: CodegenLocation,
    ) -> Vec<(CodegenLocation, Vec<PlannedInstruction>)> {
        // Rule is built backwards, because SeccompConditions need to know the jump offset to the
        // next rule, when compiled to BPF.
        let mut accumulator = Vec::with_capacity(
            rule.conditions
                .len()
                .checked_mul(usize::from(CONDITION_MAX_LEN))
                .unwrap(),
        );
        let mut offset = 1;

        // Conditions are translated into planned BPF statements and prepended to the rule.
        rule.conditions
            .into_iter()
            .enumerate()
            .for_each(|(condition_index, condition)| {
                let condition_location = CodegenLocation::Condition {
                    syscall: match &location {
                        CodegenLocation::Rule { syscall, .. }
                        | CodegenLocation::Condition { syscall, .. } => *syscall,
                        _ => None,
                    },
                    rule_index: match &location {
                        CodegenLocation::Rule { rule_index, .. }
                        | CodegenLocation::Condition { rule_index, .. } => *rule_index,
                        _ => 0,
                    },
                    condition_index,
                };
                SeccompRule::layout_condition(
                    condition,
                    &condition_location,
                    &mut accumulator,
                    &mut offset,
                )
            });

        // The two initial jump statements are prepended to the rule.
        accumulator.push((
            location.clone(),
            vec![planned_jump(1), planned_jump(offset + 1)],
        ));

        // The blocks are reversed to obtain the final order of the rule.
        accumulator.reverse();
        accumulator
    }
}

impl From<SeccompRule> for BpfProgram {
    fn from(rule: SeccompRule) -> Self {
        let location = CodegenLocation::Rule {
            syscall: None,
            rule_index: 0,
        };
        let planned: Vec<PlannedInstruction> = SeccompRule::layout(rule, location)
            .into_iter()
            .flat_map(|(_, block)| block)
            .collect();

        // A standalone rule contains offsets relative to a surrounding rule chain (the on-match
        // return and the following rule are not part of the rule itself), so whole-program
        // reachability cannot be checked here. The helper jumps above still guarantee that every
        // conditional offset fits in a `u8` and every unconditional offset fits in a `u32`.
        debug_assert!(planned.iter().all(|instruction| match instruction {
            PlannedInstruction::ConditionalJump { jt, jf, .. } => {
                *jt <= u8::MAX as usize && *jf <= u8::MAX as usize
            }
            PlannedInstruction::Jump { offset } => *offset <= u32::MAX as usize,
            PlannedInstruction::Statement { .. } => true,
        }));
        emit_program(planned)
    }
}

#[cfg(test)]
mod tests {
    use super::SeccompRule;
    use crate::backend::bpf::*;
    use crate::backend::{
        Error, SeccompCmpArgLen as ArgLen, SeccompCmpOp::*, SeccompCondition as Cond,
    };

    #[test]
    fn test_validate_rule() {
        assert_eq!(SeccompRule::new(vec![]).unwrap_err(), Error::EmptyRule);
    }

    // Checks that rule gets translated correctly into BPF statements.
    #[test]
    fn test_rule_bpf_output() {
        let rule = SeccompRule::new(vec![
            Cond::new(0, ArgLen::Dword, Eq, 1).unwrap(),
            Cond::new(2, ArgLen::Qword, MaskedEq(0b1010), 14).unwrap(),
        ])
        .unwrap();

        let (msb_offset, lsb_offset) = { (4, 0) };

        // Builds hardcoded BPF instructions.
        let instructions = vec![
            bpf_stmt(BPF_JMP | BPF_JA, 1),  // Start evaluating the rule.
            bpf_stmt(BPF_JMP | BPF_JA, 10), // Jump to the next rule.
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32 + msb_offset),
            bpf_stmt(BPF_ALU | BPF_AND | BPF_K, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 6),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32 + lsb_offset),
            bpf_stmt(BPF_ALU | BPF_AND | BPF_K, 0b1010),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 14 & 0b1010, 0, 3),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16 + lsb_offset),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1),
        ];
        // In a filter, these instructions would follow:
        // RET match_action
        // OTHER RULES...
        // RET mismatch_action. (if the syscall number matched and then all rules fail to match)
        // RET default action. (if no syscall number matched)

        // Compares translated rule with hardcoded BPF instructions.
        let bpfprog: BpfProgram = rule.into();
        assert_eq!(bpfprog, instructions);
    }

    // Checks that rule with too many conditions gets translated correctly into BPF statements
    // using three helper jumps.
    #[test]
    fn test_rule_many_conditions_bpf_output() {
        // Builds rule.
        let mut conditions = Vec::with_capacity(43);
        for _ in 0..42 {
            conditions.push(Cond::new(0, ArgLen::Qword, MaskedEq(0), 0).unwrap());
        }
        conditions.push(Cond::new(0, ArgLen::Qword, Eq, 0).unwrap());
        let rule = SeccompRule::new(conditions).unwrap();

        let (msb_offset, lsb_offset) = { (4, 0) };

        // Builds hardcoded BPF instructions.
        let mut instructions = vec![
            bpf_stmt(BPF_JMP | BPF_JA, 1), // Start evaluating the rule.
            bpf_stmt(BPF_JMP | BPF_JA, 6), // Jump to the next rule. Actually to a helper jump.
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16 + msb_offset),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16 + lsb_offset),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 2),
            bpf_stmt(BPF_JMP | BPF_JA, 254),
            bpf_stmt(BPF_JMP | BPF_JA, 254),
        ];
        let mut offset = 253;
        for _ in 0..42 {
            offset -= 6;
            // Add the rest of the `MaskedEq` conditions.
            instructions.append(&mut vec![
                bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16 + msb_offset),
                bpf_stmt(BPF_ALU | BPF_AND | BPF_K, 0),
                bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, offset + 3),
                bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16 + lsb_offset),
                bpf_stmt(BPF_ALU | BPF_AND | BPF_K, 0),
                bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, offset),
            ]);
        }

        // Compares translated rule with hardcoded BPF instructions.
        let bpfprog: BpfProgram = rule.into();
        assert_eq!(bpfprog, instructions);
    }
}
