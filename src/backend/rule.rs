// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::collections::{BTreeMap, HashSet};

use crate::backend::{
    bpf::*, condition::SeccompCondition, Error, Result, SeccompCmpArgLen, SeccompCmpOp,
};

/// Checks whether a set of conditions on the same syscall argument can be simultaneously
/// satisfied.
///
/// The `eq`, `ge`, `gt`, `le` and `lt` conditions are combined into an inclusive
/// `[lower, upper]` interval (plus an optional exact value), which is then checked against the
/// `ne` exclusions and the `masked_eq` bit constraints.
fn constraints_satisfiable(conditions: &[&SeccompCondition]) -> bool {
    // Inclusive bounds of the interval the argument value must belong to.
    let mut lower: u64 = 0;
    let mut upper: u64 = u64::MAX;
    // Exact value imposed by `eq` conditions, if any.
    let mut eq_value: Option<u64> = None;
    // Values excluded by `ne` conditions.
    let mut ne_values: HashSet<u64> = HashSet::new();
    // Bit constraints imposed by `masked_eq` conditions: (mask, masked value) pairs.
    let mut masked_eqs: Vec<(u64, u64)> = Vec::new();

    for condition in conditions {
        let value = condition.value();
        match condition.operator() {
            SeccompCmpOp::Eq => {
                if let Some(previous) = eq_value {
                    if previous != value {
                        return false;
                    }
                } else {
                    eq_value = Some(value);
                }
            }
            SeccompCmpOp::Ne => {
                ne_values.insert(value);
            }
            SeccompCmpOp::Gt => match value.checked_add(1) {
                Some(bound) => lower = lower.max(bound),
                // No value can be greater than u64::MAX.
                None => return false,
            },
            SeccompCmpOp::Ge => lower = lower.max(value),
            SeccompCmpOp::Lt => match value.checked_sub(1) {
                Some(bound) => upper = upper.min(bound),
                // No value can be less than 0.
                None => return false,
            },
            SeccompCmpOp::Le => upper = upper.min(value),
            SeccompCmpOp::MaskedEq(mask) => masked_eqs.push((*mask, value & mask)),
        }
    }

    if lower > upper {
        return false;
    }

    // Two `masked_eq` conditions that constrain the same bits to different values contradict
    // each other.
    for (index, (mask, masked_value)) in masked_eqs.iter().enumerate() {
        for (other_mask, other_masked_value) in &masked_eqs[index + 1..] {
            let common_bits = mask & other_mask;
            if masked_value & common_bits != other_masked_value & common_bits {
                return false;
            }
        }
    }

    if let Some(value) = eq_value {
        // The exact value must fit the interval, not be excluded and satisfy the bit
        // constraints.
        return value >= lower
            && value <= upper
            && !ne_values.contains(&value)
            && masked_eqs
                .iter()
                .all(|(mask, masked_value)| value & mask == *masked_value);
    }

    // The interval must contain at least one value that is not excluded by a `ne` condition.
    // A `None` interval length means the interval is too large to be exhausted by the finite
    // number of exclusions.
    if let Some(interval_len) = upper
        .checked_sub(lower)
        .and_then(|diff| diff.checked_add(1))
    {
        let excluded = ne_values
            .iter()
            .filter(|value| **value >= lower && **value <= upper)
            .count() as u64;
        if excluded >= interval_len {
            return false;
        }
    }

    // If the interval is a single point, it must also satisfy the bit constraints.
    !(lower == upper
        && masked_eqs
            .iter()
            .any(|(mask, masked_value)| lower & mask != *masked_value))
}

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

    /// Returns the canonical form of the rule's conditions: sorted and deduplicated.
    ///
    /// The conditions of a rule are and-bound, and conjunction is commutative and idempotent,
    /// so two rules are provably equivalent if and only if their canonical forms are equal.
    /// This equivalence is used by [`SeccompFilter`](super::SeccompFilter) to detect duplicate
    /// rules at compile time.
    pub(crate) fn canonical_conditions(&self) -> Vec<SeccompCondition> {
        let mut conditions = self.conditions.clone();
        conditions.sort();
        conditions.dedup();
        conditions
    }

    /// Checks whether the conditions of the rule can be simultaneously satisfied.
    ///
    /// Conditions on different syscall arguments are independent, so the rule is satisfiable
    /// iff the constraints on each argument are. The check is sound but conservative: it only
    /// reports definite contradictions between `eq`, `ne`, `ge`, `gt`, `le`, `lt` and
    /// `masked_eq` conditions on the same argument.
    pub(crate) fn is_satisfiable(&self) -> bool {
        // Group the conditions by the argument (and argument length) they constrain.
        let mut groups: BTreeMap<(u8, &SeccompCmpArgLen), Vec<&SeccompCondition>> = BTreeMap::new();
        for condition in &self.conditions {
            groups
                .entry((condition.arg_index(), condition.arg_len()))
                .or_default()
                .push(condition);
        }

        groups.values().all(|group| constraints_satisfiable(group))
    }

    /// Appends a condition of the rule to an accumulator.
    ///
    /// The length of the rule and offset to the next rule are updated.
    ///
    /// # Arguments
    ///
    /// * `condition` - The condition added to the rule.
    /// * `accumulator` - Accumulator of BPF statements that compose the BPF program.
    /// * `rule_len` - Number of conditions in the rule.
    /// * `offset` - Offset (in number of BPF statements) to the next rule.
    fn append_condition(
        condition: SeccompCondition,
        accumulator: &mut Vec<Vec<sock_filter>>,
        offset: &mut u8,
    ) {
        // Tries to detect whether prepending the current condition will produce an unjumpable
        // offset (since BPF conditional jumps are a maximum of 255 instructions, which is
        // u8::MAX).
        if offset.checked_add(CONDITION_MAX_LEN + 1).is_none() {
            // If that is the case, three additional helper jumps are prepended and the offset
            // is reset to 1.
            //
            // - The first jump continues the evaluation of the condition chain by jumping to
            //   the next condition or the action of the rule if the last condition was matched.
            // - The second, jumps out of the rule, to the next rule or the default action of
            //   the filter in case of the last rule in the rule chain of a syscall.
            // - The third jumps out of the rule chain of the syscall, to the rule chain of the
            //   next syscall number to be checked or the default action of the filter in the
            //   case of the last rule chain.
            let helper_jumps = vec![
                bpf_stmt(BPF_JMP | BPF_JA, 2),
                bpf_stmt(BPF_JMP | BPF_JA, u32::from(*offset) + 1),
                bpf_stmt(BPF_JMP | BPF_JA, u32::from(*offset) + 1),
            ];
            accumulator.push(helper_jumps);
            *offset = 1;
        }

        let condition = condition.into_bpf(*offset);
        // Safe to unwrap since we checked that offset + `CONDITION_MAX_LEN` does not overflow.
        *offset += u8::try_from(condition.len()).unwrap();
        accumulator.push(condition);
    }
}

impl From<SeccompRule> for BpfProgram {
    fn from(rule: SeccompRule) -> Self {
        // Each rule starts with 2 jump statements:
        // * The first jump enters the rule, attempting a match.
        // * The second one jumps out of the rule, into the next rule of the syscall or to the
        //   default action if none of the rules were matched.

        // Rule is built backwards, because SeccompConditions need to know the jump offset to the
        // next rule, when compiled to BPF.
        let mut accumulator = Vec::with_capacity(
            rule.conditions
                .len()
                // Realistically, this overflow should never happen.
                // If the nr of statements ever overflows `usize`, the rust vector allocation would
                // anyway fail.
                .checked_mul(CONDITION_MAX_LEN as usize)
                .unwrap(),
        );
        let mut offset = 1;

        // Conditions are translated into BPF statements and prepended to the rule.
        rule.conditions.into_iter().for_each(|condition| {
            SeccompRule::append_condition(condition, &mut accumulator, &mut offset)
        });

        // The two initial jump statements are prepended to the rule.
        accumulator.push(vec![
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, u32::from(offset) + 1),
        ]);

        // Finally, builds the translated rule by reversing and consuming the accumulator.
        let mut result = Vec::new();
        accumulator
            .into_iter()
            .rev()
            .for_each(|mut instructions| result.append(&mut instructions));

        result
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

    #[test]
    fn test_canonical_conditions() {
        // Conjunction is commutative and idempotent, so the canonical form is independent of
        // condition order and duplication.
        let rule = SeccompRule::new(vec![
            Cond::new(2, ArgLen::Dword, Le, 14).unwrap(),
            Cond::new(0, ArgLen::Qword, Eq, 1).unwrap(),
            Cond::new(2, ArgLen::Dword, Le, 14).unwrap(),
        ])
        .unwrap();

        assert_eq!(
            rule.canonical_conditions(),
            vec![
                Cond::new(0, ArgLen::Qword, Eq, 1).unwrap(),
                Cond::new(2, ArgLen::Dword, Le, 14).unwrap(),
            ]
        );
    }

    #[test]
    fn test_is_satisfiable() {
        // Satisfiable rules.
        for conditions in [
            vec![Cond::new(0, ArgLen::Dword, Eq, 1).unwrap()],
            vec![
                Cond::new(0, ArgLen::Dword, Gt, 20).unwrap(),
                Cond::new(0, ArgLen::Dword, Lt, 30).unwrap(),
            ],
            vec![
                Cond::new(0, ArgLen::Dword, Ge, 20).unwrap(),
                Cond::new(0, ArgLen::Dword, Le, 20).unwrap(),
            ],
            vec![
                Cond::new(0, ArgLen::Dword, Eq, 10).unwrap(),
                Cond::new(0, ArgLen::Dword, Ne, 11).unwrap(),
            ],
            vec![
                Cond::new(0, ArgLen::Dword, Ne, 1).unwrap(),
                Cond::new(0, ArgLen::Dword, Ne, 2).unwrap(),
            ],
            vec![
                Cond::new(0, ArgLen::Dword, MaskedEq(0b100), 36).unwrap(),
                Cond::new(0, ArgLen::Dword, Eq, 36).unwrap(),
            ],
            // Conditions on different arguments are independent.
            vec![
                Cond::new(0, ArgLen::Dword, Eq, 1).unwrap(),
                Cond::new(1, ArgLen::Dword, Eq, 2).unwrap(),
            ],
        ] {
            assert!(SeccompRule::new(conditions).unwrap().is_satisfiable());
        }

        // Rules with mutually exclusive conditions.
        for conditions in [
            // Two different exact values.
            vec![
                Cond::new(0, ArgLen::Dword, Eq, 1).unwrap(),
                Cond::new(0, ArgLen::Dword, Eq, 2).unwrap(),
            ],
            // Exact value excluded by `ne`.
            vec![
                Cond::new(0, ArgLen::Dword, Eq, 1).unwrap(),
                Cond::new(0, ArgLen::Dword, Ne, 1).unwrap(),
            ],
            // Exact value outside the interval.
            vec![
                Cond::new(0, ArgLen::Dword, Eq, 1).unwrap(),
                Cond::new(0, ArgLen::Dword, Gt, 1).unwrap(),
            ],
            // Empty interval.
            vec![
                Cond::new(0, ArgLen::Dword, Lt, 5).unwrap(),
                Cond::new(0, ArgLen::Dword, Gt, 10).unwrap(),
            ],
            vec![
                Cond::new(0, ArgLen::Dword, Le, 5).unwrap(),
                Cond::new(0, ArgLen::Dword, Ge, 6).unwrap(),
            ],
            vec![Cond::new(0, ArgLen::Dword, Lt, 0).unwrap()],
            vec![Cond::new(0, ArgLen::Dword, Gt, u64::MAX).unwrap()],
            // All points of the interval excluded by `ne` conditions.
            vec![
                Cond::new(0, ArgLen::Dword, Ge, 1).unwrap(),
                Cond::new(0, ArgLen::Dword, Le, 2).unwrap(),
                Cond::new(0, ArgLen::Dword, Ne, 1).unwrap(),
                Cond::new(0, ArgLen::Dword, Ne, 2).unwrap(),
            ],
            // Conflicting bit constraints on overlapping masks.
            vec![
                Cond::new(0, ArgLen::Dword, MaskedEq(0b11), 0b01).unwrap(),
                Cond::new(0, ArgLen::Dword, MaskedEq(0b10), 0b10).unwrap(),
            ],
            // Exact value violating a bit constraint.
            vec![
                Cond::new(0, ArgLen::Dword, MaskedEq(0b100), 0).unwrap(),
                Cond::new(0, ArgLen::Dword, Eq, 0b100).unwrap(),
            ],
        ] {
            assert!(!SeccompRule::new(conditions).unwrap().is_satisfiable());
        }
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
