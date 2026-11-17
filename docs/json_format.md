## JSON file format

A JSON file expresses the seccomp policy for a process. It may contain multiple
filters, which can be semantically mapped to thread types in multithreaded
applications, and is specific to just one target platform of the application.

At the top level, the file requires an object that maps unique string keys to
seccomp filters:

```
{
    "vmm": {
       "mismatch_action": {
            "errno" : -1
       },
       "match_action": "allow",
       "filter": [...]
    },
    "api": {...},
    "vcpu": {...},
}
```

The associated filter is a JSON object containing the `mismatch_action`,
`match_action` and `filter` properties.

The `mismatch_action` represents the action executed if none of the rules in
`filter` match, and `match_action` is what gets executed if a rule in the
filter matches (e.g: `"Allow"` in the case of implementing an allowlist).

An **action** is the JSON representation of the following enum:

```rust
pub enum SeccompAction {
    Allow, // Allows syscall.
    Errno(u32), // Returns from syscall with specified error number.
    KillThread, // Kills calling process.
    KillProcess, // Kills calling thread.
    Log, // Allows syscall after logging it.
    Trace(u32), // Notifies tracing process of the caller with respective number.
    Trap, // Sends `SIGSYS` to the calling process.
}
```

The `filter` property specifies the set of rules that would trigger a match.
This is an array containing multiple **or-bound SyscallRule** **objects**
(if one of them matches, the corresponding action gets triggered).

The **SyscallRule** object is used for adding a rule to a syscall.
It has an optional `args` property that is used to specify a vector of
and-bound conditions that the syscall arguments must satisfy in order for the
rule to match.

In the absence of the `args` property, the corresponding action will get
triggered by any call that matches that name, irrespective of the argument
values.

Here is the structure of the object:

```
{
    "syscall": "accept4", // mandatory, the syscall name
    "comment": "Used by vsock & api thread", // optional, for adding comments
    "args": [...] // optional, vector of and-bound conditions for the arguments
}
```

Note that the file format expects syscall names, not arch-specific numbers, for
increased usability. This is not true, however for the syscall arguments, which
are expected as base-10 integers.

In order to allow a syscall with multiple alternatives for the same parameters,
one can write multiple syscall rule objects at the filter-level, each with its
own, distinct rules.

## Rule combination semantics

The rules of a syscall are **or-bound**, and the conditions of a rule are
**and-bound**. The following conflicts are detected at compile time, instead of
being silently resolved in an order-dependent way:

- **Unconditional vs. conditional rules**: an unconditional rule (no `args`)
  matches any argument values, so it subsumes every conditional rule of the
  same syscall (formally, `true OR P` is `true` for any condition `P`), making
  the conditional rules provably dead. Silently dropping them would mask the
  author's intent, while falling back to the unconditional match when all
  conditions fail would violate the principle of least privilege. The
  combination is therefore rejected with a `ConflictingRules` error, in either
  order. An unconditional rule is only valid as the single rule of its
  syscall.
- **Duplicate rules**: two rules are provably equivalent if and only if their
  condition sets are equal, because conjunction is commutative and idempotent
  (condition order and repeated conditions do not change the meaning of a
  rule). Equivalent rules of the same syscall are redundant and are rejected
  with a `DuplicateRule` error. This also covers repeated unconditional rules
  of a syscall.
- **Empty conditions**: a rule with an empty `args` vector is rejected with an
  `EmptyRule` error. To match a syscall regardless of argument values, use a
  rule without the `args` property.
- **Mutually exclusive conditions**: a rule whose conditions can never be
  simultaneously satisfied (e.g. `eq 1` and `eq 2` on the same argument, an
  empty `ge`/`le` interval, an `eq` value excluded by `ne`, or `masked_eq`
  constraints that disagree on overlapping mask bits) can never match and is
  rejected with a `ContradictoryRule` error.

A **condition object** is made up of the following mandatory properties:

- `index` (0-based index of the syscall argument we want to check)
- `type` (`dword` or `qword`, which specifies the argument size - 4 or 8
    bytes respectively)
- `op`, which is one of `eq, ge, gt, ge, lt, masked_eq, ne` (the operator used
    for comparing the parameter to `val`)
- `val` is the integer value being checked against

As mentioned eariler, named parameters are not supported in the JSON file, but
only numeric constants. One can provide meaning to each numeric value, much
like when using named parameters, by using the optional `comment` property:

```
{
    "syscall": "accept4",
    "args": [
        {
            "index": 3,
            "type": "dword",
            "op": "eq",
            "val": 1,
            "comment": "libc::AF_UNIX"
        }
    ]
}
```

View an example filter in the [Readme](../README.md#example-json-filter).
