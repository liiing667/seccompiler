// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Multi-architecture fixtures.
//!
//! These tests verify that the target architecture selected by the caller is
//! threaded consistently through JSON parsing, syscall name resolution and
//! the architecture validation sequence embedded in the compiled BPF program,
//! and that unknown or conflicting names fail closed.

#![cfg(feature = "json")]
#![allow(clippy::undocumented_unsafe_blocks)]

use seccompiler::{apply_filter, compile_from_json, sock_filter, BpfProgram, Error, TargetArch};
use std::convert::TryInto;
use std::env::consts::ARCH;
use std::str::FromStr;

// BPF instruction opcodes, see linux/bpf_common.h.
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

// `struct seccomp_data` field offsets, see linux/seccomp.h.
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

// `AUDIT_ARCH_*` values, see linux/audit.h.
const AUDIT_ARCH_X86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;
const AUDIT_ARCH_AARCH64: u32 = 183 | 0x8000_0000 | 0x4000_0000;
const AUDIT_ARCH_RISCV64: u32 = 243 | 0x8000_0000 | 0x4000_0000;

// See linux/seccomp.h.
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_TRAP: u32 = 0x0003_0000;

/// The supported target architectures and their expected properties:
/// (name, audit arch value, syscall numbers for `openat`, `read`, `futex`, `close`).
const ARCH_FIXTURES: [(&str, u32, [i64; 4]); 3] = [
    ("x86_64", AUDIT_ARCH_X86_64, [257, 0, 202, 3]),
    ("aarch64", AUDIT_ARCH_AARCH64, [56, 63, 98, 57]),
    ("riscv64", AUDIT_ARCH_RISCV64, [56, 63, 98, 57]),
];

/// JSON allowlist using syscall names available on all supported architectures.
const COMMON_JSON: &str = r#"{
    "main_thread": {
        "mismatch_action": "trap",
        "match_action": "allow",
        "filter": [
            { "syscall": "openat" },
            { "syscall": "read" },
            { "syscall": "futex" },
            { "syscall": "close" }
        ]
    }
}"#;

/// The expected architecture validation sequence that every compiled BPF
/// program must start with.
fn expected_arch_validation_sequence(audit_arch: u32) -> [sock_filter; 3] {
    [
        sock_filter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_ARCH_OFFSET,
        },
        sock_filter {
            code: BPF_JMP_JEQ_K,
            jt: 1,
            jf: 0,
            k: audit_arch,
        },
        sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        },
    ]
}

/// Returns the syscall numbers compared against in the given BPF program,
/// skipping the leading architecture validation sequence and the syscall
/// number load.
fn extract_syscall_numbers(program: &BpfProgram) -> Vec<u32> {
    program[4..]
        .iter()
        .filter(|instr| instr.code == BPF_JMP_JEQ_K)
        .map(|instr| instr.k)
        .collect()
}

#[test]
fn test_arch_selection_threads_through_compilation() {
    for (arch_name, audit_arch, syscall_nrs) in ARCH_FIXTURES.iter() {
        let arch: TargetArch = (*arch_name).try_into().unwrap();

        let mut filters = compile_from_json(COMMON_JSON.as_bytes(), arch).unwrap();
        let program = filters.remove("main_thread").unwrap();

        // The BPF program must start by validating the selected architecture
        // and killing the process on any mismatch.
        assert_eq!(
            program[..3],
            expected_arch_validation_sequence(*audit_arch)[..],
            "wrong arch validation sequence for {}",
            arch_name
        );

        // The syscall names must have been resolved using the table of the
        // selected architecture.
        let mut actual_nrs = extract_syscall_numbers(&program);
        actual_nrs.sort_unstable();
        let mut expected_nrs: Vec<u32> = syscall_nrs.iter().map(|nr| *nr as u32).collect();
        expected_nrs.sort_unstable();
        assert_eq!(
            actual_nrs, expected_nrs,
            "wrong syscall numbers for {}",
            arch_name
        );

        // The on-match and default actions must be preserved.
        assert!(program
            .iter()
            .any(|instr| instr.code == BPF_RET_K && instr.k == SECCOMP_RET_ALLOW));
        assert!(program
            .iter()
            .any(|instr| instr.code == BPF_RET_K && instr.k == SECCOMP_RET_TRAP));
    }
}

#[test]
fn test_output_thread_keys_share_arch_identity() {
    let json_input = r#"{
        "thread_1": {
            "mismatch_action": "trap",
            "match_action": "allow",
            "filter": [{ "syscall": "read" }]
        },
        "thread_2": {
            "mismatch_action": "trap",
            "match_action": "allow",
            "filter": [{ "syscall": "close" }]
        }
    }"#;

    for (arch_name, audit_arch, _) in ARCH_FIXTURES.iter() {
        let filters =
            compile_from_json(json_input.as_bytes(), (*arch_name).try_into().unwrap()).unwrap();

        // Every filter in the output map must carry the same, requested
        // architecture identity.
        assert_eq!(filters.len(), 2);
        for (thread_key, program) in filters.iter() {
            assert_eq!(
                program[..3],
                expected_arch_validation_sequence(*audit_arch)[..],
                "filter `{}` does not validate the requested arch {}",
                thread_key,
                arch_name
            );
        }
    }
}

#[test]
fn test_unknown_arch_names_fail_closed() {
    for invalid in [
        "", "x86", "amd64", "i686", "aarch32", "arm64", "riscv", "riscv32", "x86_64 ",
    ] {
        assert!(TargetArch::try_from(invalid).is_err(), "{}", invalid);
        assert!(TargetArch::from_str(invalid).is_err(), "{}", invalid);
    }

    for (arch_name, _, _) in ARCH_FIXTURES.iter() {
        assert!(TargetArch::try_from(*arch_name).is_ok());
        assert!(TargetArch::from_str(arch_name).is_ok());
    }
}

#[test]
fn test_unknown_syscall_names_fail_closed() {
    let json_input = r#"{
        "main_thread": {
            "mismatch_action": "trap",
            "match_action": "allow",
            "filter": [{ "syscall": "definitely_not_a_syscall" }]
        }
    }"#;

    for (arch_name, _, _) in ARCH_FIXTURES.iter() {
        let result = compile_from_json(json_input.as_bytes(), (*arch_name).try_into().unwrap());
        assert!(
            matches!(result, Err(Error::JsonFrontend(_))),
            "unknown syscall name must fail closed for {}",
            arch_name
        );
    }
}

#[test]
fn test_cross_arch_syscall_names_fail_closed() {
    let json_with = |syscall: &str| {
        format!(
            r#"{{"main_thread": {{"mismatch_action": "trap", "match_action": "allow",
            "filter": [{{ "syscall": "{}" }}]}}}}"#,
            syscall
        )
    };

    // `open` only exists in the x86_64 table. Compiling it for another
    // architecture must fail instead of silently producing a filter that
    // looks like it contains rules.
    let json_open = json_with("open");
    assert!(compile_from_json(json_open.as_bytes(), TargetArch::x86_64).is_ok());
    assert!(compile_from_json(json_open.as_bytes(), TargetArch::aarch64).is_err());
    assert!(compile_from_json(json_open.as_bytes(), TargetArch::riscv64).is_err());

    // `riscv_hwprobe` only exists in the riscv64 table.
    let json_hwprobe = json_with("riscv_hwprobe");
    assert!(compile_from_json(json_hwprobe.as_bytes(), TargetArch::riscv64).is_ok());
    assert!(compile_from_json(json_hwprobe.as_bytes(), TargetArch::x86_64).is_err());
    assert!(compile_from_json(json_hwprobe.as_bytes(), TargetArch::aarch64).is_err());
}

#[test]
fn test_conflicting_action_aliases_fail_closed() {
    // `filter_action` is an alias of `match_action`; specifying both is a
    // conflict and must be rejected.
    let json_input = r#"{
        "main_thread": {
            "mismatch_action": "trap",
            "match_action": "allow",
            "filter_action": "trap",
            "filter": []
        }
    }"#;
    for (arch_name, _, _) in ARCH_FIXTURES.iter() {
        assert!(
            compile_from_json(json_input.as_bytes(), (*arch_name).try_into().unwrap()).is_err()
        );
    }

    // `default_action` is an alias of `mismatch_action`.
    let json_input = r#"{
        "main_thread": {
            "mismatch_action": "trap",
            "default_action": "allow",
            "match_action": "allow",
            "filter": []
        }
    }"#;
    for (arch_name, _, _) in ARCH_FIXTURES.iter() {
        assert!(
            compile_from_json(json_input.as_bytes(), (*arch_name).try_into().unwrap()).is_err()
        );
    }
}

#[test]
fn test_duplicate_thread_keys_fail_closed() {
    let json_input = r#"{
        "main_thread": {
            "mismatch_action": "trap",
            "match_action": "allow",
            "filter": []
        },
        "main_thread": {
            "mismatch_action": "trap",
            "match_action": "allow",
            "filter": []
        }
    }"#;
    for (arch_name, _, _) in ARCH_FIXTURES.iter() {
        assert!(
            compile_from_json(json_input.as_bytes(), (*arch_name).try_into().unwrap()).is_err()
        );
    }
}

#[test]
fn test_foreign_arch_filters_fail_closed_at_runtime() {
    // A filter compiled for an architecture different from the running one
    // must kill the process upon evaluation (it appears as if it received a
    // SIGSYS), instead of executing rules against the wrong syscall table.
    let foreign_archs: &[&str] = match ARCH {
        "x86_64" => &["aarch64", "riscv64"],
        "aarch64" => &["x86_64", "riscv64"],
        "riscv64" => &["x86_64", "aarch64"],
        _ => &[],
    };

    let json_input = r#"{
        "main_thread": {
            "mismatch_action": "allow",
            "match_action": "trap",
            "filter": []
        }
    }"#;

    for arch in foreign_archs {
        let mut filters =
            compile_from_json(json_input.as_bytes(), (*arch).try_into().unwrap()).unwrap();
        let filter = filters.remove("main_thread").unwrap();

        // We need to use `fork` instead of `thread::spawn` to prohibit cargo
        // from failing the test due to the SIGSYS exit code.
        let pid = unsafe { libc::fork() };
        match pid {
            0 => {
                apply_filter(&filter).unwrap();
                // This syscall triggers the arch validation sequence.
                unsafe { libc::getpid() };
                // If we got here, the filter did not fail closed.
                unsafe { libc::_exit(1) };
            }
            child_pid => {
                let mut child_status: i32 = -1;
                let pid_done = unsafe { libc::waitpid(child_pid, &mut child_status, 0) };
                assert_eq!(pid_done, child_pid);

                assert!(
                    libc::WIFSIGNALED(child_status),
                    "filter compiled for {} did not kill the process",
                    arch
                );
                assert_eq!(libc::WTERMSIG(child_status), libc::SIGSYS);
            }
        }
    }
}
