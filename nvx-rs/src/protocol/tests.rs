//! Tests of the control protocol, including golden byte fixtures.
//!
//! The fixtures are literal bytes, produced with Python's struct module using the formats of
//! `scripts/nvx_tools/control_session.py` and the guest agent: `"<4sHBB16sQQI"` for outer
//! headers, `"<4sBBHQiI"` for application frames, `"<IHH"` and `"<IHHHHI"` for `EXEC` payloads,
//! `"<II"` and `"<HHH"` for `MAPS` payloads, and `"<I"` for features. The host's encoders and the
//! decoders that the fake OpenVMM shares with it must both match them, so a change to the codec
//! that both sides would agree on still fails here.

use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

/// A workload that runs `argv` without a timeout in `/` with the default environment.
fn program<'a>(argv: &[&str]) -> Workload<'a> {
    Workload {
        argv: argv.iter().map(|argument| (*argument).to_owned()).collect(),
        timeout_ms: 0,
        cwd: None,
        environment: WorkloadEnvironment::Default,
        limits: ExecLimits::default(),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn host_attach_matches_the_python_client() {
    let capability: Vec<u8> = (1..=32).collect();
    let record = encode_outer(OUTER_HOST_ATTACH, &[0; 16], 0, 0, &capability).unwrap();
    assert_eq!(
        hex(&record),
        concat!(
            "4e56585301000200",
            "00000000000000000000000000000000",
            "0000000000000000",
            "0000000000000000",
            "20000000",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        )
    );
}

#[test]
fn data_record_matches_the_python_client() {
    let instance: [u8; 16] = array(&(0x10..0x20).collect::<Vec<u8>>());
    let frame = encode_app(APP_PING, 0x0102_0304_0506_0708, 0, &[]);
    assert_eq!(
        hex(&frame),
        "4e5658430101000008070605040302010000000000000000"
    );
    let record = encode_outer(OUTER_DATA, &instance, 3, 7, &frame).unwrap();
    assert_eq!(
        hex(&record[..OUTER_HEADER_LEN]),
        concat!(
            "4e56585301000500101112131415161718191a1b1c1d1e1f",
            "0300000000000000",
            "0700000000000000",
            "18000000",
        )
    );
    let header = decode_outer_header(&array(&record[..OUTER_HEADER_LEN])).unwrap();
    assert_eq!(
        header,
        OuterHeader {
            record_type: OUTER_DATA,
            instance_id: instance,
            epoch: 3,
            sequence: 7,
            length: APP_HEADER_LEN,
        }
    );
}

#[test]
fn exec_payload_matches_the_python_client() {
    let workload = Workload {
        timeout_ms: 5000,
        ..program(&["/bin/sh", "-c", "echo hi"])
    };
    let payload = encode_exec_payload(&workload).unwrap();
    assert_eq!(
        hex(&payload),
        concat!(
            "8813000003000000",
            "070000002f62696e2f7368",
            "020000002d63",
            "070000006563686f206869",
        )
    );
}

// Golden vector produced with Python's struct module: "<II", then "<HHH" before each entry.
#[test]
fn maps_payload_lists_each_entry_after_its_position() {
    let payloads = encode_maps_payloads(
        &[map("0", "/w", false), map("1/a b", "/t/x", true)],
        OUTER_MAX_PAYLOAD - APP_HEADER_LEN,
    )
    .unwrap();
    assert_eq!(payloads.len(), 1);
    assert_eq!(
        hex(&payloads[0]),
        concat!(
            "0000000002000000",
            "000001000200",
            "30",
            "2f77",
            "010005000400",
            "312f612062",
            "2f742f78",
        )
    );
}

#[test]
fn golden_outer_headers_decode_as_the_broker_sends_them() {
    let ready = bytes(concat!(
        "4e56585301000700",
        "07070707070707070707070707070707",
        "0400000000000000",
        "0900000000000000",
        "00000000",
    ));
    let expected = OuterHeader {
        record_type: OUTER_READY,
        instance_id: [7; 16],
        epoch: 4,
        sequence: 9,
        length: 0,
    };
    assert_eq!(decode_outer_header(&array(&ready)).unwrap(), expected);
    assert_eq!(
        encode_outer(OUTER_READY, &[7; 16], 4, 9, &[]).unwrap(),
        ready
    );
    // The broker's other records differ only in their type byte.
    for (record_type, byte) in [
        (OUTER_HOST_ATTACH, "02"),
        (OUTER_RESET, "03"),
        (OUTER_DATA, "05"),
        (OUTER_WAIT, "06"),
        (OUTER_READY, "07"),
        (OUTER_ERROR, "08"),
    ] {
        let mut header = ready.clone();
        header[6] = bytes(byte)[0];
        assert_eq!(
            decode_outer_header(&array(&header)).unwrap().record_type,
            record_type
        );
    }
}

#[test]
fn golden_application_frames_round_trip() {
    let fixtures: [(&str, u8, u64, i32, &[u8]); 4] = [
        (
            "4e5658430101000008070605040302010000000000000000",
            APP_PING,
            0x0102_0304_0506_0708,
            0,
            b"",
        ),
        (
            "4e565843018200000900000000000000000000000300000068690a",
            APP_STDOUT,
            9,
            0,
            b"hi\n",
        ),
        (
            "4e565843018400000900000000000000030000000400000065786974",
            APP_EXIT,
            9,
            3,
            b"exit",
        ),
        (
            "4e56584301ff00000900000000000000020000000a0000006377642d6661696c6564",
            APP_ERROR,
            9,
            2,
            CWD_FAILED.as_bytes(),
        ),
    ];
    for (fixture, kind, request_id, status, payload) in fixtures {
        let frame = bytes(fixture);
        assert_eq!(
            hex(&encode_app(kind, request_id, status, payload)),
            fixture,
            "{kind:#x}"
        );
        assert_eq!(
            decode_app(&frame).unwrap(),
            AppFrame {
                kind,
                request_id,
                status,
                payload,
            }
        );
    }
}

/// `EXEC` payloads in their wire form, the workload that the host encodes into each, and the
/// payload that the guest agent decodes from each.
#[test]
fn golden_exec_payloads_round_trip() {
    let environment = strings(&["FOO=a b", "EMPTY="]);
    let fixtures: [(&str, Workload<'_>, ExecPayload); 6] = [
        (
            concat!(
                "8813000003000000",
                "070000002f62696e2f7368",
                "020000002d63",
                "070000006563686f206869",
            ),
            Workload {
                timeout_ms: 5000,
                ..program(&["/bin/sh", "-c", "echo hi"])
            },
            ExecPayload {
                timeout_ms: 5000,
                argv: strings(&["/bin/sh", "-c", "echo hi"]),
                cwd: None,
                environment: None,
                inherit_default_env: true,
                limits: ExecLimits::default(),
            },
        ),
        (
            concat!("ffffffff01000000", "090000002f62696e2f74727565"),
            Workload {
                timeout_ms: MAX_TIMEOUT_MS,
                ..program(&["/bin/true"])
            },
            ExecPayload {
                timeout_ms: MAX_TIMEOUT_MS,
                argv: strings(&["/bin/true"]),
                cwd: None,
                environment: None,
                inherit_default_env: true,
                limits: ExecLimits::default(),
            },
        ),
        (
            concat!(
                "0000000001000100",
                "0100000004000000",
                "080000002f62696e2f707764",
                "2f746d70",
            ),
            Workload {
                cwd: Some("/tmp"),
                ..program(&["/bin/pwd"])
            },
            ExecPayload {
                timeout_ms: 0,
                argv: strings(&["/bin/pwd"]),
                cwd: Some("/tmp".to_owned()),
                environment: None,
                inherit_default_env: true,
                limits: ExecLimits::default(),
            },
        ),
        (
            concat!(
                "0000000001000100",
                "0700020004000000",
                "080000002f62696e2f656e76",
                "2f746d70",
                "07000000464f4f3d612062",
                "06000000454d5054593d",
            ),
            Workload {
                cwd: Some("/tmp"),
                environment: WorkloadEnvironment::Layered(&environment),
                ..program(&["/bin/env"])
            },
            ExecPayload {
                timeout_ms: 0,
                argv: strings(&["/bin/env"]),
                cwd: Some("/tmp".to_owned()),
                environment: Some(environment.clone()),
                inherit_default_env: true,
                limits: ExecLimits::default(),
            },
        ),
        (
            concat!(
                "0000000001000100",
                "0200020000000000",
                "080000002f62696e2f656e76",
                "07000000464f4f3d612062",
                "06000000454d5054593d",
            ),
            Workload {
                environment: WorkloadEnvironment::Replaced(&environment),
                ..program(&["/bin/env"])
            },
            ExecPayload {
                timeout_ms: 0,
                argv: strings(&["/bin/env"]),
                cwd: None,
                environment: Some(environment.clone()),
                inherit_default_env: false,
                limits: ExecLimits::default(),
            },
        ),
        (
            concat!(
                "0000000001000100",
                "0200000000000000",
                "080000002f62696e2f656e76",
            ),
            Workload {
                environment: WorkloadEnvironment::Replaced(&[]),
                ..program(&["/bin/env"])
            },
            ExecPayload {
                timeout_ms: 0,
                argv: strings(&["/bin/env"]),
                cwd: None,
                environment: Some(Vec::new()),
                inherit_default_env: false,
                limits: ExecLimits::default(),
            },
        ),
    ];
    for (fixture, workload, decoded) in fixtures {
        assert_eq!(
            hex(&encode_exec_payload(&workload).unwrap()),
            fixture,
            "{workload:?}"
        );
        assert_eq!(decode_exec_payload(&bytes(fixture)).unwrap(), decoded);
    }
}

#[test]
fn golden_maps_payload_round_trips() {
    let fixture = concat!(
        "0000000002000000",
        "000001000200",
        "30",
        "2f77",
        "010005000400",
        "312f612062",
        "2f742f78",
    );
    let maps = [map("0", "/w", false), map("1/a b", "/t/x", true)];
    let payloads = encode_maps_payloads(&maps, OUTER_MAX_PAYLOAD - APP_HEADER_LEN).unwrap();
    assert_eq!(payloads.len(), 1);
    assert_eq!(hex(&payloads[0]), fixture);
    assert_eq!(
        decode_maps_payload(&bytes(fixture)).unwrap(),
        MapsPayload {
            first: 0,
            maps: maps.to_vec(),
        }
    );
    // A later request continues the table at its first entry's index.
    let continued = concat!("0300000001000000", "000001000200", "35", "2f77");
    assert_eq!(
        decode_maps_payload(&bytes(continued)).unwrap(),
        MapsPayload {
            first: 3,
            maps: vec![map("5", "/w", false)],
        }
    );
}

#[test]
fn golden_features_payload_names_the_required_bits() {
    assert_eq!(hex(&GuestFeatures::REQUIRED.encode()), "7d000000");
    assert_eq!(
        GuestFeatures::decode(&bytes("7d000000")).unwrap(),
        GuestFeatures::REQUIRED
    );
    assert_eq!(
        GuestFeatures::CANCEL
            | GuestFeatures::WORKLOAD_ACCOUNT
            | GuestFeatures::EXEC_CGROUP
            | GuestFeatures::EXEC_ENVIRONMENT
            | GuestFeatures::EXEC_CWD
            | GuestFeatures::HOST_MAPPING_TABLE,
        GuestFeatures::REQUIRED
    );
}

#[test]
fn exec_payload_carries_every_32_bit_timeout() {
    for timeout_ms in [0, 3_600_001, 86_400_000, MAX_TIMEOUT_MS] {
        let workload = Workload {
            timeout_ms,
            cwd: Some("/tmp"),
            ..program(&["/bin/true"])
        };
        let payload = encode_exec_payload(&workload).unwrap();
        assert_eq!(payload[..4], timeout_ms.to_le_bytes(), "{timeout_ms}");
        assert_eq!(
            decode_exec_payload(&payload).unwrap().timeout_ms,
            timeout_ms
        );
    }
}

#[test]
fn exec_payload_carries_the_working_directory_natively() {
    for cwd in ["", "tmp", &format!("/{}", "a".repeat(4096)), "/t\0mp"] {
        let workload = Workload {
            cwd: Some(cwd),
            ..program(&["/bin/pwd"])
        };
        assert!(encode_exec_payload(&workload).is_err(), "{cwd:?}");
    }
    let longest = format!("/{}", "a".repeat(4095));
    let workload = Workload {
        cwd: Some(&longest),
        ..program(&["/bin/pwd"])
    };
    let payload = encode_exec_payload(&workload).unwrap();
    assert_eq!(decode_exec_payload(&payload).unwrap().cwd, Some(longest));
}

#[test]
fn exec_payload_distinguishes_explicit_environments() {
    let environment = strings(&["FOO=a b", "EMPTY="]);
    let empty = Workload {
        environment: WorkloadEnvironment::Replaced(&[]),
        ..program(&["/bin/env"])
    };
    let empty = encode_exec_payload(&empty).unwrap();
    assert_eq!(&empty[6..16], &[1, 0, 2, 0, 0, 0, 0, 0, 0, 0]);
    let layered = Workload {
        environment: WorkloadEnvironment::Layered(&environment),
        ..program(&["/bin/env"])
    };
    let layered = encode_exec_payload(&layered).unwrap();
    assert_eq!(&layered[8..10], &6u16.to_le_bytes());
    let default = encode_exec_payload(&program(&["/bin/env"])).unwrap();
    assert_eq!(&default[6..8], &[0, 0]);
}

/// A payload that carries per-execution limits uses the second extension, and the guest reads
/// back the values the host wrote; a request outside the supported range is refused instead of
/// being clipped.
#[test]
fn exec_limits_round_trip_and_are_bounded() {
    let workload = |limits: ExecLimits| Workload {
        limits,
        ..program(&["/bin/true"])
    };
    let limits = ExecLimits {
        mem_mb: 256,
        cpu_percent: 50,
        pids_max: 8,
    };
    let payload = encode_exec_payload(&workload(limits)).unwrap();
    // The header announces the second extension, which is what a guest keys on.
    assert_eq!(
        u16::from_le_bytes([payload[6], payload[7]]),
        EXEC_EXTENDED_V2,
        "a payload with limits must use extension 2"
    );
    let decoded = decode_exec_payload(&payload).unwrap();
    assert_eq!(decoded.limits, limits);
    assert_eq!(decoded.argv, ["/bin/true"]);

    // Without limits the payload stays what an older guest understands, and decodes to no limits.
    let plain = encode_exec_payload(&workload(ExecLimits::default())).unwrap();
    assert_ne!(
        u16::from_le_bytes([plain[6], plain[7]]),
        EXEC_EXTENDED_V2,
        "a payload without limits must not claim the new extension"
    );
    assert_eq!(
        decode_exec_payload(&plain).unwrap().limits,
        ExecLimits::default()
    );

    // One field over its bound refuses the request: clipping a limit would be a silent promise.
    for out_of_range in [
        ExecLimits {
            mem_mb: MAX_EXEC_MEMORY_MIB + 1,
            ..limits
        },
        ExecLimits {
            cpu_percent: MAX_EXEC_CPU_PERCENT + 1,
            ..limits
        },
        ExecLimits {
            pids_max: MAX_EXEC_PIDS + 1,
            ..limits
        },
    ] {
        assert!(
            encode_exec_payload(&workload(out_of_range)).is_err(),
            "an out-of-range limit must be refused: {out_of_range:?}"
        );
    }
}

#[test]
fn exec_payload_enforces_agent_limits() {
    let encode = |argv: Vec<String>, timeout_ms| {
        encode_exec_payload(&Workload {
            argv,
            timeout_ms,
            ..program(&[])
        })
    };
    let argument = |value: &str| vec![value.to_owned()];
    assert!(encode(argument("bin/sh"), 0).is_err());
    assert!(encode(Vec::new(), 0).is_err());
    assert!(encode(argument(&format!("/{}", "a".repeat(4096))), 0).is_err());
    assert!(encode(vec!["/bin/true".to_owned(); 65], 0).is_err());
    assert!(encode(vec!["/bin/echo".to_owned(), String::new()], 0).is_err());
    assert!(encode(vec!["/bin/true".to_owned(); 64], MAX_TIMEOUT_MS).is_ok());
    let unique =
        |count: usize| -> Vec<String> { (0..count).map(|index| format!("KEY{index}=")).collect() };
    let encode_environment = |environment: &[String]| {
        encode_exec_payload(&Workload {
            environment: WorkloadEnvironment::Replaced(environment),
            ..program(&["/bin/env"])
        })
    };
    assert!(encode_environment(&unique(MAX_ENVIRONMENT)).is_ok());
    assert!(encode_environment(&unique(MAX_ENVIRONMENT + 1)).is_err());
    assert!(encode_environment(&["A=1".to_owned(), "A=2".to_owned()]).is_err());
    assert!(encode_environment(&["A=1".to_owned(), "AB=2".to_owned()]).is_ok());
    for entry in ["NOVALUE", "=value", &format!("A={}", "x".repeat(4096))] {
        assert!(encode_environment(&[entry.to_owned()]).is_err());
    }
    // Everything shares the 64 KiB control record.
    let large = |count: usize| -> Vec<String> {
        (0..count)
            .map(|index| format!("KEY{index:02}={}", "x".repeat(4000)))
            .collect()
    };
    assert!(encode_environment(&large(15)).is_ok());
    assert!(encode_environment(&large(17)).is_err());
    // The working directory counts toward the same limit.
    let full = vec![format!("/{}", "a".repeat(MAX_ARGUMENT_BYTES - 1)); 15];
    assert!(encode(full.clone(), 0).is_ok());
    let cwd = format!("/{}", "d".repeat(MAX_CWD_BYTES - 1));
    let with_cwd = Workload {
        argv: full,
        cwd: Some(&cwd),
        ..program(&[])
    };
    assert!(encode_exec_payload(&with_cwd).is_err());
}

/// Encodes an extended exec request with an explicit environment, without the host's checks.
fn extended(argv: &[&str], cwd: Option<&str>, environment: &[&str]) -> Vec<u8> {
    let length = |text: &str| u32::try_from(text.len()).unwrap().to_le_bytes();
    let mut flags = EXEC_ENVIRONMENT_PRESENT;
    if cwd.is_some() {
        flags |= EXEC_CWD_PRESENT;
    }
    let mut payload = 0u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&u16::try_from(argv.len()).unwrap().to_le_bytes());
    payload.extend_from_slice(&EXEC_EXTENDED.to_le_bytes());
    payload.extend_from_slice(&flags.to_le_bytes());
    payload.extend_from_slice(&u16::try_from(environment.len()).unwrap().to_le_bytes());
    payload.extend_from_slice(&length(cwd.unwrap_or_default()));
    for argument in argv {
        payload.extend_from_slice(&length(argument));
        payload.extend_from_slice(argument.as_bytes());
    }
    payload.extend_from_slice(cwd.unwrap_or_default().as_bytes());
    for entry in environment {
        payload.extend_from_slice(&length(entry));
        payload.extend_from_slice(entry.as_bytes());
    }
    payload
}

#[test]
fn exec_requests_are_refused_where_the_guest_agent_refuses_them() {
    let exec = decode_exec_payload(&extended(
        &["/usr/bin/env", "-0"],
        Some("/tmp"),
        &["FOO=bar", "EMPTY="],
    ))
    .unwrap();
    assert_eq!(exec.argv, ["/usr/bin/env", "-0"]);
    assert_eq!(exec.cwd.as_deref(), Some("/tmp"));
    assert_eq!(
        exec.environment,
        Some(vec!["FOO=bar".to_owned(), "EMPTY=".to_owned()])
    );
    assert!(!exec.inherit_default_env);
    for payload in [
        extended(&["/usr/bin/env"], None, &["FOO=b\0r"]),
        extended(&["/usr/bin/env"], None, &["F\0O=bar"]),
        extended(&["/usr/bin/e\0nv"], None, &[]),
        extended(&["/usr/bin/env", "a\0b"], None, &[]),
        extended(&["/usr/bin/env"], Some("/t\0mp"), &[]),
        extended(&["/usr/bin/env"], Some("tmp"), &[]),
        extended(&["/usr/bin/env"], None, &["FOO=1", "FOO=2"]),
        extended(&["/usr/bin/env"], None, &["NOVALUE"]),
        extended(&["/usr/bin/env"], None, &["=value"]),
        extended(&[], None, &[]),
        extended(&["/bin/true"; MAX_ARGUMENTS + 1], None, &[]),
        extended(&["usr/bin/env"], None, &[]),
        // The argument count is refused before the arguments are read.
        {
            let mut payload = encode_exec_payload(&program(&["/bin/true"])).unwrap();
            payload[4..6].copy_from_slice(&65u16.to_le_bytes());
            payload
        },
        {
            let mut payload = encode_exec_payload(&program(&["/x"])).unwrap();
            payload[12] = b'x';
            payload
        },
        // An unknown flag, and the inherit flag without an environment.
        {
            let mut payload = extended(&["/usr/bin/env"], None, &[]);
            payload[8] = 0x08;
            payload
        },
        {
            let mut payload = encode_exec_payload(&program(&["/usr/bin/env"])).unwrap();
            payload.push(0);
            payload
        },
        vec![0; 7],
    ] {
        assert!(decode_exec_payload(&payload).is_err(), "{payload:?}");
    }
    let mut inherit_only = extended(&["/usr/bin/env"], None, &[]);
    inherit_only[8..10].copy_from_slice(&EXEC_INHERIT_DEFAULT_ENV.to_le_bytes());
    assert!(decode_exec_payload(&inherit_only).is_err());
    let most = decode_exec_payload(&extended(&["/bin/true"; MAX_ARGUMENTS], None, &[])).unwrap();
    assert_eq!(most.argv.len(), MAX_ARGUMENTS);
}

#[test]
fn decoders_reject_malformed_input() {
    let mut header = [0u8; OUTER_HEADER_LEN];
    assert!(decode_outer_header(&header).is_err());
    header[..4].copy_from_slice(&OUTER_MAGIC);
    header[4] = 1;
    header[40..44].copy_from_slice(&(OUTER_MAX_PAYLOAD as u32 + 1).to_le_bytes());
    assert!(decode_outer_header(&header).is_err());

    let mut frame = encode_app(APP_STDOUT, 1, 0, b"abc");
    assert_eq!(decode_app(&frame).unwrap().payload, b"abc");
    frame.push(0);
    assert!(decode_app(&frame).is_err());
    assert!(decode_app(&frame[..10]).is_err());
}

#[test]
fn exit_categories_match_the_guest_agent() {
    for category in [
        ExitCategory::Exit,
        ExitCategory::Timeout,
        ExitCategory::OutputLimit,
        ExitCategory::Signal,
        ExitCategory::Failed,
        ExitCategory::Cancelled,
    ] {
        assert_eq!(
            ExitCategory::parse(category.as_str().as_bytes()).unwrap(),
            category
        );
    }
    assert_eq!(ExitCategory::parse(b"exit").unwrap(), ExitCategory::Exit);
    assert_eq!(
        ExitCategory::parse(b"timeout").unwrap(),
        ExitCategory::Timeout
    );
    assert_eq!(
        ExitCategory::parse(b"output-limit").unwrap(),
        ExitCategory::OutputLimit
    );
    assert_eq!(
        ExitCategory::parse(b"signal").unwrap(),
        ExitCategory::Signal
    );
    assert_eq!(
        ExitCategory::parse(b"failed").unwrap(),
        ExitCategory::Failed
    );
    assert_eq!(
        ExitCategory::parse(b"cancelled").unwrap(),
        ExitCategory::Cancelled
    );
    assert!(ExitCategory::parse(b"canceled").is_err());
}

#[test]
fn guest_features_report_what_a_guest_lacks() {
    let required = GuestFeatures::REQUIRED;
    let complete = GuestFeatures::decode(&required.encode()).unwrap();
    assert!(complete.missing(required).is_empty());
    assert!(complete.contains(required));

    // Trailing bytes belong to later revisions.
    let cancel_only = GuestFeatures::decode(&[1, 0, 0, 0, 0xaa]).unwrap();
    assert_eq!(cancel_only, GuestFeatures::CANCEL);
    assert!(!cancel_only.contains(required));
    assert_eq!(
        cancel_only.missing(required),
        [
            "workload accounts",
            "workload containment",
            "per-execution environments",
            "working directories",
            "host path mapping tables",
        ]
    );
    assert!(GuestFeatures::decode(&[1, 0, 0]).is_err());

    // A guest of the previous release announced its host mappings with bit 1, which no
    // longer counts.
    let previous = GuestFeatures::decode(&0b11_1111u32.to_le_bytes()).unwrap();
    assert_eq!(previous.missing(required), ["host path mapping tables"]);

    // Every required feature has a name, so a refusal can say what is missing.
    assert_eq!(
        GuestFeatures::NONE.missing(required).len(),
        required.bits().count_ones() as usize
    );
}

#[test]
fn guest_features_use_distinct_bits() {
    let mut seen = 1u32 << 1;
    for (feature, name) in GuestFeatures::NAMES {
        assert_eq!(feature.bits().count_ones(), 1, "{name}");
        assert_eq!(seen & feature.bits(), 0, "{name} reuses a feature bit");
        seen |= feature.bits();
    }
}

fn map(source: &str, target: &str, read_only: bool) -> HostMap {
    HostMap {
        source: source.to_owned(),
        target: target.to_owned(),
        read_only,
    }
}

#[test]
fn maps_payloads_are_split_to_fit_the_limit() {
    let maps: Vec<HostMap> = (0..10)
        .map(|index| {
            map(
                &format!("0/{index:02}"),
                &format!("/work/{index:02}"),
                index % 2 == 0,
            )
        })
        .collect();
    // Each entry takes 6 + 4 + 8 bytes, so a 64-byte payload holds 3 entries.
    let payloads = encode_maps_payloads(&maps, 64).unwrap();
    assert_eq!(payloads.len(), 4);
    let mut next = 0u32;
    for payload in &payloads {
        assert!(payload.len() <= 64);
        assert_eq!(u32::from_le_bytes(array(&payload[..4])), next);
        let count = u32::from_le_bytes(array(&payload[4..8]));
        let mut offset = MAPS_HEADER_LEN;
        for index in next..next + count {
            let field = |at: usize| usize::from(u16::from_le_bytes(array(&payload[at..at + 2])));
            let flags = field(offset);
            let source_len = field(offset + 2);
            let target_len = field(offset + 4);
            offset += MAP_ENTRY_HEADER_LEN;
            let expected = &maps[index as usize];
            assert_eq!(flags == usize::from(MAP_READ_ONLY), expected.read_only);
            assert_eq!(
                &payload[offset..offset + source_len],
                expected.source.as_bytes()
            );
            offset += source_len;
            assert_eq!(
                &payload[offset..offset + target_len],
                expected.target.as_bytes()
            );
            offset += target_len;
        }
        assert_eq!(offset, payload.len());
        // The guest agent reads back exactly the entries that the host sent.
        let decoded = decode_maps_payload(payload).unwrap();
        assert_eq!(decoded.first, next);
        assert_eq!(
            decoded.maps,
            maps[next as usize..(next + count) as usize].to_vec()
        );
        next += count;
    }
    assert_eq!(next, 10);

    // The largest table fits the control protocol in a few requests.
    let long = format!("/{}", "t".repeat(MAX_MAP_PATH_BYTES - 1));
    let largest: Vec<HostMap> = (0..MAX_HOST_MAPPINGS)
        .map(|index| map(&format!("0/{index}"), &long, false))
        .collect();
    let payloads = encode_maps_payloads(&largest, OUTER_MAX_PAYLOAD - APP_HEADER_LEN).unwrap();
    assert!(
        payloads
            .iter()
            .all(|payload| APP_HEADER_LEN + payload.len() <= OUTER_MAX_PAYLOAD)
    );
    assert_eq!(
        payloads
            .iter()
            .map(|payload| u32::from_le_bytes(array(&payload[4..8])))
            .sum::<u32>() as usize,
        MAX_HOST_MAPPINGS
    );
}

#[test]
fn maps_payloads_enforce_agent_limits() {
    let limit = OUTER_MAX_PAYLOAD - APP_HEADER_LEN;
    let too_long = format!("/{}", "t".repeat(MAX_MAP_PATH_BYTES));
    for invalid in [
        map("", "/w", false),
        map("/0", "/w", false),
        map("0", "w", false),
        map("0", &too_long, false),
        map(&"s".repeat(MAX_MAP_PATH_BYTES + 1), "/w", false),
        map("0\0", "/w", false),
        map("0", "/w\0", false),
        // The guest agent refuses empty, `.`, and `..` components in either path.
        map(".", "/w", false),
        map("0/.", "/w", false),
        map("0/../1", "/w", false),
        map("0//1", "/w", false),
        map("0/", "/w", false),
        map("0", "/", false),
        map("0", "//w", false),
        map("0", "/w/", false),
        map("0", "/tmp/../etc", false),
        map("0", "/w/./x", false),
    ] {
        assert!(
            encode_maps_payloads(std::slice::from_ref(&invalid), limit).is_err(),
            "{invalid:?}"
        );
    }
    // Names that merely start with dots are ordinary components.
    let dotted = map("0/.config", "/home/..data/...", false);
    let payloads = encode_maps_payloads(std::slice::from_ref(&dotted), limit).unwrap();
    assert_eq!(decode_maps_payload(&payloads[0]).unwrap().maps, [dotted]);
    let longest = format!("/{}", "t".repeat(MAX_MAP_PATH_BYTES - 1));
    let source = "s".repeat(MAX_MAP_PATH_BYTES);
    assert!(encode_maps_payloads(&[map(&source, &longest, false)], limit).is_ok());
    assert!(encode_maps_payloads(&[], limit).is_err());
    let too_many = vec![map("0", "/w", true); MAX_HOST_MAPPINGS + 1];
    assert!(encode_maps_payloads(&too_many, limit).is_err());
    // An entry that cannot fit any request is refused rather than split.
    assert!(encode_maps_payloads(&[map("0", "/abcdefghijklmnop", true)], 20).is_err());
}

#[test]
fn maps_decoding_refuses_what_the_guest_agent_refuses() {
    let valid = bytes(concat!("0000000001000000", "000001000200", "30", "2f77"));
    decode_maps_payload(&valid).unwrap();
    let mut unknown_flag = valid.clone();
    unknown_flag[8] = 2;
    let mut relative_target = valid.clone();
    relative_target[15] = b'w';
    let mut nul_target = valid.clone();
    nul_target[16] = 0;
    let mut not_utf8 = valid.clone();
    not_utf8[14] = 0xff;
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut dot_source = valid.clone();
    dot_source[14] = b'.';
    let mut nul_source = valid.clone();
    nul_source[14] = 0;
    let mut dot_target = valid.clone();
    dot_target[16] = b'.';
    for invalid in [
        unknown_flag,
        relative_target,
        nul_target,
        not_utf8,
        trailing,
        dot_source,
        nul_source,
        dot_target,
        valid[..valid.len() - 1].to_vec(),
        valid[..7].to_vec(),
        // One more entry announced than the payload holds.
        bytes(concat!("0000000002000000", "000001000200", "30", "2f77")),
        // An empty source, the guest's root, a trailing slash, and a `..` component.
        bytes(concat!("0000000001000000", "000000000200", "2f77")),
        bytes(concat!("0000000001000000", "000001000100", "30", "2f")),
        bytes(concat!("0000000001000000", "000001000300", "30", "2f772f")),
        bytes(concat!(
            "0000000001000000",
            "000004000200",
            "302f2e2e",
            "2f77"
        )),
    ] {
        assert!(decode_maps_payload(&invalid).is_err(), "{invalid:?}");
    }
}

fn guest_agent_source() -> Option<String> {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .join("guest")
        .join("common")
        .join("nvx-managed-agent.c");
    std::fs::read_to_string(source).ok()
}

#[test]
fn feature_definitions_match_the_guest_agent_source() {
    let Some(source) = guest_agent_source() else {
        return;
    };
    let mut definitions = vec![
        format!("#define APP_FEATURES {APP_FEATURES}U"),
        format!("#define APP_MAPS {APP_MAPS}U"),
    ];
    for (name, feature) in [
        ("CANCEL", GuestFeatures::CANCEL),
        ("WORKLOAD_ACCOUNT", GuestFeatures::WORKLOAD_ACCOUNT),
        ("EXEC_CGROUP", GuestFeatures::EXEC_CGROUP),
        ("EXEC_ENVIRONMENT", GuestFeatures::EXEC_ENVIRONMENT),
        ("EXEC_CWD", GuestFeatures::EXEC_CWD),
        ("HOST_MAPPING_TABLE", GuestFeatures::HOST_MAPPING_TABLE),
    ] {
        let bit = feature.bits().trailing_zeros();
        definitions.push(format!("#define FEATURE_{name} (1U << {bit})"));
    }
    for definition in definitions {
        assert!(
            source.contains(&definition),
            "the guest agent does not define `{definition}`"
        );
    }
    // The retired bit stays unused, so hosts that need it refuse the image.
    assert!(!source.contains("(1U << 1)"));
}

#[test]
fn host_mapping_table_matches_the_guest_agent_source() {
    let Some(source) = guest_agent_source() else {
        return;
    };
    for expected in [
        format!("#define MAX_HOST_MAPPINGS {MAX_HOST_MAPPINGS}U"),
        format!("#define MAX_GUEST_PATH {}U", MAX_MAP_PATH_BYTES + 1),
        format!("#define MAPS_HEADER_LEN {MAPS_HEADER_LEN}U"),
        format!("#define MAP_ENTRY_HEADER_LEN {MAP_ENTRY_HEADER_LEN}U"),
        format!("#define MAP_READ_ONLY {MAP_READ_ONLY}U"),
        format!("#define MAPS_TOKEN \"{MAPS_TOKEN}\""),
        format!("\"{MAPPINGS_INCOMPLETE}\""),
        format!("\"{MAPPING_FAILED}\""),
    ] {
        assert!(
            source.contains(&expected),
            "the guest agent does not contain `{expected}`"
        );
    }
}

#[test]
fn exec_extension_matches_the_guest_agent_source() {
    // The agent accepts a working directory as long as one argument, more than any directory
    // that a workload can enter.
    const { assert!(MAX_CWD_BYTES < MAX_ARGUMENT_BYTES) };
    let Some(source) = guest_agent_source() else {
        return;
    };
    for expected in [
        format!("#define EXEC_EXTENDED {EXEC_EXTENDED}U"),
        format!("#define EXEC_EXTENDED_V2 {EXEC_EXTENDED_V2}U"),
        format!("#define EXEC_CWD_PRESENT {EXEC_CWD_PRESENT}U"),
        format!("#define EXEC_ENVIRONMENT_PRESENT {EXEC_ENVIRONMENT_PRESENT}U"),
        format!("#define EXEC_INHERIT_DEFAULT_ENV {EXEC_INHERIT_DEFAULT_ENV}U"),
        // The guest refuses a limit outside these ranges, so a drift here would turn a valid
        // request into a refused one (or the reverse) without either side noticing.
        format!("#define MAX_EXEC_MEMORY_MIB {MAX_EXEC_MEMORY_MIB}U"),
        format!("#define MAX_EXEC_CPU_PERCENT {MAX_EXEC_CPU_PERCENT}U"),
        format!("#define MAX_EXEC_PIDS {MAX_EXEC_PIDS}U"),
        format!("#define MAX_ARGUMENTS {MAX_ARGUMENTS}U"),
        format!("#define MAX_ARGUMENT_LEN {MAX_ARGUMENT_BYTES}U"),
        format!("#define MAX_ENVIRONMENT {MAX_ENVIRONMENT}U"),
        format!(
            "#define MAX_OUTPUT_BYTES ({}U * 1024U)",
            MAX_OUTPUT_BYTES / 1024
        ),
        format!("\"{CWD_FAILED}\""),
        format!("\"{LAUNCH_FAILED}\""),
        format!("\"{INVALID_REQUEST}\""),
        format!("\"{BUSY}\""),
        format!("\"{}\"", String::from_utf8_lossy(UNSUPPORTED_OPERATION)),
    ] {
        assert!(
            source.contains(&expected),
            "the guest agent does not contain `{expected}`"
        );
    }
}

#[test]
fn record_definitions_match_the_guest_agent_source() {
    let Some(source) = guest_agent_source() else {
        return;
    };
    for expected in [
        format!("#define OUTER_HEADER_LEN {OUTER_HEADER_LEN}U"),
        format!("#define OUTER_MAX_PAYLOAD {OUTER_MAX_PAYLOAD}U"),
        format!("#define OUTER_VERSION {OUTER_VERSION}U"),
        format!("#define OUTER_RESET {OUTER_RESET}U"),
        format!("#define OUTER_DATA {OUTER_DATA}U"),
        format!("#define APP_HEADER_LEN {APP_HEADER_LEN}U"),
        format!("#define APP_VERSION {APP_VERSION}U"),
        format!("#define APP_PING {APP_PING}U"),
        format!("#define APP_EXEC {APP_EXEC}U"),
        format!("#define APP_STOP {APP_STOP}U"),
        format!("#define APP_CANCEL {APP_CANCEL}U"),
        format!("#define APP_READY {APP_READY:#x}U"),
        format!("#define APP_STDOUT {APP_STDOUT:#x}U"),
        format!("#define APP_STDERR {APP_STDERR:#x}U"),
        format!("#define APP_EXIT {APP_EXIT:#x}U"),
        format!("#define APP_STOPPED {APP_STOPPED:#x}U"),
        format!("#define APP_ERROR {APP_ERROR:#x}U"),
    ] {
        assert!(
            source.contains(&expected),
            "the guest agent does not contain `{expected}`"
        );
    }
}

#[test]
fn maps_continue_a_table_at_the_first_index() {
    let maps = [HostMap {
        source: "dyn0".to_owned(),
        target: "/mnt/dyn0".to_owned(),
        read_only: true,
    }];
    let payloads = encode_maps_payloads_from(3, &maps, 4096).unwrap();
    assert_eq!(payloads.len(), 1);
    let decoded = decode_maps_payload(&payloads[0]).unwrap();
    assert_eq!(decoded.first, 3);
    assert_eq!(decoded.maps, maps);
    // The plain encoder still starts a table at entry 0.
    let plain = encode_maps_payloads(&maps, 4096).unwrap();
    assert_eq!(decode_maps_payload(&plain[0]).unwrap().first, 0);
    // A runtime sequence number is not an index into the 4096-entry table, so it may pass the
    // table's bound; it still has to fit the 32-bit field.
    let late = encode_maps_payloads_from(MAX_HOST_MAPPINGS + 10, &maps, 4096).unwrap();
    assert_eq!(
        decode_maps_payload(&late[0]).unwrap().first,
        u32::try_from(MAX_HOST_MAPPINGS + 10).unwrap()
    );
    assert!(encode_maps_payloads_from(u32::MAX as usize, &maps, 4096).is_err());
    assert!(encode_maps_payloads_from(u32::MAX as usize - 1, &maps, 4096).is_ok());
}
