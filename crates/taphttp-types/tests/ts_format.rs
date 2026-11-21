//! `ts` on the wire must stay byte-identical across the chrono -> jiff swap
//! (#11): existing logs, sqlite rows and consumers (spall's UI sorts on the
//! string) keep working. These tests only touch JSON text, so they pin the
//! format whatever type backs `TrafficEntry::ts`.

use taphttp_types::TrafficEntry;

fn ts_of(line: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    v["ts"].as_str().unwrap().to_string()
}

/// Parse a line, write it back, return the written `ts`.
fn rewritten_ts(line: &str) -> String {
    let e: TrafficEntry = serde_json::from_str(line).unwrap();
    ts_of(&serde_json::to_string(&e).unwrap())
}

fn line_with_ts(ts: &str) -> String {
    format!(
        r#"{{"schema_version":4,"id":"x","ts":"{ts}","host":"h","method":"GET","url":"http://h/","req_headers":[],"req_body":null,"status":200,"res_headers":[],"res_body":null,"duration_ms":1,"replay_of":null,"source":null}}"#
    )
}

#[test]
fn real_v3_lines_round_trip_with_identical_ts() {
    let real = include_str!("fixtures/v3-real.jsonl");
    let mut n = 0;
    for line in real.lines() {
        assert_eq!(rewritten_ts(line), ts_of(line), "{line}");
        // And the rewritten line parses back to the same entry.
        let e: TrafficEntry = serde_json::from_str(line).unwrap();
        let again: TrafficEntry =
            serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(again, e);
        n += 1;
    }
    assert_eq!(n, 2, "fixture has a 9-digit and a 6-digit ts");
}

/// chrono's serde writes UTC with `Z` and 0, 3, 6 or 9 fractional digits:
/// the fewest of those that represent the value exactly.
#[test]
fn fraction_is_0_3_6_or_9_digits() {
    for (input, written) in [
        ("2026-11-21T02:44:44Z", "2026-11-21T02:44:44Z"),
        ("2026-11-21T02:44:44.000Z", "2026-11-21T02:44:44Z"),
        ("2026-11-21T02:44:44.5Z", "2026-11-21T02:44:44.500Z"),
        ("2026-11-21T02:44:44.123Z", "2026-11-21T02:44:44.123Z"),
        ("2026-11-21T02:44:44.1234Z", "2026-11-21T02:44:44.123400Z"),
        ("2026-11-21T02:44:44.516724Z", "2026-11-21T02:44:44.516724Z"),
        ("2026-11-21T02:44:44.000120Z", "2026-11-21T02:44:44.000120Z"),
        (
            "2026-11-21T02:44:44.1234567Z",
            "2026-11-21T02:44:44.123456700Z",
        ),
        (
            "2026-11-21T02:44:44.333929611Z",
            "2026-11-21T02:44:44.333929611Z",
        ),
        (
            "2026-11-21T02:44:44.000000001Z",
            "2026-11-21T02:44:44.000000001Z",
        ),
    ] {
        assert_eq!(rewritten_ts(&line_with_ts(input)), written, "input {input}");
    }
}

#[test]
fn offsets_are_accepted_and_written_as_utc_z() {
    for (input, written) in [
        ("2026-11-21T04:44:44.5+02:00", "2026-11-21T02:44:44.500Z"),
        ("2026-11-20T21:44:44-05:00", "2026-11-21T02:44:44Z"),
        ("2026-11-21T02:44:44+00:00", "2026-11-21T02:44:44Z"),
    ] {
        assert_eq!(rewritten_ts(&line_with_ts(input)), written, "input {input}");
    }
}

#[test]
fn non_timestamps_are_rejected() {
    for bad in ["", "yesterday", "2026-11-21", "2026-13-01T00:00:00Z"] {
        let r = serde_json::from_str::<TrafficEntry>(&line_with_ts(bad));
        assert!(r.is_err(), "{bad:?} should not parse");
    }
}
