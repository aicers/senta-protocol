use std::collections::BTreeMap;

use serde::Deserialize;

use super::*;

#[derive(Debug, Deserialize, PartialEq)]
struct Inner {
    sha256: Base64UrlArray<32>,
    sources: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Content {
    group_id: LowerUuid,
    version: u64,
    inner: Inner,
    channels: BTreeMap<String, Vec<u64>>,
    note: Option<String>,
    #[serde(default)]
    expires_at: Nullable<UtcTimestamp>,
}

const SHA: &str = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
const GROUP: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";

fn valid() -> serde_json::Value {
    serde_json::json!({
        "group_id": GROUP,
        "version": 3,
        "inner": { "sha256": SHA, "sources": ["https://a.example/x"] },
        "channels": { "Microsoft-Windows-Sysmon/Operational": [1, 3] },
    })
}

fn parse(json: &str) -> Result<Content, SchemaError> {
    from_slice(json.as_bytes())
}

fn with(edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>)) -> String {
    let mut value = valid();
    edit(value.as_object_mut().unwrap());
    value.to_string()
}

#[track_caller]
fn rejected(json: &str, path: &str) -> SchemaError {
    let error = parse(json).expect_err(json);
    assert_eq!(error.path(), path, "{error}");
    error
}

#[test]
fn accepts_a_valid_content() {
    let content = parse(&valid().to_string()).unwrap();
    assert_eq!(content.group_id.get(), GROUP.parse::<uuid::Uuid>().unwrap());
    assert_eq!(content.version, 3);
    assert_eq!(content.inner.sha256.get().len(), 32);
    assert_eq!(content.note, None);
    assert_eq!(content.expires_at, Nullable::Absent);
    assert_eq!(
        content.channels["Microsoft-Windows-Sysmon/Operational"],
        [1, 3]
    );
}

#[test]
fn rejects_non_objects_trailing_data_and_bad_utf8() {
    for json in ["[]", "1", "\"x\"", "null", "true"] {
        rejected(json, "$");
    }
    let mut trailing = valid().to_string();
    trailing.push_str(" {}");
    rejected(&trailing, "$");
    assert!(from_slice::<Content>(b"{\"group_id\":\"\xff\"}").is_err());
    assert!(from_slice::<Content>(b"\xef\xbb\xbf{}").is_err());
}

#[test]
fn rejects_unknown_fields_at_any_depth() {
    rejected(
        &with(|m| {
            m.insert("extra".into(), 1.into());
        }),
        "$.extra",
    );
    rejected(
        &with(|m| {
            m["inner"]
                .as_object_mut()
                .unwrap()
                .insert("extra".into(), true.into());
        }),
        "$.inner.extra",
    );
}

#[test]
fn rejects_keys_differing_only_in_case_or_spelling() {
    for key in ["groupId", "Group_id", "GROUP_ID", "group-id"] {
        let json = with(|m| {
            let value = m.remove("group_id").unwrap();
            m.insert(key.into(), value);
        });
        let error = parse(&json).unwrap_err();
        assert!(error.message().contains("unknown field"), "{error}");
    }
}

#[test]
fn accepts_map_keys_that_are_not_snake_case() {
    let content = parse(&with(|m| {
        m["channels"] = serde_json::json!({ "Security": [4624], "a b-C": [] });
    }))
    .unwrap();
    assert_eq!(content.channels.len(), 2);
}

#[test]
fn rejects_missing_required_fields() {
    let error = rejected(
        &with(|m| {
            m.remove("version");
        }),
        "$",
    );
    assert!(
        error.message().contains("missing field `version`"),
        "{error}"
    );
    rejected(
        &with(|m| {
            m["inner"].as_object_mut().unwrap().remove("sources");
        }),
        "$.inner",
    );
}

#[test]
fn rejects_duplicate_keys_at_any_depth() {
    let base = valid().to_string();
    let top = base.replacen("{", r#"{"version":3,"#, 1);
    rejected(&top, "$.version");
    let nested = base.replacen(r#""inner":{"#, r#""inner":{"sources":[],"#, 1);
    rejected(&nested, "$.inner.sources");
    let map = base.replacen(
        r#""channels":{"#,
        r#""channels":{"Microsoft-Windows-Sysmon/Operational":[],"#,
        1,
    );
    rejected(
        &map,
        r#"$.channels["Microsoft-Windows-Sysmon/Operational"]"#,
    );
    // An escaped key is the same key.
    let escaped = base.replacen("{", r#"{"version":3,"#, 1);
    rejected(&escaped, "$.version");
    // Even inside a value no field reads.
    let ignored = base.replacen(r#""channels":{"#, r#""channels":{"x":[{"a":1,"a":2}],"#, 1);
    rejected(&ignored, "$.channels.x[0].a");
}

#[test]
fn takes_integers_from_zero_to_two_to_the_53_minus_one() {
    let max = parse(&with(|m| {
        m["version"] = 9_007_199_254_740_991_u64.into();
    }))
    .unwrap();
    assert_eq!(max.version, 9_007_199_254_740_991);
    assert_eq!(
        parse(&with(|m| m["version"] = 0.into())).unwrap().version,
        0
    );

    for number in [
        "9007199254740992",
        "18446744073709551616",
        "1.0",
        "1e3",
        "1E3",
        "-1",
        "-0",
        "0.5",
    ] {
        let json =
            valid()
                .to_string()
                .replacen(r#""version":3"#, &format!(r#""version":{number}"#), 1);
        let error = rejected(&json, "$.version");
        assert!(error.message().contains("integers"), "{error}");
        // At any depth, in a map field's values too.
        let json = valid()
            .to_string()
            .replacen("[1,3]", &format!("[1,{number}]"), 1);
        rejected(
            &json,
            r#"$.channels["Microsoft-Windows-Sysmon/Operational"][1]"#,
        );
    }
}

#[test]
fn rejects_explicit_null_for_an_optional_field() {
    let error = rejected(
        &with(|m| {
            m.insert("note".into(), serde_json::Value::Null);
        }),
        "$.note",
    );
    assert!(error.message().contains("explicit null"), "{error}");
    let note = parse(&with(|m| {
        m.insert("note".into(), "hi".into());
    }))
    .unwrap()
    .note;
    assert_eq!(note.as_deref(), Some("hi"));
}

#[test]
fn nullable_tells_null_value_and_absence_apart() {
    let absent = parse(&valid().to_string()).unwrap();
    assert_eq!(absent.expires_at, Nullable::Absent);
    let null = parse(&with(|m| {
        m.insert("expires_at".into(), serde_json::Value::Null);
    }))
    .unwrap();
    assert_eq!(null.expires_at, Nullable::Null);
    let value = parse(&with(|m| {
        m.insert("expires_at".into(), "2026-01-02T03:04:05Z".into());
    }))
    .unwrap();
    assert_eq!(
        value.expires_at,
        Nullable::Value(UtcTimestamp::parse("2026-01-02T03:04:05Z").unwrap())
    );
}

#[test]
fn a_nullable_field_without_default_is_required() {
    #[derive(Debug, Deserialize)]
    struct Required {
        value: Nullable<u64>,
    }
    assert!(from_slice::<Required>(b"{}").is_err());
    assert_eq!(
        from_slice::<Required>(br#"{"value":null}"#).unwrap().value,
        Nullable::Null
    );
    assert_eq!(
        from_slice::<Required>(br#"{"value":1}"#).unwrap().value,
        Nullable::Value(1)
    );
    // Null inside the value is not let through.
    #[derive(Debug, Deserialize)]
    struct Nested {
        value: Nullable<Option<u64>>,
    }
    assert_eq!(
        from_slice::<Nested>(br#"{"value":null}"#).unwrap().value,
        Nullable::Null
    );
    #[derive(Debug, Deserialize)]
    struct InList {
        value: Nullable<Vec<Option<u64>>>,
    }
    let error = from_slice::<InList>(br#"{"value":[null]}"#).unwrap_err();
    assert_eq!(error.path(), "$.value[0]");
    assert_eq!(
        from_slice::<InList>(br#"{"value":[1]}"#).unwrap().value,
        Nullable::Value(vec![Some(1)])
    );
}

#[test]
fn rejects_a_struct_written_as_an_array() {
    let json = with(|m| {
        m["inner"] = serde_json::json!([SHA, []]);
    });
    rejected(&json, "$.inner");
}

#[test]
fn rejects_schema_field_names_that_are_not_snake_case() {
    #[derive(Debug, Deserialize)]
    struct Renamed {
        #[serde(rename = "groupId")]
        _group_id: u64,
    }
    let error = from_slice::<Renamed>(br#"{"groupId":1}"#).unwrap_err();
    assert!(error.message().contains("snake_case"), "{error}");
}

#[test]
fn reads_nested_paths_in_errors() {
    let json = with(|m| {
        m["inner"]["sources"] = serde_json::json!(["a", 1]);
    });
    let error = rejected(&json, "$.inner.sources[1]");
    assert!(error.to_string().contains("$.inner.sources[1]"));
}

#[test]
fn reads_utc_timestamps_ending_in_z() {
    for (text, nanos) in [
        ("2026-01-02T03:04:05Z", 0),
        ("2026-01-02T03:04:05.1Z", 100_000_000),
        ("2026-01-02T03:04:05.123456789Z", 123_456_789),
    ] {
        let parsed = UtcTimestamp::parse(text).unwrap().get();
        assert_eq!(parsed.subsec_nanosecond(), nanos, "{text}");
        assert_eq!(parsed.as_second(), 1_767_323_045, "{text}");
    }
    for text in [
        "2026-01-02T03:04:05+00:00",
        "2026-01-02T03:04:05-00:00",
        "2026-01-02T12:04:05+09:00",
        "2026-01-02t03:04:05Z",
        "2026-01-02T03:04:05z",
        "2026-01-02 03:04:05Z",
        "2026-01-02T03:04:05.Z",
        "2026-01-02T03:04:05.1234567890Z",
        "2026-01-02T03:04Z",
        "2026-13-02T03:04:05Z",
        "2026-02-30T03:04:05Z",
        "2026-01-02T24:04:05Z",
        "+2026-01-02T03:04:05Z",
        "2026-01-02T03:04:05ZZ",
        "",
    ] {
        assert_eq!(UtcTimestamp::parse(text), None, "{text}");
    }
    #[derive(Debug, Deserialize)]
    struct At {
        at: UtcTimestamp,
    }
    assert_eq!(
        from_slice::<At>(br#"{"at":"2026-01-02T03:04:05Z"}"#)
            .unwrap()
            .at
            .get()
            .as_second(),
        1_767_323_045
    );
    let error = from_slice::<At>(br#"{"at":"2026-01-02T03:04:05+00:00"}"#).unwrap_err();
    assert_eq!(error.path(), "$.at");
    assert_eq!(
        serde_json::to_string(&UtcTimestamp::parse("2026-01-02T03:04:05.5Z").unwrap()).unwrap(),
        r#""2026-01-02T03:04:05.5Z""#
    );
}

#[test]
fn reads_lowercase_hyphenated_uuids_only() {
    assert!(LowerUuid::parse(GROUP).is_some());
    for text in [
        GROUP.to_uppercase(),
        format!("{{{GROUP}}}"),
        GROUP.replace('-', ""),
        format!("urn:uuid:{GROUP}"),
        GROUP.replacen('f', "g", 1),
        GROUP[1..].to_owned(),
    ] {
        assert_eq!(LowerUuid::parse(&text), None, "{text}");
    }
    assert_eq!(
        serde_json::to_string(&LowerUuid::parse(GROUP).unwrap()).unwrap(),
        format!("\"{GROUP}\"")
    );
}

#[test]
fn reads_base64url_bytes() {
    assert_eq!(Base64UrlBytes::parse("YWI").unwrap().as_bytes(), b"ab");
    assert_eq!(Base64UrlBytes::parse("YWI="), None);
    assert_eq!(Base64UrlBytes::parse("YWJ"), None);
    assert!(Base64UrlArray::<32>::parse(SHA).is_some());
    assert_eq!(Base64UrlArray::<31>::parse(SHA), None);
    assert_eq!(Base64UrlArray::<32>::parse(&format!("{SHA}=")), None);
    let short = with(|m| m["inner"]["sha256"] = "YWI".into());
    rejected(&short, "$.inner.sha256");
}
