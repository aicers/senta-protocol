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
    let escaped = base.replacen("{", r#"{"versio\u006e":3,"#, 1);
    rejected(&escaped, "$.version");
    let escaped_map = base.replacen(
        r#""channels":{"#,
        r#""channels":{"Microsoft-Windows-Sysmon\/Operational":[],"#,
        1,
    );
    rejected(
        &escaped_map,
        r#"$.channels["Microsoft-Windows-Sysmon/Operational"]"#,
    );
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

/// Numbers out of rule, at least one for each way serde_json can hand a
/// number over, with or without its `arbitrary_precision` feature.
const OUT_OF_RULE_NUMBERS: [&str; 12] = [
    "9007199254740992",
    "18446744073709551615",
    "18446744073709551616",
    "100000000000000000000000000000000000000",
    "1.0",
    "1e3",
    "1E3",
    "1e-3",
    "-1",
    "-0",
    "-18446744073709551617",
    "0.5",
];

/// Fields whose type would take a number past 2^53 − 1, a negative one or
/// one with a fraction, were the shape pass not to stop it first.
#[derive(Debug, Deserialize)]
struct Wide {
    small: u64,
    big: u128,
    signed: i128,
    real: f64,
    list: Vec<u128>,
    map: BTreeMap<String, f64>,
}

const WIDE: &str = r#"{"small":1,"big":2,"signed":3,"real":4,"list":[5],"map":{"a":6}}"#;

#[test]
fn holds_wide_number_fields_to_the_same_integers() {
    let wide = from_slice::<Wide>(WIDE.as_bytes()).unwrap();
    assert_eq!((wide.small, wide.big, wide.signed), (1, 2, 3));
    assert!((wide.real - 4.0).abs() < f64::EPSILON);
    assert_eq!(wide.list, [5]);
    assert_eq!(wide.map.len(), 1);
    let max = WIDE.replacen(":2,", ":9007199254740991,", 1);
    assert_eq!(
        from_slice::<Wide>(max.as_bytes()).unwrap().big,
        9_007_199_254_740_991
    );
    let zero = WIDE.replacen(":4,", ":0,", 1);
    assert!(from_slice::<Wide>(zero.as_bytes()).is_ok());

    for (old, path) in [
        ("1", "$.small"),
        ("2", "$.big"),
        ("3", "$.signed"),
        ("4", "$.real"),
        ("5", "$.list[0]"),
        ("6", "$.map.a"),
    ] {
        for number in OUT_OF_RULE_NUMBERS {
            let start = WIDE.find(old).unwrap();
            let json = format!("{}{number}{}", &WIDE[..start], &WIDE[start + 1..]);
            let error = from_slice::<Wide>(json.as_bytes()).expect_err(&json);
            // The very same error, position included, whichever way the
            // number was handed over.
            assert_eq!(
                error.to_string(),
                format!(
                    "numbers must be integers from 0 to 2^53 - 1, written without a sign, \
                     a fraction or an exponent at line 1 column {} (at {path})",
                    start + number.len()
                ),
                "{json}"
            );
        }
    }
}

#[test]
fn rejects_an_object_led_by_the_serde_json_number_key() {
    // How serde_json's `arbitrary_precision` feature hands over a number
    // that is not an `i64` or a `u64`; rejected as a number out of rule even
    // without the feature.
    for value in [r#""1""#, r#""1.0""#, "1", "{}"] {
        let json = valid().to_string().replacen(
            r#""version":3"#,
            &format!(r#""version":{{"$serde_json::private::Number":{value}}}"#),
            1,
        );
        let error = rejected(&json, "$.version");
        assert!(error.message().contains("integers"), "{error}");
    }
    let json =
        valid()
            .to_string()
            .replacen("[1,3]", r#"[1,{"$serde_json::private::Number":"1e3"}]"#, 1);
    rejected(
        &json,
        r#"$.channels["Microsoft-Windows-Sysmon/Operational"][1]"#,
    );
    // Anywhere but first, it is an ordinary key.
    let json = valid().to_string().replacen(
        r#""channels":{"#,
        r#""channels":{"a":[1],"$serde_json::private::Number":[2],"#,
        1,
    );
    let content = parse(&json).unwrap();
    assert_eq!(content.channels["$serde_json::private::Number"], [2]);
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

/// Times at second `60`: mid-minute, at the end of a month with no leap
/// second, and on the real leap second at the end of 2016, with and without
/// a fraction, and one past it.
const LEAP_SECONDS: [&str; 6] = [
    "2026-01-02T03:04:60Z",
    "2026-01-31T23:59:60Z",
    "2016-12-31T23:59:60Z",
    "2016-12-31T23:59:60.5Z",
    "2016-12-31T23:59:60.999999999Z",
    "2026-01-02T03:04:61Z",
];

#[test]
fn rejects_second_60_on_any_date() {
    for text in LEAP_SECONDS {
        assert_eq!(UtcTimestamp::parse(text), None, "{text}");
    }
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
    for (text, second, nanos) in [
        ("2026-01-02T03:04:59Z", 1_767_323_099, 0),
        ("2016-12-31T23:59:59Z", 1_483_228_799, 0),
        ("2016-12-31T23:59:59.999999999Z", 1_483_228_799, 999_999_999),
        ("2017-01-01T00:00:00Z", 1_483_228_800, 0),
    ] {
        let parsed = UtcTimestamp::parse(text).unwrap().get();
        assert_eq!(parsed.as_second(), second, "{text}");
        assert_eq!(parsed.subsec_nanosecond(), nanos, "{text}");
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
    for text in LEAP_SECONDS {
        let error = from_slice::<At>(format!(r#"{{"at":"{text}"}}"#).as_bytes()).unwrap_err();
        assert_eq!(error.path(), "$.at", "{text}");
    }
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

const UNSCHEMATIC: &str = "without a schema";

#[track_caller]
fn unschematic<T: serde::de::DeserializeOwned + std::fmt::Debug>(json: &str, path: &str) {
    let error = from_slice::<T>(json.as_bytes()).expect_err(json);
    assert_eq!(error.path(), path, "{json}: {error}");
    assert!(error.message().contains(UNSCHEMATIC), "{json}: {error}");
}

#[test]
fn rejects_an_internally_tagged_enum_whatever_its_content() {
    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum Tagged {
        Note { text: Option<String> },
    }
    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    struct Outer {
        item: Tagged,
    }

    // Serde would let the unknown field and the explicit `null` through.
    unschematic::<Outer>(r#"{"item":{"kind":"note","extra":1}}"#, "$.item");
    unschematic::<Outer>(r#"{"item":{"kind":"note","text":null}}"#, "$.item");
    unschematic::<Outer>(r#"{"item":{"kind":"note","text":"a"}}"#, "$.item");
    unschematic::<Tagged>(r#"{"kind":"note","text":"a"}"#, "$");
}

#[test]
fn rejects_an_untagged_enum_and_a_flattened_field() {
    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum Untagged {
        Note { text: String },
    }
    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    struct WithUntagged {
        item: Untagged,
    }
    unschematic::<WithUntagged>(r#"{"item":{"text":"a","extra":1}}"#, "$.item");
    unschematic::<WithUntagged>(r#"{"item":{"text":"a"}}"#, "$.item");

    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    struct Inner {
        text: Option<String>,
    }
    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    struct Flattened {
        id: u64,
        #[serde(flatten)]
        inner: Inner,
    }
    unschematic::<Flattened>(r#"{"id":1,"extra":1}"#, "$.extra");
    unschematic::<Flattened>(r#"{"id":1,"text":null}"#, "$.text");
    unschematic::<Flattened>(r#"{"id":1,"text":"a"}"#, "$.text");
}

#[test]
fn rejects_an_adjacently_tagged_enum_in_either_order() {
    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    #[serde(tag = "kind", content = "body", rename_all = "snake_case")]
    enum Adjacent {
        Note { text: Option<String> },
    }

    unschematic::<Adjacent>(r#"{"kind":"note","body":{"extra":1}}"#, "$.body");
    unschematic::<Adjacent>(r#"{"kind":"note","body":{"text":null}}"#, "$.body");
    unschematic::<Adjacent>(r#"{"kind":"note","body":{"text":"a"}}"#, "$.body");
    unschematic::<Adjacent>(r#"{"body":{"text":"a"},"kind":"note"}"#, "$.body");
}

#[test]
fn rejects_a_field_that_takes_any_json() {
    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    struct AnyValue {
        value: serde_json::Value,
    }
    unschematic::<AnyValue>(r#"{"value":{"a":null}}"#, "$.value");
    unschematic::<AnyValue>(r#"{"value":1}"#, "$.value");

    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    struct Ignored {
        value: serde::de::IgnoredAny,
    }
    unschematic::<Ignored>(r#"{"value":{"a":null}}"#, "$.value");
}

#[test]
fn holds_an_alias_to_the_field_name_rules() {
    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    struct Aliased {
        #[serde(alias = "old_name")]
        name: String,
    }
    assert!(from_slice::<Aliased>(br#"{"name":"a"}"#).is_ok());
    assert!(from_slice::<Aliased>(br#"{"old_name":"a"}"#).is_ok());
    rejected_as::<Aliased>(r#"{"Old_name":"a"}"#, "$.Old_name");
    rejected_as::<Aliased>(r#"{"name":"a","old_name":"b"}"#, "$");

    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    struct CamelAlias {
        #[serde(alias = "oldName")]
        name: String,
    }
    let error = from_slice::<CamelAlias>(br#"{"name":"a"}"#).unwrap_err();
    assert!(error.message().contains("not snake_case"), "{error}");
}

#[track_caller]
fn rejected_as<T: serde::de::DeserializeOwned + std::fmt::Debug>(json: &str, path: &str) {
    let error = from_slice::<T>(json.as_bytes()).expect_err(json);
    assert_eq!(error.path(), path, "{json}: {error}");
}

/// The forms the module documentation says pass although content types
/// must not use them. Kept in step with that documentation: should one of
/// these start to fail, the documentation is to say so.
#[test]
fn lets_through_what_the_documentation_says_it_does_not_catch() {
    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    struct Inner {
        text: Option<String>,
    }
    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    struct Flattened {
        #[serde(rename = "Id")]
        id: u64,
        #[serde(flatten)]
        inner: Inner,
    }
    // No key falls to the flattened field, and the declared name `Id` is
    // not held to snake_case.
    assert!(from_slice::<Flattened>(br#"{"Id":1}"#).is_ok());
    unschematic::<Flattened>(r#"{"Id":1,"text":"a"}"#, "$.text");

    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    struct Body {
        text: String,
    }
    #[allow(dead_code)] // Only deserialization is under test.
    #[derive(Debug, Deserialize)]
    #[serde(tag = "kind", content = "body", rename_all = "snake_case")]
    enum Adjacent {
        Unit,
        Scalar(u64),
        Wrapped(Body),
        Pair(u64, u64),
        Fields { text: String },
    }
    for json in [
        r#"{"kind":"unit"}"#,
        r#"{"kind":"scalar","body":1}"#,
        r#"{"kind":"wrapped","body":{"text":"a"}}"#,
        r#"{"kind":"pair","body":[1,2]}"#,
    ] {
        assert!(from_slice::<Adjacent>(json.as_bytes()).is_ok(), "{json}");
    }
    // What passes is still held to the rules.
    rejected_as::<Adjacent>(
        r#"{"kind":"wrapped","body":{"text":"a","extra":1}}"#,
        "$.body.extra",
    );
    rejected_as::<Adjacent>(r#"{"kind":"scalar","body":1.0}"#, "$.body");
    // And the rest fails.
    unschematic::<Adjacent>(r#"{"kind":"unit","body":null}"#, "$.body");
    unschematic::<Adjacent>(r#"{"body":1,"kind":"scalar"}"#, "$.body");
    unschematic::<Adjacent>(r#"{"kind":"fields","body":{"text":"a"}}"#, "$.body");
}
