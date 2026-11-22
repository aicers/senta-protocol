//! The CBOR contract of the result enums in `senta_protocol::results`.
//!
//! Every decoding check runs twice: on the enum decoded on its own, and on
//! the enum decoded as a field of a struct.

use ciborium::Value;
use senta_protocol::results::{CommandResultKind, DocumentResult, InstallConfigFailure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// A struct carrying all three enums, as a message would.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Holder {
    doc: DocumentResult,
    command: CommandResultKind,
    install: InstallConfigFailure,
}

/// One of the enums, and where it sits in [`Holder`].
trait Field: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug + Clone {
    const NAME: &'static str;
    fn get(holder: Holder) -> Self;
}

impl Field for DocumentResult {
    const NAME: &'static str = "doc";
    fn get(holder: Holder) -> Self {
        holder.doc
    }
}

impl Field for CommandResultKind {
    const NAME: &'static str = "command";
    fn get(holder: Holder) -> Self {
        holder.command
    }
}

impl Field for InstallConfigFailure {
    const NAME: &'static str = "install";
    fn get(holder: Holder) -> Self {
        holder.install
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn int(n: u64) -> Value {
    Value::from(n)
}

fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(entries)
}

fn entry(tag: &str, content: Value) -> Value {
    map(vec![(text(tag), content)])
}

fn to_bytes<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    bytes
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ciborium::de::Error<std::io::Error>> {
    ciborium::from_reader(bytes)
}

/// Returns the CBOR data model value that `value` encodes to.
fn shape<T: Serialize>(value: &T) -> Value {
    decode(&to_bytes(value)).unwrap()
}

/// Compares two values, ignoring the order of entries within maps.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Map(a), Value::Map(b)) => {
            a.len() == b.len()
                && a.iter().all(|(key, value)| {
                    let mut found = b.iter().filter(|(other, _)| same(key, other));
                    matches!(
                        (found.next(), found.next()),
                        (Some((_, other)), None) if same(value, other)
                    )
                })
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same(a, b))
        }
        _ => a == b,
    }
}

/// A [`Holder`] as a CBOR map with `value` in `T`'s field and valid values
/// in the others.
fn in_holder<T: Field>(value: Value) -> Value {
    let mut entries = vec![
        (text("doc"), text("applied")),
        (text("command"), text("done")),
        (text("install"), text("keyset_invalid")),
    ];
    for (key, slot) in &mut entries {
        if key == &text(T::NAME) {
            *slot = value.clone();
        }
    }
    map(entries)
}

#[track_caller]
fn assert_decodes<T: Field>(input: &Value, expected: &T) {
    let decoded: T = decode(&to_bytes(input)).unwrap_or_else(|e| panic!("{input:?}: {e}"));
    assert_eq!(&decoded, expected, "standalone: {input:?}");
    let holder: Holder = decode(&to_bytes(&in_holder::<T>(input.clone())))
        .unwrap_or_else(|e| panic!("in a struct, {input:?}: {e}"));
    assert_eq!(&T::get(holder), expected, "in a struct: {input:?}");
}

#[track_caller]
fn assert_rejects<T: Field>(input: &Value) {
    let standalone = decode::<T>(&to_bytes(input));
    assert!(standalone.is_err(), "standalone {input:?}: {standalone:?}");
    let in_struct = decode::<Holder>(&to_bytes(&in_holder::<T>(input.clone())));
    assert!(in_struct.is_err(), "in a struct {input:?}: {in_struct:?}");
}

/// Checks the encoding of `value` against `expected`, and that it decodes
/// back to itself, alone and in a struct.
#[track_caller]
fn assert_contract<T: Field>(value: &T, expected: &Value) {
    let actual = shape(value);
    assert!(
        same(&actual, expected),
        "{value:?}: {actual:?} != {expected:?}"
    );
    assert_decodes(&actual, value);
    let decoded: T = decode(&to_bytes(value)).unwrap();
    assert_eq!(&decoded, value);
}

/// Every non-`Other` `DocumentResult` and the value it encodes to.
fn documents() -> Vec<(DocumentResult, Value)> {
    vec![
        (DocumentResult::Applied, text("applied")),
        (DocumentResult::Duplicate, text("duplicate")),
        (DocumentResult::Stale, text("stale")),
        (DocumentResult::Conflict, text("conflict")),
        (DocumentResult::EpochMismatch, text("epoch_mismatch")),
        (DocumentResult::WrongTarget, text("wrong_target")),
        (DocumentResult::BadSignature, text("bad_signature")),
        (DocumentResult::UnknownKid, text("unknown_kid")),
        (DocumentResult::RevokedKid, text("revoked_kid")),
        (DocumentResult::WrongKeyClass, text("wrong_key_class")),
        (DocumentResult::SchemaError, text("schema_error")),
        (DocumentResult::Expired, text("expired")),
        (DocumentResult::NotYetValid, text("not_yet_valid")),
        (
            DocumentResult::KeysetGap {
                have_epoch: 3,
                have_version: u64::MAX,
            },
            entry(
                "keyset_gap",
                map(vec![
                    (text("have_epoch"), int(3)),
                    (text("have_version"), int(u64::MAX)),
                ]),
            ),
        ),
        (
            DocumentResult::RecoveryKeyGap { have: 0 },
            entry("recovery_key_gap", map(vec![(text("have"), int(0))])),
        ),
        (
            DocumentResult::ApplyFailed {
                reason: "disk full".to_owned(),
            },
            entry(
                "apply_failed",
                map(vec![(text("reason"), text("disk full"))]),
            ),
        ),
    ]
}

/// Every non-`Other` `CommandResultKind` and the value it encodes to,
/// `Rejected` once for every non-`Other` `DocumentResult`.
fn commands() -> Vec<(CommandResultKind, Value)> {
    let mut commands = vec![
        (CommandResultKind::Done, text("done")),
        (CommandResultKind::AlreadyDone, text("already_done")),
        (
            CommandResultKind::Failed {
                reason: "no space".to_owned(),
            },
            entry("failed", map(vec![(text("reason"), text("no space"))])),
        ),
    ];
    for (doc, doc_shape) in documents() {
        commands.push((
            CommandResultKind::Rejected(doc),
            entry("rejected", doc_shape),
        ));
    }
    commands
}

/// Every non-`Other` `InstallConfigFailure` and the value it encodes to.
fn installs() -> Vec<(InstallConfigFailure, Value)> {
    vec![
        (
            InstallConfigFailure::DeploymentCertInvalid,
            text("deployment_cert_invalid"),
        ),
        (
            InstallConfigFailure::UntrustedVendorKey,
            text("untrusted_vendor_key"),
        ),
        (
            InstallConfigFailure::InstallConfigInvalid,
            text("install_config_invalid"),
        ),
        (
            InstallConfigFailure::InstallIdMismatch,
            text("install_id_mismatch"),
        ),
        (InstallConfigFailure::KeysetInvalid, text("keyset_invalid")),
        (
            InstallConfigFailure::AddressesInvalid,
            text("addresses_invalid"),
        ),
        (
            InstallConfigFailure::EnrollTokenInvalid,
            text("enroll_token_invalid"),
        ),
    ]
}

fn keyset_gap(fields: Vec<(Value, Value)>) -> Value {
    entry("keyset_gap", map(fields))
}

/// A map with the key `a` twice.
fn duplicated() -> Value {
    map(vec![(text("a"), int(1)), (text("a"), int(2))])
}

#[test]
fn document_results_encode_to_their_shapes_and_round_trip() {
    for (value, expected) in documents() {
        assert_contract(&value, &expected);
    }
}

#[test]
fn command_results_encode_to_their_shapes_and_round_trip() {
    for (value, expected) in commands() {
        assert_contract(&value, &expected);
    }
}

#[test]
fn install_config_failures_encode_to_their_shapes_and_round_trip() {
    for (value, expected) in installs() {
        assert_contract(&value, &expected);
    }
}

#[test]
fn representative_encodings_match_their_bytes() {
    // "applied"
    assert_eq!(to_bytes(&DocumentResult::Applied), b"\x67applied".to_vec());
    // {"recovery_key_gap": {"have": 5}}
    assert_eq!(
        to_bytes(&DocumentResult::RecoveryKeyGap { have: 5 }),
        b"\xa1\x70recovery_key_gap\xa1\x64have\x05".to_vec()
    );
    // {"rejected": "stale"}
    assert_eq!(
        to_bytes(&CommandResultKind::Rejected(DocumentResult::Stale)),
        b"\xa1\x68rejected\x65stale".to_vec()
    );
    // {"failed": {"reason": "x"}}
    assert_eq!(
        to_bytes(&CommandResultKind::Failed {
            reason: "x".to_owned()
        }),
        b"\xa1\x66failed\xa1\x66reason\x61x".to_vec()
    );
    // "keyset_invalid"
    assert_eq!(
        to_bytes(&InstallConfigFailure::KeysetInvalid),
        b"\x6ekeyset_invalid".to_vec()
    );
}

#[test]
fn field_maps_decode_in_any_order() {
    let reversed = keyset_gap(vec![
        (text("have_version"), int(7)),
        (text("have_epoch"), int(3)),
    ]);
    let expected = DocumentResult::KeysetGap {
        have_epoch: 3,
        have_version: 7,
    };
    assert_decodes(&reversed, &expected);
    assert_decodes(
        &entry("rejected", reversed),
        &CommandResultKind::Rejected(expected),
    );
}

#[test]
fn other_with_an_unregistered_tag_round_trips() {
    let doc = DocumentResult::Other("future_value".to_owned());
    assert_eq!(shape(&doc), text("future_value"));
    assert_decodes(&shape(&doc), &doc);

    let command = CommandResultKind::Other("future_value".to_owned());
    assert_eq!(shape(&command), text("future_value"));
    assert_decodes(&shape(&command), &command);

    let install = InstallConfigFailure::Other("future_value".to_owned());
    assert_eq!(shape(&install), text("future_value"));
    assert_decodes(&shape(&install), &install);

    // A tag registered in another enum is unknown to this one.
    let command = CommandResultKind::Other("applied".to_owned());
    assert_decodes(&shape(&command), &command);
}

#[test]
fn other_with_a_registered_unit_tag_reads_as_that_variant() {
    let encoded = shape(&CommandResultKind::Other("done".to_owned()));
    assert_decodes(&encoded, &CommandResultKind::Done);

    let encoded = shape(&DocumentResult::Other("applied".to_owned()));
    assert_decodes(&encoded, &DocumentResult::Applied);

    let encoded = shape(&InstallConfigFailure::Other("keyset_invalid".to_owned()));
    assert_decodes(&encoded, &InstallConfigFailure::KeysetInvalid);
}

#[test]
fn other_with_a_registered_content_tag_is_a_decoding_error() {
    assert_rejects::<CommandResultKind>(&shape(&CommandResultKind::Other("failed".to_owned())));
    assert_rejects::<CommandResultKind>(&shape(&CommandResultKind::Other("rejected".to_owned())));
    for tag in ["keyset_gap", "recovery_key_gap", "apply_failed"] {
        assert_rejects::<DocumentResult>(&shape(&DocumentResult::Other(tag.to_owned())));
    }
}

#[test]
fn nested_other_follows_the_same_rules() {
    let future = CommandResultKind::Rejected(DocumentResult::Other("future_value".to_owned()));
    assert_eq!(shape(&future), entry("rejected", text("future_value")));
    assert_decodes(&shape(&future), &future);

    let applied = CommandResultKind::Rejected(DocumentResult::Other("applied".to_owned()));
    assert_decodes(
        &shape(&applied),
        &CommandResultKind::Rejected(DocumentResult::Applied),
    );

    let gap = CommandResultKind::Rejected(DocumentResult::Other("keyset_gap".to_owned()));
    assert_rejects::<CommandResultKind>(&shape(&gap));
}

#[test]
fn unknown_tags_become_other() {
    let contents = [
        int(1),
        Value::Array(vec![int(1), text("x")]),
        map(vec![(text("a"), int(1))]),
        // Discarded content may have keys of any type.
        map(vec![(int(1), int(2)), (Value::Bool(true), Value::Null)]),
        Value::Null,
        Value::Bytes(vec![1, 2]),
        Value::Float(0.5),
        // A CBOR tag, and a bignum beyond 128 bits.
        Value::Tag(1, Box::new(int(0))),
        Value::Tag(2, Box::new(Value::Bytes(vec![1; 20]))),
    ];

    assert_decodes(
        &text("future_value"),
        &DocumentResult::Other("future_value".to_owned()),
    );
    assert_decodes(
        &text("future_value"),
        &CommandResultKind::Other("future_value".to_owned()),
    );
    assert_decodes(
        &text("future_value"),
        &InstallConfigFailure::Other("future_value".to_owned()),
    );
    for content in contents {
        let input = entry("future_value", content.clone());
        assert_decodes(&input, &DocumentResult::Other("future_value".to_owned()));
        assert_decodes(&input, &CommandResultKind::Other("future_value".to_owned()));
        assert_decodes(
            &input,
            &InstallConfigFailure::Other("future_value".to_owned()),
        );
        assert_decodes(
            &entry("rejected", input),
            &CommandResultKind::Rejected(DocumentResult::Other("future_value".to_owned())),
        );
    }
    assert_decodes(
        &entry("rejected", text("future_value")),
        &CommandResultKind::Rejected(DocumentResult::Other("future_value".to_owned())),
    );
}

#[test]
fn long_unknown_tags_become_other() {
    // Longer than ciborium's scratch buffer.
    let tag = "x".repeat(10_000);
    assert_decodes(&text(&tag), &DocumentResult::Other(tag.clone()));
    assert_decodes(&entry(&tag, int(1)), &DocumentResult::Other(tag.clone()));
}

#[test]
fn unknown_fields_are_ignored() {
    let extra = || {
        vec![
            (text("added_later"), int(9)),
            (text("nested"), map(vec![(int(1), Value::Array(vec![]))])),
        ]
    };

    let mut fields = vec![(text("have_epoch"), int(3)), (text("have_version"), int(7))];
    fields.extend(extra());
    assert_decodes(
        &keyset_gap(fields),
        &DocumentResult::KeysetGap {
            have_epoch: 3,
            have_version: 7,
        },
    );

    let mut fields = extra();
    fields.push((text("have"), int(2)));
    assert_decodes(
        &entry("recovery_key_gap", map(fields)),
        &DocumentResult::RecoveryKeyGap { have: 2 },
    );

    let mut fields = vec![(text("reason"), text("why"))];
    fields.extend(extra());
    assert_decodes(
        &entry("apply_failed", map(fields.clone())),
        &DocumentResult::ApplyFailed {
            reason: "why".to_owned(),
        },
    );
    assert_decodes(
        &entry("failed", map(fields)),
        &CommandResultKind::Failed {
            reason: "why".to_owned(),
        },
    );
}

#[test]
fn unit_tags_in_a_map_decode_to_their_variant() {
    for (value, tag) in documents().into_iter().take(13) {
        let Value::Text(tag) = tag else {
            unreachable!()
        };
        assert_decodes(
            &entry(&tag, map(vec![(text("added_later"), int(1))])),
            &value,
        );
        assert_decodes(&entry(&tag, Value::Null), &value);
    }
    assert_decodes(&entry("done", int(1)), &CommandResultKind::Done);
    assert_decodes(
        &entry("already_done", Value::Array(vec![])),
        &CommandResultKind::AlreadyDone,
    );
    for (value, tag) in installs() {
        let Value::Text(tag) = tag else {
            unreachable!()
        };
        assert_decodes(&entry(&tag, map(vec![])), &value);
    }
}

#[test]
fn malformed_field_maps_are_errors() {
    let bignum = |bytes: Vec<u8>| Value::Tag(2, Box::new(Value::Bytes(bytes)));
    let negative = Value::Integer((-1_i64).into());
    let below_range = Value::Integer((-(1_i128 << 64)).try_into().unwrap());
    let above_range = bignum(vec![1, 0, 0, 0, 0, 0, 0, 0, 0]);

    let docs = [
        // Missing fields.
        keyset_gap(vec![(text("have_epoch"), int(3))]),
        keyset_gap(vec![(text("have_version"), int(3))]),
        entry("recovery_key_gap", map(vec![])),
        entry("apply_failed", map(vec![(text("other"), text("x"))])),
        // Mistyped fields.
        keyset_gap(vec![
            (text("have_epoch"), negative.clone()),
            (text("have_version"), int(1)),
        ]),
        keyset_gap(vec![
            (text("have_epoch"), int(1)),
            (text("have_version"), below_range),
        ]),
        keyset_gap(vec![
            (text("have_epoch"), above_range.clone()),
            (text("have_version"), int(1)),
        ]),
        entry("recovery_key_gap", map(vec![(text("have"), negative)])),
        entry("recovery_key_gap", map(vec![(text("have"), above_range)])),
        entry(
            "recovery_key_gap",
            map(vec![(text("have"), Value::Float(1.0))]),
        ),
        entry("recovery_key_gap", map(vec![(text("have"), text("1"))])),
        entry("apply_failed", map(vec![(text("reason"), int(1))])),
        entry(
            "apply_failed",
            map(vec![(text("reason"), Value::Bytes(b"x".to_vec()))]),
        ),
        entry("apply_failed", map(vec![(text("reason"), Value::Null)])),
        // Integer keys are not read as field positions.
        keyset_gap(vec![(int(0), int(1)), (int(1), int(2))]),
        keyset_gap(vec![
            (text("have_epoch"), int(1)),
            (text("have_version"), int(2)),
            (int(2), int(3)),
        ]),
        // Content that is not a map.
        entry("keyset_gap", int(1)),
        entry("keyset_gap", text("have_epoch")),
        entry("keyset_gap", Value::Array(vec![int(1), int(2)])),
        entry("apply_failed", text("why")),
    ];
    for input in &docs {
        assert_rejects::<DocumentResult>(input);
        assert_rejects::<CommandResultKind>(&entry("rejected", input.clone()));
    }

    for input in [
        entry("failed", map(vec![])),
        entry("failed", map(vec![(text("reason"), int(1))])),
        entry("failed", text("why")),
        entry("failed", map(vec![(int(0), text("why"))])),
    ] {
        assert_rejects::<CommandResultKind>(&input);
    }
}

#[test]
fn malformed_values_are_errors() {
    // Content tags as text.
    for tag in ["keyset_gap", "recovery_key_gap", "apply_failed"] {
        assert_rejects::<DocumentResult>(&text(tag));
    }
    assert_rejects::<CommandResultKind>(&text("failed"));
    assert_rejects::<CommandResultKind>(&text("rejected"));

    let malformed = [
        // No entry, two entries.
        map(vec![]),
        map(vec![
            (text("applied"), Value::Null),
            (text("stale"), Value::Null),
        ]),
        map(vec![
            (text("future"), int(1)),
            (text("other_future"), int(2)),
        ]),
        // A key that is not text.
        map(vec![(int(1), text("applied"))]),
        map(vec![(Value::Bytes(b"applied".to_vec()), Value::Null)]),
        // Neither text nor a map.
        int(1),
        Value::Integer((-1_i64).into()),
        Value::Array(vec![text("applied")]),
        Value::Bytes(b"applied".to_vec()),
        Value::Bool(true),
        Value::Null,
        Value::Float(1.5),
    ];
    for input in &malformed {
        assert_rejects::<DocumentResult>(input);
        assert_rejects::<CommandResultKind>(input);
        assert_rejects::<InstallConfigFailure>(input);
        assert_rejects::<CommandResultKind>(&entry("rejected", input.clone()));
    }
}

#[test]
fn duplicate_keys_are_errors() {
    // Known fields repeated.
    let known = keyset_gap(vec![
        (text("have_epoch"), int(1)),
        (text("have_version"), int(2)),
        (text("have_epoch"), int(1)),
    ]);
    assert_rejects::<DocumentResult>(&known);
    assert_rejects::<DocumentResult>(&entry(
        "apply_failed",
        map(vec![
            (text("reason"), text("a")),
            (text("reason"), text("a")),
        ]),
    ));
    assert_rejects::<CommandResultKind>(&entry(
        "failed",
        map(vec![
            (text("reason"), text("a")),
            (text("reason"), text("b")),
        ]),
    ));

    // Unknown fields repeated.
    let unknown = keyset_gap(vec![
        (text("have_epoch"), int(1)),
        (text("have_version"), int(2)),
        (text("added_later"), int(1)),
        (text("added_later"), int(2)),
    ]);
    assert_rejects::<DocumentResult>(&unknown);
    assert_rejects::<CommandResultKind>(&entry(
        "failed",
        map(vec![
            (text("reason"), text("a")),
            (text("added_later"), int(1)),
            (text("added_later"), int(1)),
        ]),
    ));

    // A field map nested in `rejected`.
    assert_rejects::<CommandResultKind>(&entry("rejected", known));
    assert_rejects::<CommandResultKind>(&entry("rejected", unknown));

    // Inside the discarded content of an unknown tag, at any depth.
    let discarded = [
        duplicated(),
        Value::Array(vec![int(1), duplicated()]),
        map(vec![(
            text("deep"),
            map(vec![(text("deeper"), duplicated())]),
        )]),
        map(vec![(int(1), int(1)), (int(1), int(2))]),
        // Inside a CBOR tag.
        Value::Tag(100, Box::new(duplicated())),
        // Inside a map used as a key.
        map(vec![(duplicated(), int(1))]),
    ];
    for content in &discarded {
        let input = entry("future_value", content.clone());
        assert_rejects::<DocumentResult>(&input);
        assert_rejects::<CommandResultKind>(&input);
        assert_rejects::<InstallConfigFailure>(&input);
        assert_rejects::<CommandResultKind>(&entry("rejected", input));
        // Inside the discarded content of a known unit tag.
        assert_rejects::<DocumentResult>(&entry("applied", content.clone()));
        assert_rejects::<CommandResultKind>(&entry("done", content.clone()));
        assert_rejects::<InstallConfigFailure>(&entry("keyset_invalid", content.clone()));
    }

    // Inside the value of an ignored unknown field.
    for content in &discarded {
        assert_rejects::<DocumentResult>(&keyset_gap(vec![
            (text("have_epoch"), int(1)),
            (text("have_version"), int(2)),
            (text("added_later"), content.clone()),
        ]));
        assert_rejects::<CommandResultKind>(&entry(
            "failed",
            map(vec![
                (text("reason"), text("a")),
                (text("added_later"), content.clone()),
            ]),
        ));
        assert_rejects::<CommandResultKind>(&entry(
            "rejected",
            entry(
                "recovery_key_gap",
                map(vec![
                    (text("have"), int(1)),
                    (text("added_later"), content.clone()),
                ]),
            ),
        ));
    }
}

#[test]
fn keys_in_discarded_maps_compare_as_cbor_values() {
    let distinct = [
        // An integer is not a float, nor text a byte string.
        (int(1), Value::Float(1.0)),
        (text("a"), Value::Bytes(b"a".to_vec())),
        (int(1), Value::Integer((-2_i64).into())),
        (Value::Bool(true), Value::Bool(false)),
        (Value::Float(1.0), Value::Float(-1.0)),
        // Arrays and maps compare element by element, in order.
        (
            Value::Array(vec![int(1), int(2)]),
            Value::Array(vec![int(2), int(1)]),
        ),
        (
            map(vec![(text("a"), int(1)), (text("b"), int(2))]),
            map(vec![(text("b"), int(2)), (text("a"), int(1))]),
        ),
        // Tags with different numbers.
        (
            Value::Tag(100, Box::new(int(1))),
            Value::Tag(101, Box::new(int(1))),
        ),
    ];
    for (a, b) in distinct {
        let content = map(vec![(a, int(1)), (b, int(2))]);
        assert_decodes(
            &entry("future_value", content),
            &DocumentResult::Other("future_value".to_owned()),
        );
    }

    let equal = [
        Value::Float(1.5),
        Value::Null,
        Value::Bytes(b"a".to_vec()),
        Value::Integer((-5_i64).into()),
        Value::Array(vec![int(1), text("x")]),
        map(vec![(text("a"), int(1))]),
        Value::Tag(100, Box::new(int(1))),
    ];
    for key in equal {
        let content = map(vec![(key.clone(), int(1)), (key, int(2))]);
        assert_rejects::<DocumentResult>(&entry("future_value", content));
    }

    // An integer equals itself however it is encoded: as a plain integer
    // or as a bignum of any length, leading zeros included. Seventeen
    // bytes is past what ciborium turns into an integer by itself.
    let same_integer = [
        (int(1), bignum(1, &[1])),
        (int(1), bignum(1, &padded(17, &[1]))),
        (bignum(1, &[1]), bignum(1, &padded(17, &[1]))),
        (int(u64::MAX), bignum(1, &[0xff; 8])),
        (
            Value::Integer((-1_i64).into()),
            bignum(-1, &padded(17, &[])),
        ),
        (
            Value::Integer((-256_i64).into()),
            bignum(-1, &padded(20, &[0xff])),
        ),
        (
            bignum(-1, &[0xff; 16]),
            bignum(-1, &padded(17, &[0xff; 16])),
        ),
        // Past `u128`, with and without leading zeros.
        (bignum(1, &[1; 17]), bignum(1, &padded(20, &[1; 17]))),
        (bignum(-1, &[1; 17]), bignum(-1, &padded(20, &[1; 17]))),
    ];
    for (a, b) in same_integer {
        let content = map(vec![(a, int(1)), (b, int(2))]);
        assert_rejects::<DocumentResult>(&entry("future_value", content.clone()));
        assert_rejects::<InstallConfigFailure>(&entry("future_value", content.clone()));
        for (input, _) in discarded_places(&content) {
            assert_rejects::<CommandResultKind>(&input);
        }
    }

    let different_integers = [
        (bignum(1, &[1]), bignum(-1, &[1])),
        (bignum(1, &[1; 17]), bignum(-1, &[1; 17])),
        (bignum(1, &[1; 17]), bignum(1, &[1; 18])),
        (bignum(1, &[1; 17]), bignum(1, &[2; 17])),
        (int(1), bignum(1, &[2])),
        // A bignum is an integer, not its bytes.
        (bignum(1, &[1]), Value::Bytes(vec![1])),
        (bignum(1, &[1; 17]), Value::Bytes(vec![1; 17])),
    ];
    for (a, b) in different_integers {
        let content = map(vec![(a, int(1)), (b, int(2))]);
        for (input, expected) in discarded_places(&content) {
            assert_decodes(&input, &expected);
        }
    }
}

/// A bignum: `sign` is 1 for tag 2 and -1 for tag 3.
fn bignum(sign: i8, magnitude: &[u8]) -> Value {
    let tag = if sign < 0 { 3 } else { 2 };
    Value::Tag(tag, Box::new(Value::Bytes(magnitude.to_vec())))
}

/// `digits` after enough leading zeros to make `len` bytes.
fn padded(len: usize, digits: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; len - digits.len()];
    bytes.extend_from_slice(digits);
    bytes
}

/// `content` in every place a `CommandResultKind` discards or ignores a
/// value — as an unknown tag's content, as that of a known unit tag, as
/// an unknown field's value, and the same inside `rejected` — each with
/// what it decodes to when `content` is accepted.
fn discarded_places(content: &Value) -> Vec<(Value, CommandResultKind)> {
    let future = || "future_value".to_owned();
    vec![
        (
            entry("future_value", content.clone()),
            CommandResultKind::Other(future()),
        ),
        (entry("done", content.clone()), CommandResultKind::Done),
        (
            entry(
                "failed",
                map(vec![
                    (text("reason"), text("a")),
                    (text("added_later"), content.clone()),
                ]),
            ),
            CommandResultKind::Failed {
                reason: "a".to_owned(),
            },
        ),
        (
            entry("rejected", entry("future_value", content.clone())),
            CommandResultKind::Rejected(DocumentResult::Other(future())),
        ),
        (
            entry("rejected", entry("applied", content.clone())),
            CommandResultKind::Rejected(DocumentResult::Applied),
        ),
        (
            entry(
                "rejected",
                keyset_gap(vec![
                    (text("have_epoch"), int(1)),
                    (text("have_version"), int(2)),
                    (text("added_later"), content.clone()),
                ]),
            ),
            CommandResultKind::Rejected(DocumentResult::KeysetGap {
                have_epoch: 1,
                have_version: 2,
            }),
        ),
    ]
}

#[test]
fn discarded_bignums_of_any_size_decode() {
    let bignums = [
        // -2^128, the smallest integer a 16-byte bignum holds.
        bignum(-1, &[0xff; 16]),
        // -2^127 - 1, just past `i128`.
        bignum(-1, &padded(16, &[0x80])),
        bignum(1, &[0xff; 16]),
        bignum(-1, &[0xff; 17]),
        bignum(1, &[0xff; 17]),
        bignum(-1, &padded(17, &[1])),
        bignum(1, &[]),
        bignum(-1, &[]),
    ];
    for value in bignums {
        let contents = [
            value.clone(),
            Value::Array(vec![value.clone()]),
            map(vec![(text("a"), value.clone())]),
            // As a key of a discarded map.
            map(vec![(value.clone(), int(1))]),
            Value::Tag(100, Box::new(value.clone())),
        ];
        for content in &contents {
            for (input, expected) in discarded_places(content) {
                assert_decodes(&input, &expected);
            }
            assert_decodes(
                &keyset_gap(vec![
                    (text("have_epoch"), int(1)),
                    (text("have_version"), int(2)),
                    (text("added_later"), content.clone()),
                ]),
                &DocumentResult::KeysetGap {
                    have_epoch: 1,
                    have_version: 2,
                },
            );
            assert_decodes(
                &entry("keyset_invalid", content.clone()),
                &InstallConfigFailure::KeysetInvalid,
            );
        }
    }
}

#[test]
fn large_discarded_maps_decode() {
    let content = map((0..100_000).map(|i| (int(i), int(i))).collect());
    assert_decodes(
        &entry("future_value", content),
        &DocumentResult::Other("future_value".to_owned()),
    );
}

#[test]
fn structs_carrying_the_enums_round_trip() {
    let docs = documents()
        .into_iter()
        .map(|(doc, _)| doc)
        .chain([DocumentResult::Other("future_value".to_owned())]);
    let mut cycled_commands = commands()
        .into_iter()
        .map(|(command, _)| command)
        .chain([
            CommandResultKind::Other("future_value".to_owned()),
            CommandResultKind::Rejected(DocumentResult::Other("future_value".to_owned())),
        ])
        .cycle();
    let mut cycled_installs = installs()
        .into_iter()
        .map(|(install, _)| install)
        .chain([InstallConfigFailure::Other("future_value".to_owned())])
        .cycle();
    for doc in docs {
        let holder = Holder {
            doc,
            command: cycled_commands.next().unwrap(),
            install: cycled_installs.next().unwrap(),
        };
        let decoded: Holder = decode(&to_bytes(&holder)).unwrap();
        assert_eq!(decoded, holder);
    }

    // Every command, `Rejected` holding each document, in a struct.
    for (command, _) in commands() {
        let holder = Holder {
            doc: DocumentResult::Applied,
            command,
            install: InstallConfigFailure::KeysetInvalid,
        };
        let decoded: Holder = decode(&to_bytes(&holder)).unwrap();
        assert_eq!(decoded, holder);
    }
}

/// Encodes a text string shorter than 24 bytes as raw CBOR.
fn raw_text(s: &str) -> Vec<u8> {
    let len = u8::try_from(s.len()).unwrap();
    assert!(len < 24, "{s} is too long for a one-byte header");
    let mut bytes = vec![0x60 | len];
    bytes.extend_from_slice(s.as_bytes());
    bytes
}

/// Encodes a map of fewer than 24 entries, each already raw CBOR.
fn raw_map(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let len = u8::try_from(entries.len()).unwrap();
    assert!(len < 24);
    let mut bytes = vec![0xa0 | len];
    for (key, value) in entries {
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(value);
    }
    bytes
}

/// Encodes `{tag: content}` with `content` already raw CBOR.
fn raw_entry(tag: &str, content: &[u8]) -> Vec<u8> {
    raw_map(&[(&raw_text(tag), content)])
}

/// [`in_holder`] for raw CBOR: `value` in `T`'s field of a [`Holder`].
fn raw_in_holder<T: Field>(value: &[u8]) -> Vec<u8> {
    let fields = [
        ("doc", raw_text("applied")),
        ("command", raw_text("done")),
        ("install", raw_text("keyset_invalid")),
    ];
    let names: Vec<Vec<u8>> = fields.iter().map(|(name, _)| raw_text(name)).collect();
    let entries: Vec<(&[u8], &[u8])> = fields
        .iter()
        .zip(&names)
        .map(|((name, default), key)| {
            let slot: &[u8] = if *name == T::NAME { value } else { default };
            (key.as_slice(), slot)
        })
        .collect();
    raw_map(&entries)
}

#[track_caller]
fn assert_raw_decodes<T: Field>(input: &[u8], expected: &T) {
    let decoded: T = decode(input).unwrap_or_else(|e| panic!("{input:02x?}: {e}"));
    assert_eq!(&decoded, expected, "standalone: {input:02x?}");
    let holder: Holder = decode(&raw_in_holder::<T>(input))
        .unwrap_or_else(|e| panic!("in a struct, {input:02x?}: {e}"));
    assert_eq!(&T::get(holder), expected, "in a struct: {input:02x?}");
}

#[track_caller]
fn assert_raw_rejects<T: Field>(input: &[u8]) {
    let standalone = decode::<T>(input);
    assert!(
        standalone.is_err(),
        "standalone {input:02x?}: {standalone:?}"
    );
    let in_struct = decode::<Holder>(&raw_in_holder::<T>(input));
    assert!(
        in_struct.is_err(),
        "in a struct {input:02x?}: {in_struct:?}"
    );
}

/// Hands each place [`discarded_places`] lists, for raw CBOR `content`,
/// and the `DocumentResult` and `InstallConfigFailure` places too, to the
/// check for its enum along with what it decodes to when accepted.
fn for_raw_discarded_places(
    content: &[u8],
    mut check_document: impl FnMut(&[u8], &DocumentResult),
    mut check_command: impl FnMut(&[u8], &CommandResultKind),
    mut check_install: impl FnMut(&[u8], &InstallConfigFailure),
) {
    let future = || "future_value".to_owned();
    let added_later = raw_text("added_later");
    let keyset_gap = raw_entry(
        "keyset_gap",
        &raw_map(&[
            (&raw_text("have_epoch"), &[0x01]),
            (&raw_text("have_version"), &[0x02]),
            (&added_later, content),
        ]),
    );
    let gap = DocumentResult::KeysetGap {
        have_epoch: 1,
        have_version: 2,
    };

    check_document(
        &raw_entry("future_value", content),
        &DocumentResult::Other(future()),
    );
    check_document(&raw_entry("applied", content), &DocumentResult::Applied);
    check_document(&keyset_gap, &gap);

    check_command(
        &raw_entry("future_value", content),
        &CommandResultKind::Other(future()),
    );
    check_command(&raw_entry("done", content), &CommandResultKind::Done);
    check_command(
        &raw_entry(
            "failed",
            &raw_map(&[
                (&raw_text("reason"), &raw_text("a")),
                (&added_later, content),
            ]),
        ),
        &CommandResultKind::Failed {
            reason: "a".to_owned(),
        },
    );
    check_command(
        &raw_entry("rejected", &raw_entry("future_value", content)),
        &CommandResultKind::Rejected(DocumentResult::Other(future())),
    );
    check_command(
        &raw_entry("rejected", &raw_entry("applied", content)),
        &CommandResultKind::Rejected(DocumentResult::Applied),
    );
    check_command(
        &raw_entry("rejected", &keyset_gap),
        &CommandResultKind::Rejected(gap),
    );

    check_install(
        &raw_entry("future_value", content),
        &InstallConfigFailure::Other(future()),
    );
    check_install(
        &raw_entry("keyset_invalid", content),
        &InstallConfigFailure::KeysetInvalid,
    );
}

/// A discarded map with `a` and `b`, raw CBOR, as its two keys.
fn raw_two_keys(a: &[u8], b: &[u8]) -> Vec<u8> {
    raw_map(&[(a, &[0x01]), (b, &[0x02])])
}

#[test]
fn float_keys_compare_by_value_whatever_their_width() {
    // RFC 8949 section 2 leaves the width a float is encoded at out of the
    // data model, so the bit pattern compared is that of the value.
    let half_1_5: &[u8] = &[0xf9, 0x3e, 0x00];
    let single_1_5: &[u8] = &[0xfa, 0x3f, 0xc0, 0x00, 0x00];
    let double_1_5: &[u8] = &[0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0];
    let half_nan: &[u8] = &[0xf9, 0x7e, 0x00];
    let double_nan: &[u8] = &[0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0];
    let equal = [
        (half_1_5, single_1_5),
        (half_1_5, double_1_5),
        (single_1_5, double_1_5),
        // The same quiet NaN, its significand zero-extended.
        (half_nan, double_nan),
    ];
    for (a, b) in equal {
        let content = raw_two_keys(a, b);
        for_raw_discarded_places(
            &content,
            |input, _| assert_raw_rejects::<DocumentResult>(input),
            |input, _| assert_raw_rejects::<CommandResultKind>(input),
            |input, _| assert_raw_rejects::<InstallConfigFailure>(input),
        );
    }

    let distinct: [(&[u8], &[u8]); 4] = [
        // 0.0 and -0.0 differ in their sign bit.
        (&[0xf9, 0x00, 0x00], &[0xf9, 0x80, 0x00]),
        (&[0xf9, 0x00, 0x00], &[0xfb, 0x80, 0, 0, 0, 0, 0, 0, 0]),
        // NaNs with different payloads.
        (half_nan, &[0xf9, 0x7e, 0x01]),
        // 1.5 and the next double after it.
        (double_1_5, &[0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 1]),
    ];
    for (a, b) in distinct {
        let content = raw_two_keys(a, b);
        for_raw_discarded_places(
            &content,
            assert_raw_decodes::<DocumentResult>,
            assert_raw_decodes::<CommandResultKind>,
            assert_raw_decodes::<InstallConfigFailure>,
        );
    }
}

#[test]
fn discarded_simple_values_decode_only_where_ciborium_reads_them() {
    let contents = |value: &[u8]| {
        vec![
            value.to_vec(),
            [&[0x81], value].concat(),
            raw_map(&[(&raw_text("a"), value)]),
            raw_map(&[(value, &[0x01])]),
        ]
    };

    // false, true, null and undefined are discarded like any other value.
    for value in [[0xf4], [0xf5], [0xf6], [0xf7]] {
        for content in contents(&value) {
            for_raw_discarded_places(
                &content,
                assert_raw_decodes::<DocumentResult>,
                assert_raw_decodes::<CommandResultKind>,
                assert_raw_decodes::<InstallConfigFailure>,
            );
        }
    }

    // Any other simple value fails, because ciborium's deserializer hands
    // none to serde on any path: it rejects the same bytes read as its own
    // `Value` or as `IgnoredAny` too. This pins that limit; if a ciborium
    // release lifts it, this test fails and the discarding should follow.
    let unassigned: [&[u8]; 4] = [&[0xe0], &[0xf0], &[0xf8, 0x20], &[0xf8, 0xff]];
    for value in unassigned {
        for content in contents(value) {
            let codec_rejects = |input: &[u8]| {
                assert!(decode::<Value>(input).is_err(), "{input:02x?}");
                assert!(
                    decode::<serde::de::IgnoredAny>(input).is_err(),
                    "{input:02x?}"
                );
            };
            for_raw_discarded_places(
                &content,
                |input, _| {
                    codec_rejects(input);
                    assert_raw_rejects::<DocumentResult>(input);
                },
                |input, _| {
                    codec_rejects(input);
                    assert_raw_rejects::<CommandResultKind>(input);
                },
                |input, _| {
                    codec_rejects(input);
                    assert_raw_rejects::<InstallConfigFailure>(input);
                },
            );
        }
    }
}
