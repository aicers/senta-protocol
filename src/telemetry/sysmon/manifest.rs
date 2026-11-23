//! Checks the field descriptor table against the Sysmon manifest committed
//! under `schemas/`: the entry of the base schema version, read as it is.

use std::collections::BTreeSet;

use super::BASE_SCHEMA_VERSION;
use super::kinds::{FieldDesc, KINDS};
use super::value::FieldType;
use crate::telemetry::kind::{self, KindFamily};

const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/schemas/sysmon/manifest.xml");

/// The Sysmon kinds with a body.
const SYSMON_KINDS: [u16; 19] = [
    1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 22, 23, 25, 26,
];
/// The events of the base schema that have no body.
const EVENTS_WITHOUT_BODY: [u16; 9] = [4, 16, 18, 19, 20, 21, 24, 100, 255];
/// The kinds whose process key is the source process.
const SOURCE_PROCESS_KINDS: [u16; 2] = [8, 10];

/// One `<data>` element of a manifest event.
struct ManifestField {
    name: String,
    in_type: String,
}

/// One `<event>` of the base schema's manifest entry.
struct ManifestEvent {
    value: u16,
    fields: Vec<ManifestField>,
}

/// Reads the events of the base schema's `<manifest>` entry.
fn base_events() -> Vec<ManifestEvent> {
    let text = std::fs::read_to_string(MANIFEST).expect("the manifest is readable");
    let doc = roxmltree::Document::parse(&text).expect("the manifest is XML");
    let mut entries = doc.root_element().children().filter(|node| {
        node.has_tag_name("manifest")
            && node.attribute("schemaversion") == Some(BASE_SCHEMA_VERSION)
    });
    let entry = entries.next().expect("the manifest has the base version");
    assert!(entries.next().is_none(), "the base version appears once");
    let events = entry
        .children()
        .find(|node| node.has_tag_name("events"))
        .expect("the base entry has events");
    events
        .children()
        .filter(|node| node.has_tag_name("event"))
        .map(|event| ManifestEvent {
            value: event
                .attribute("value")
                .expect("an event has a value")
                .parse()
                .expect("an event's value is a number"),
            fields: event
                .children()
                .filter(|node| node.has_tag_name("data"))
                .map(|data| ManifestField {
                    name: data
                        .attribute("name")
                        .expect("a field has a name")
                        .to_owned(),
                    in_type: data
                        .attribute("inType")
                        .expect("a field has an inType")
                        .to_owned(),
                })
                .collect(),
        })
        .collect()
}

/// Turns a schema name into snake_case, a run of capitals making one word
/// and a digit joining the word before it.
fn snake_case(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::with_capacity(name.len() + 4);
    for (i, &c) in chars.iter().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            let prev = chars.get(i - 1).copied();
            let next = chars.get(i + 1).copied();
            let after_word = prev.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit());
            let ends_run = prev.is_some_and(|p| p.is_ascii_uppercase())
                && next.is_some_and(|n| n.is_ascii_lowercase());
            if after_word || ends_run {
                out.push('_');
            }
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

/// The body type a manifest field takes, by the first rule that fits.
fn body_type(field: &ManifestField) -> Result<FieldType, String> {
    let name = field.name.as_str();
    Ok(if name == "Hashes" {
        FieldType::Hashes
    } else if name == "SourceIp" || name == "DestinationIp" {
        FieldType::Ip
    } else if name.ends_with("UtcTime") {
        FieldType::Time
    } else {
        match field.in_type.as_str() {
            "win:GUID" => FieldType::Guid,
            "win:Boolean" => FieldType::Bool,
            "win:UInt16" => FieldType::U16,
            "win:UInt32" => FieldType::U32,
            "win:UInt64" | "win:HexInt64" | "win:HexInt32" => FieldType::U64,
            "win:UnicodeString" | "win:AnsiString" => FieldType::Str,
            other => return Err(format!("{name}: {other} is not a type of the base version")),
        }
    })
}

/// Compares the table's kinds with the manifest's events: the same kinds,
/// and for each the manifest's fields less `UtcTime`, in order, with the
/// same schema names, keys and body types.
fn compare(events: &[ManifestEvent], table: &[(u16, &[FieldDesc])]) -> Result<(), String> {
    let table_kinds: BTreeSet<u16> = table.iter().map(|&(kind, _)| kind).collect();
    if table_kinds.len() != table.len() {
        return Err("the table lists a kind twice".to_owned());
    }
    let expected_kinds = BTreeSet::from(SYSMON_KINDS);
    if table_kinds != expected_kinds {
        return Err(format!(
            "the table has the kinds {table_kinds:?}, expected {expected_kinds:?}"
        ));
    }
    for &(kind, fields) in table {
        let event = events
            .iter()
            .find(|event| event.value == kind)
            .ok_or_else(|| format!("event {kind} is not in the manifest"))?;
        let expected = event
            .fields
            .iter()
            .filter(|field| field.name != "UtcTime")
            .map(|field| {
                body_type(field).map(|ty| (field.name.clone(), snake_case(&field.name), ty))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let actual: Vec<_> = fields
            .iter()
            .map(|desc| (desc.schema.to_owned(), desc.key.to_owned(), desc.ty))
            .collect();
        if actual != expected {
            return Err(format!(
                "event {kind}: the table has {actual:?}, the manifest gives {expected:?}"
            ));
        }
    }
    Ok(())
}

fn table() -> Vec<(u16, &'static [FieldDesc])> {
    KINDS.iter().map(|desc| (desc.kind, desc.fields)).collect()
}

#[test]
fn table_matches_the_manifest() {
    let events = base_events();
    compare(&events, &table()).unwrap();

    let event_values: BTreeSet<u16> = events.iter().map(|event| event.value).collect();
    let mut all = BTreeSet::from(SYSMON_KINDS);
    all.extend(EVENTS_WITHOUT_BODY);
    assert_eq!(event_values, all);

    // The kinds with a body are the registry's Sysmon kinds, each still at
    // schema version 1 under the base version.
    let registry: BTreeSet<u16> = (1..=255)
        .filter(|&number| {
            kind::family(number) == Some(KindFamily::Sysmon) && kind::info(number).is_some()
        })
        .collect();
    let table: BTreeSet<u16> = KINDS.iter().map(|desc| desc.kind).collect();
    assert_eq!(table, registry);
    assert_eq!(table, BTreeSet::from(SYSMON_KINDS));
    for number in table {
        let info = kind::info(number).expect("the kind is in the registry");
        assert_eq!(info.schema(), 1, "kind {number}");
    }
}

#[test]
fn comparison_catches_a_changed_order_or_type() {
    let events = base_events();
    let table = table();
    let (index, _) = table
        .iter()
        .enumerate()
        .find(|(_, (kind, _))| *kind == kind::SYSMON_PROCESS_ACCESS)
        .unwrap();

    let mut swapped = table[index].1.to_vec();
    swapped.swap(1, 2);
    let mut reordered = table.clone();
    reordered[index].1 = &swapped;
    assert!(compare(&events, &reordered).is_err());

    let mut retyped_fields = table[index].1.to_vec();
    let granted = retyped_fields
        .iter_mut()
        .find(|desc| desc.key == "granted_access")
        .unwrap();
    assert_eq!(granted.ty, FieldType::U64);
    granted.ty = FieldType::U32;
    let mut retyped = table.clone();
    retyped[index].1 = &retyped_fields;
    assert!(compare(&events, &retyped).is_err());

    let mut renamed_fields = table[index].1.to_vec();
    renamed_fields[1].key = "source_process_g_u_i_d";
    let mut renamed = table.clone();
    renamed[index].1 = &renamed_fields;
    assert!(compare(&events, &renamed).is_err());

    let mut missing = table.clone();
    missing.remove(index);
    assert!(compare(&events, &missing).is_err());
}

#[test]
fn process_key_fields_follow_the_rule() {
    for desc in KINDS {
        let expected = if SOURCE_PROCESS_KINDS.contains(&desc.kind) {
            Some("source_process_guid")
        } else {
            desc.fields
                .iter()
                .find(|field| field.key == "process_guid")
                .map(|field| field.key)
        };
        assert_eq!(desc.process_key, expected, "kind {}", desc.kind);
        if let Some(key) = desc.process_key {
            let field = desc.fields.iter().find(|field| field.key == key).unwrap();
            assert_eq!(field.ty, FieldType::Guid, "kind {}", desc.kind);
        }
    }
}

#[test]
fn snake_case_examples() {
    for (name, expected) in [
        ("ParentProcessGuid", "parent_process_guid"),
        ("SourceProcessGUID", "source_process_guid"),
        ("TargetProcessGUID", "target_process_guid"),
        ("SourceIsIpv6", "source_is_ipv6"),
        ("TargetFilename", "target_filename"),
        ("LogonId", "logon_id"),
        ("ID", "id"),
        ("Type", "type"),
    ] {
        assert_eq!(snake_case(name), expected);
    }
}
