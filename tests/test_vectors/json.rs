//! An ordered JSON tree, for the parts of a vector whose shape varies: the
//! result notation, and the JSON payloads signed into documents.
//!
//! Objects keep their members in the order written, both when built here
//! and when read back from a file, so neither output depends on the map
//! order of `serde_json`.

use std::fmt;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// A JSON value whose objects keep their member order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum J {
    Null,
    Bool(bool),
    Int(u64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
    /// JSON text written out as it is, for payloads that break the rules
    /// on purpose (a repeated key, a number above 2^53 − 1). Only signed
    /// payloads use it; it never appears in a vector file's own structure.
    Raw(String),
}

impl J {
    pub fn str(text: impl Into<String>) -> Self {
        Self::Str(text.into())
    }

    pub fn obj<K: Into<String>>(members: impl IntoIterator<Item = (K, J)>) -> Self {
        Self::Obj(
            members
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }

    /// The one-entry object `{tag: content}`.
    pub fn tagged(tag: &str, content: J) -> Self {
        Self::Obj(vec![(tag.to_owned(), content)])
    }

    pub fn arr(items: impl IntoIterator<Item = J>) -> Self {
        Self::Arr(items.into_iter().collect())
    }

    /// Returns the object with `key` removed.
    pub fn without(&self, key: &str) -> Self {
        match self {
            Self::Obj(members) => Self::Obj(
                members
                    .iter()
                    .filter(|(name, _)| name != key)
                    .cloned()
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    /// Returns the object with `key` set to `value`, in place if present
    /// and appended otherwise.
    pub fn with(&self, key: &str, value: J) -> Self {
        match self {
            Self::Obj(members) => {
                let mut members = members.clone();
                match members.iter_mut().find(|(name, _)| name == key) {
                    Some(member) => member.1 = value,
                    None => members.push((key.to_owned(), value)),
                }
                Self::Obj(members)
            }
            other => other.clone(),
        }
    }

    /// Returns the member `key` of an object.
    pub fn get(&self, key: &str) -> Option<&J> {
        match self {
            Self::Obj(members) => members
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// Writes the value as compact JSON text.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Self::Int(value) => out.push_str(&value.to_string()),
            Self::Str(text) => out.push_str(&json_string(text)),
            Self::Arr(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Self::Obj(members) => {
                out.push('{');
                for (index, (key, value)) in members.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&json_string(key));
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
            Self::Raw(text) => out.push_str(text),
        }
    }

    /// Converts to a `serde_json` value, for comparisons in which member
    /// order does not matter.
    pub fn to_value(&self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Bool(value) => Value::Bool(*value),
            Self::Int(value) => Value::from(*value),
            Self::Str(text) => Value::String(text.clone()),
            Self::Arr(items) => Value::Array(items.iter().map(Self::to_value).collect()),
            Self::Obj(members) => Value::Object(
                members
                    .iter()
                    .map(|(key, value)| (key.clone(), value.to_value()))
                    .collect(),
            ),
            Self::Raw(text) => serde_json::from_str(text).unwrap_or(Value::Null),
        }
    }

    /// Converts from a `serde_json` value. Object members come in the map
    /// order of `serde_json`; only comparisons use the result.
    pub fn from_value(value: &Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(value) => Self::Bool(*value),
            Value::Number(number) => number
                .as_u64()
                .map_or_else(|| Self::Raw(number.to_string()), Self::Int),
            Value::String(text) => Self::Str(text.clone()),
            Value::Array(items) => Self::Arr(items.iter().map(Self::from_value).collect()),
            Value::Object(members) => Self::Obj(
                members
                    .iter()
                    .map(|(key, value)| (key.clone(), Self::from_value(value)))
                    .collect(),
            ),
        }
    }

    /// Converts anything serializable, such as one of the crate's result
    /// enums, through `serde_json`.
    pub fn of<T: Serialize + ?Sized>(value: &T) -> Self {
        Self::from_value(&serde_json::to_value(value).expect("the value serializes to JSON"))
    }

    /// Returns whether two values are the same JSON, whatever the order of
    /// their object members.
    pub fn same(&self, other: &Self) -> bool {
        self.to_value() == other.to_value()
    }
}

impl fmt::Display for J {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

fn json_string(text: &str) -> String {
    serde_json::to_string(text).expect("a string serializes to JSON")
}

impl Serialize for J {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Int(value) => serializer.serialize_u64(*value),
            Self::Str(text) => serializer.serialize_str(text),
            Self::Arr(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Obj(members) => {
                let mut map = serializer.serialize_map(Some(members.len()))?;
                for (key, value) in members {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
            Self::Raw(_) => Err(serde::ser::Error::custom(
                "raw JSON text is only for signed payloads",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for J {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JVisitor)
    }
}

struct JVisitor;

impl<'de> Visitor<'de> for JVisitor {
    type Value = J;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value with no negative or fractional number")
    }

    fn visit_unit<E: de::Error>(self) -> Result<J, E> {
        Ok(J::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<J, E> {
        Ok(J::Bool(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<J, E> {
        Ok(J::Int(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<J, E> {
        u64::try_from(value)
            .map(J::Int)
            .map_err(|_| E::custom("a negative number"))
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<J, E> {
        Ok(J::Str(text.to_owned()))
    }

    fn visit_string<E: de::Error>(self, text: String) -> Result<J, E> {
        Ok(J::Str(text))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<J, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(J::Arr(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<J, A::Error> {
        let mut members = Vec::new();
        while let Some((key, value)) = map.next_entry::<String, J>()? {
            members.push((key, value));
        }
        Ok(J::Obj(members))
    }
}
