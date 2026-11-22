//! The schema-independent pass: the document is one JSON object, no object
//! at any depth repeats a key, and every number at any depth is an integer
//! from 0 to 2^53 − 1.
//!
//! With serde_json's `arbitrary_precision` feature, which Cargo turns on
//! for this crate too wherever another crate in the same build asks for
//! it, a number that serde_json does not visit as an `i64` or a `u64`
//! (past `u64::MAX`, below `i64::MIN`, or with a fraction or an exponent)
//! reaches this pass not as a number but as an object of one key,
//! `$serde_json::private::Number`, whose value is the number's text. Every
//! integer from 0 to 2^53 − 1 still arrives as a `u64`, so such an object
//! is always a number out of rule and is rejected as one. The check runs
//! whether or not the feature is on, so a real object with that key first
//! is rejected too; no content has a use for it.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

use super::MAX_INTEGER;
use super::de::{Path, Recorder};

/// The key of the object through which serde_json's `arbitrary_precision`
/// feature hands over a number it does not visit as an `i64` or a `u64`.
const NUMBER_TOKEN: &str = "$serde_json::private::Number";

const NUMBER_RULE: &str = "numbers must be integers from 0 to 2^53 - 1, \
     written without a sign, a fraction or an exponent";

/// A JSON value at `path`, checked and discarded.
pub(super) struct Node<'a> {
    path: &'a Path<'a>,
    rec: &'a Recorder,
}

impl<'a> Node<'a> {
    pub(super) fn new(path: &'a Path<'a>, rec: &'a Recorder) -> Self {
        Self { path, rec }
    }

    fn fail<E: de::Error>(&self, message: &str) -> E {
        self.rec.record(self.path);
        E::custom(message)
    }
}

impl<'de> DeserializeSeed<'de> for Node<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<(), D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Node<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.path {
            Path::Root => f.write_str("a JSON object"),
            _ => f.write_str("a JSON value"),
        }
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<(), E> {
        if value <= MAX_INTEGER {
            Ok(())
        } else {
            Err(self.fail(NUMBER_RULE))
        }
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Err(self.fail(NUMBER_RULE))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Err(self.fail(NUMBER_RULE))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let mut index = 0;
        loop {
            let path = Path::Index {
                parent: self.path,
                index,
            };
            if seq.next_element_seed(Node::new(&path, self.rec))?.is_none() {
                return Ok(());
            }
            index += 1;
        }
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if seen.is_empty() && key == NUMBER_TOKEN {
                return Err(self.fail(NUMBER_RULE));
            }
            let path = Path::Key {
                parent: self.path,
                key: &key,
            };
            if seen.contains(&key) {
                self.rec.record(&path);
                return Err(de::Error::custom(format_args!(
                    "duplicate key `{}`",
                    key.escape_debug()
                )));
            }
            map.next_value_seed(Node::new(&path, self.rec))?;
            seen.insert(key);
        }
        Ok(())
    }
}
