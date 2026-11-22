//! The schema-independent pass: the document is one JSON object, no object
//! at any depth repeats a key, and every number at any depth is an integer
//! from 0 to 2^53 − 1.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

use super::MAX_INTEGER;
use super::de::{Path, Recorder};

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

const NUMBER_RULE: &str = "numbers must be integers from 0 to 2^53 - 1, \
     written without a sign, a fraction or an exponent";

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
