//! A [`Deserializer`] wrapper that holds a typed deserialization to the
//! strict rules regardless of how the target type was derived, and records
//! where in the document an error arose.

use std::cell::RefCell;
use std::fmt;

use serde::de::{
    self, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor,
};
use serde::{Deserialize, de::value::StrDeserializer};

/// The newtype-struct name through which [`super::Nullable`] asks for an
/// explicit `null` to be let through.
pub(super) const NULLABLE: &str = "$senta_protocol::auth::jws::strict::Nullable";

/// Where in a JSON document a value sits.
#[derive(Clone, Copy)]
pub(super) enum Path<'a> {
    Root,
    Key { parent: &'a Path<'a>, key: &'a str },
    Index { parent: &'a Path<'a>, index: usize },
}

impl fmt::Display for Path<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Path::Root => f.write_str("$"),
            Path::Key { parent, key } => {
                let plain =
                    !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
                if plain {
                    write!(f, "{parent}.{key}")
                } else {
                    write!(f, "{parent}[{key:?}]")
                }
            }
            Path::Index { parent, index } => write!(f, "{parent}[{index}]"),
        }
    }
}

/// Keeps the path of the first, innermost, error.
#[derive(Default)]
pub(super) struct Recorder(RefCell<Option<String>>);

impl Recorder {
    pub(super) fn record(&self, path: &Path<'_>) {
        let mut slot = self.0.borrow_mut();
        if slot.is_none() {
            *slot = Some(path.to_string());
        }
    }

    pub(super) fn take(&self) -> Option<String> {
        self.0.borrow_mut().take()
    }

    fn track<T, E>(&self, path: &Path<'_>, result: Result<T, E>) -> Result<T, E> {
        if result.is_err() {
            self.record(path);
        }
        result
    }
}

/// Returns whether `name` is snake_case: lowercase ASCII letters, digits and
/// `_`.
fn is_snake_case(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn check_field_names<E: de::Error>(fields: &[&str]) -> Result<(), E> {
    match fields.iter().find(|name| !is_snake_case(name)) {
        Some(name) => Err(E::custom(format_args!(
            "schema field name `{name}` is not snake_case"
        ))),
        None => Ok(()),
    }
}

/// The strict deserializer for one value at `path`.
pub(super) struct Strict<'a, D> {
    de: D,
    path: &'a Path<'a>,
    rec: &'a Recorder,
    /// Whether an explicit `null` may stand for `None`; only
    /// [`super::Nullable`] turns this on.
    null_ok: bool,
}

impl<'a, D> Strict<'a, D> {
    pub(super) fn new(de: D, path: &'a Path<'a>, rec: &'a Recorder) -> Self {
        Self {
            de,
            path,
            rec,
            null_ok: false,
        }
    }
}

/// Wraps a visitor so that whatever it is handed next is strict too.
struct Wrap<'a, V> {
    visitor: V,
    path: &'a Path<'a>,
    rec: &'a Recorder,
    /// The fields of the struct being read, if a struct is: its keys must be
    /// among them, and it must come as a JSON object, not an array.
    fields: Option<&'static [&'static str]>,
    null_ok: bool,
}

impl<'a, V> Wrap<'a, V> {
    fn new(visitor: V, path: &'a Path<'a>, rec: &'a Recorder) -> Self {
        Self {
            visitor,
            path,
            rec,
            fields: None,
            null_ok: true,
        }
    }
}

macro_rules! forward_deserialize {
    ($($method:ident)*) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            let Self { de, path, rec, .. } = self;
            rec.track(path, de.$method(Wrap::new(visitor, path, rec)))
        }
    )*};
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Strict<'_, D> {
    type Error = D::Error;

    forward_deserialize! {
        deserialize_any deserialize_bool
        deserialize_i8 deserialize_i16 deserialize_i32 deserialize_i64 deserialize_i128
        deserialize_u8 deserialize_u16 deserialize_u32 deserialize_u64 deserialize_u128
        deserialize_f32 deserialize_f64 deserialize_char deserialize_str deserialize_string
        deserialize_bytes deserialize_byte_buf deserialize_unit deserialize_seq deserialize_map
        deserialize_identifier deserialize_ignored_any
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        let Self {
            de,
            path,
            rec,
            null_ok,
        } = self;
        let wrapped = Wrap {
            null_ok,
            ..Wrap::new(visitor, path, rec)
        };
        rec.track(path, de.deserialize_option(wrapped))
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        let Self { de, path, rec, .. } = self;
        rec.track(
            path,
            de.deserialize_unit_struct(name, Wrap::new(visitor, path, rec)),
        )
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        let Self { de, path, rec, .. } = self;
        if name == NULLABLE {
            let nullable = Strict {
                de,
                path,
                rec,
                null_ok: true,
            };
            return rec.track(path, visitor.visit_newtype_struct(nullable));
        }
        rec.track(
            path,
            de.deserialize_newtype_struct(name, Wrap::new(visitor, path, rec)),
        )
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        let Self { de, path, rec, .. } = self;
        rec.track(
            path,
            de.deserialize_tuple(len, Wrap::new(visitor, path, rec)),
        )
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        let Self { de, path, rec, .. } = self;
        rec.track(
            path,
            de.deserialize_tuple_struct(name, len, Wrap::new(visitor, path, rec)),
        )
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        let Self { de, path, rec, .. } = self;
        let result = check_field_names(fields).and_then(|()| {
            let wrapped = Wrap {
                fields: Some(fields),
                ..Wrap::new(visitor, path, rec)
            };
            de.deserialize_struct(name, fields, wrapped)
        });
        rec.track(path, result)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        let Self { de, path, rec, .. } = self;
        rec.track(
            path,
            de.deserialize_enum(name, variants, Wrap::new(visitor, path, rec)),
        )
    }

    fn is_human_readable(&self) -> bool {
        self.de.is_human_readable()
    }
}

macro_rules! forward_visit {
    ($($method:ident: $ty:ty)*) => {$(
        fn $method<E: de::Error>(self, value: $ty) -> Result<Self::Value, E> {
            self.visitor.$method(value)
        }
    )*};
}

impl<'de, V: Visitor<'de>> Visitor<'de> for Wrap<'_, V> {
    type Value = V::Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.visitor.expecting(f)
    }

    forward_visit! {
        visit_bool: bool
        visit_i8: i8 visit_i16: i16 visit_i32: i32 visit_i64: i64 visit_i128: i128
        visit_u8: u8 visit_u16: u16 visit_u32: u32 visit_u64: u64 visit_u128: u128
        visit_f32: f32 visit_f64: f64 visit_char: char
        visit_str: &str visit_borrowed_str: &'de str visit_string: String
        visit_bytes: &[u8] visit_borrowed_bytes: &'de [u8] visit_byte_buf: Vec<u8>
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        self.visitor.visit_unit()
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        if self.null_ok {
            self.visitor.visit_none()
        } else {
            Err(E::custom(
                "explicit null is not accepted here; leave the field out instead",
            ))
        }
    }

    fn visit_some<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        self.visitor
            .visit_some(Strict::new(de, self.path, self.rec))
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        self.visitor
            .visit_newtype_struct(Strict::new(de, self.path, self.rec))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        if self.fields.is_some() {
            return Err(de::Error::invalid_type(
                de::Unexpected::Seq,
                &"a JSON object",
            ));
        }
        self.visitor.visit_seq(StrictSeq {
            seq,
            path: self.path,
            rec: self.rec,
            index: 0,
        })
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        self.visitor.visit_map(StrictMap {
            map,
            path: self.path,
            rec: self.rec,
            fields: self.fields,
            key: None,
        })
    }

    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<Self::Value, A::Error> {
        self.visitor.visit_enum(StrictEnum {
            data,
            path: self.path,
            rec: self.rec,
        })
    }
}

/// A seed for a value nested at `path`.
struct Child<'a, S> {
    seed: S,
    path: &'a Path<'a>,
    rec: &'a Recorder,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Child<'_, S> {
    type Value = S::Value;

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<S::Value, D::Error> {
        self.seed.deserialize(Strict::new(de, self.path, self.rec))
    }
}

struct StrictSeq<'a, A> {
    seq: A,
    path: &'a Path<'a>,
    rec: &'a Recorder,
    index: usize,
}

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for StrictSeq<'_, A> {
    type Error = A::Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, A::Error> {
        let path = Path::Index {
            parent: self.path,
            index: self.index,
        };
        self.index += 1;
        self.seq.next_element_seed(Child {
            seed,
            path: &path,
            rec: self.rec,
        })
    }

    fn size_hint(&self) -> Option<usize> {
        self.seq.size_hint()
    }
}

struct StrictMap<'a, A> {
    map: A,
    path: &'a Path<'a>,
    rec: &'a Recorder,
    fields: Option<&'static [&'static str]>,
    /// The key most recently read, for the path of its value.
    key: Option<String>,
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for StrictMap<'_, A> {
    type Error = A::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, A::Error> {
        let entry = self.map.next_key_seed(KeySeed {
            seed,
            fields: self.fields,
            path: self.path,
            rec: self.rec,
        })?;
        Ok(entry.map(|(value, key)| {
            self.key = Some(key);
            value
        }))
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, A::Error> {
        let key = self.key.take();
        let path = Path::Key {
            parent: self.path,
            key: key.as_deref().unwrap_or("?"),
        };
        self.map.next_value_seed(Child {
            seed,
            path: &path,
            rec: self.rec,
        })
    }

    fn size_hint(&self) -> Option<usize> {
        self.map.size_hint()
    }
}

/// Reads an object key as a string, rejects it if the object is a struct
/// that does not have that field, and hands it on to the real seed.
struct KeySeed<'a, S> {
    seed: S,
    fields: Option<&'static [&'static str]>,
    path: &'a Path<'a>,
    rec: &'a Recorder,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for KeySeed<'_, S> {
    type Value = (S::Value, String);

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        let key = String::deserialize(de)?;
        if let Some(fields) = self.fields
            && !fields.contains(&key.as_str())
        {
            self.rec.record(&Path::Key {
                parent: self.path,
                key: &key,
            });
            return Err(de::Error::custom(format_args!(
                "unknown field `{}`",
                key.escape_debug()
            )));
        }
        let value = self
            .seed
            .deserialize(StrDeserializer::<D::Error>::new(&key))?;
        Ok((value, key))
    }
}

struct StrictEnum<'a, A> {
    data: A,
    path: &'a Path<'a>,
    rec: &'a Recorder,
}

impl<'a, 'de, A: EnumAccess<'de>> EnumAccess<'de> for StrictEnum<'a, A> {
    type Error = A::Error;
    type Variant = StrictVariant<'a, A::Variant>;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), A::Error> {
        let (value, variant) = self.data.variant_seed(seed)?;
        Ok((
            value,
            StrictVariant {
                variant,
                path: self.path,
                rec: self.rec,
            },
        ))
    }
}

struct StrictVariant<'a, A> {
    variant: A,
    path: &'a Path<'a>,
    rec: &'a Recorder,
}

impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for StrictVariant<'_, A> {
    type Error = A::Error;

    fn unit_variant(self) -> Result<(), A::Error> {
        self.variant.unit_variant()
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, A::Error> {
        self.variant.newtype_variant_seed(Child {
            seed,
            path: self.path,
            rec: self.rec,
        })
    }

    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, A::Error> {
        self.variant
            .tuple_variant(len, Wrap::new(visitor, self.path, self.rec))
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, A::Error> {
        check_field_names(fields)?;
        let wrapped = Wrap {
            fields: Some(fields),
            ..Wrap::new(visitor, self.path, self.rec)
        };
        self.variant.struct_variant(fields, wrapped)
    }
}
