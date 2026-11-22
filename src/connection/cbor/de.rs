//! A serde deserializer over a CBOR body that has passed
//! [`check_body`](super::scan::check_body).
//!
//! It decodes a value only from the CBOR type the rules name for it and
//! accepts no stand-in: a sequence only from an array (never a byte
//! string), a byte value only from a byte string (never an array), a string
//! only from a text string (never a byte string), a struct only from a map
//! (never an array), and a field or variant name only from a text string,
//! at a definite length or in chunks. Tags other than the bignums 2 and 3
//! are passed over, and a bignum reads as the integer it holds.
//!
//! The scan before it has established that the bytes are one well-formed
//! item, nested no deeper than [`MAX_DEPTH`](super::scan::MAX_DEPTH), so
//! every declared length here fits the bytes that remain and the recursion
//! is bounded.

use std::fmt;

use serde::de::{self, DeserializeSeed, Unexpected, Visitor};

use super::scan::{Head, Reader, ScanError, skip_value};

const TAG_BIGNUM_POSITIVE: u64 = 2;
const TAG_BIGNUM_NEGATIVE: u64 = 3;
const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;

/// An error decoding a scanned body into a type.
#[derive(Debug)]
pub(super) struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl de::Error for Error {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self(message.to_string())
    }
}

impl From<ScanError> for Error {
    fn from(_: ScanError) -> Self {
        Self("malformed CBOR".to_owned())
    }
}

/// Decodes `bytes`, which [`check_body`](super::scan::check_body) has
/// passed, into `T`.
pub(super) fn from_slice<'de, T: de::Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, Error> {
    let mut deserializer = Deserializer {
        reader: Reader::new(bytes),
    };
    T::deserialize(&mut deserializer)
}

/// The next data item, as far as its head tells.
#[derive(Debug, Clone, Copy)]
enum Token {
    /// An integer: `magnitude`, or `-1 - magnitude` when `negative`.
    Int {
        negative: bool,
        magnitude: u128,
    },
    Bytes(Option<u64>),
    Text(Option<u64>),
    Array(Option<u64>),
    Map(Option<u64>),
    Float(f64),
    Bool(bool),
    Null,
    /// Any other simple value, `undefined` among them.
    Simple,
}

impl Token {
    fn unexpected(self) -> Unexpected<'static> {
        match self {
            Self::Int {
                negative: false,
                magnitude,
            } => {
                u64::try_from(magnitude).map_or(Unexpected::Other("integer"), Unexpected::Unsigned)
            }
            Self::Int {
                negative: true,
                magnitude,
            } => i64::try_from(magnitude)
                .ok()
                .and_then(|magnitude| (-1i64).checked_sub(magnitude))
                .map_or(Unexpected::Other("integer"), Unexpected::Signed),
            Self::Bytes(_) => Unexpected::Other("byte string"),
            Self::Text(_) => Unexpected::Other("text string"),
            Self::Array(_) => Unexpected::Seq,
            Self::Map(_) => Unexpected::Map,
            Self::Float(value) => Unexpected::Float(value),
            Self::Bool(value) => Unexpected::Bool(value),
            Self::Null => Unexpected::Unit,
            Self::Simple => Unexpected::Other("simple value"),
        }
    }
}

/// The content of a byte or text string: borrowed from the input when it
/// was written at a definite length, joined from its chunks otherwise.
enum Content<'de> {
    Borrowed(&'de [u8]),
    Owned(Vec<u8>),
}

struct Deserializer<'de> {
    reader: Reader<'de>,
}

impl<'de> Deserializer<'de> {
    /// Reads the next head, passing over tags; a bignum is read whole.
    fn token(&mut self) -> Result<Token, Error> {
        loop {
            let token = match self.reader.head()? {
                Head::Tag(tag @ (TAG_BIGNUM_POSITIVE | TAG_BIGNUM_NEGATIVE)) => {
                    let mut probe = self.reader.clone();
                    if let Head::Bytes(len) = probe.head()? {
                        self.reader = probe;
                        return self.bignum(tag == TAG_BIGNUM_NEGATIVE, len);
                    }
                    continue;
                }
                Head::Tag(_) => continue,
                Head::Break => return Err(ScanError::Malformed.into()),
                Head::Unsigned(value) => Token::Int {
                    negative: false,
                    magnitude: u128::from(value),
                },
                Head::Negative(value) => Token::Int {
                    negative: true,
                    magnitude: u128::from(value),
                },
                Head::Bytes(len) => Token::Bytes(len),
                Head::Text(len) => Token::Text(len),
                Head::Array(len) => Token::Array(len),
                Head::Map(len) => Token::Map(len),
                Head::Float(bits) => Token::Float(f64::from_bits(bits)),
                Head::Simple(SIMPLE_FALSE) => Token::Bool(false),
                Head::Simple(SIMPLE_TRUE) => Token::Bool(true),
                Head::Simple(SIMPLE_NULL) => Token::Null,
                Head::Simple(_) => Token::Simple,
            };
            return Ok(token);
        }
    }

    /// Reads the next head without consuming it.
    fn peek(&self) -> Result<Token, Error> {
        Deserializer {
            reader: self.reader.clone(),
        }
        .token()
    }

    fn bignum(&mut self, negative: bool, len: Option<u64>) -> Result<Token, Error> {
        let mut digits = Vec::new();
        self.reader.string(false, len, Some(&mut digits))?;
        let significant = digits
            .iter()
            .position(|&digit| digit != 0)
            .and_then(|first| digits.get(first..))
            .unwrap_or_default();
        if significant.len() > 16 {
            return Err(de::Error::custom("bignum outside the range of 128 bits"));
        }
        let mut word = [0u8; 16];
        if let Some(target) = word.get_mut(16 - significant.len()..) {
            target.copy_from_slice(significant);
        }
        Ok(Token::Int {
            negative,
            magnitude: u128::from_be_bytes(word),
        })
    }

    fn content(&mut self, text: bool, len: Option<u64>) -> Result<Content<'de>, Error> {
        match len {
            Some(len) => {
                let content = self.reader.take(len)?;
                Ok(Content::Borrowed(content))
            }
            None => {
                let mut joined = Vec::new();
                self.reader.string(text, None, Some(&mut joined))?;
                Ok(Content::Owned(joined))
            }
        }
    }

    fn visit_bytes<V: Visitor<'de>>(
        &mut self,
        len: Option<u64>,
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.content(false, len)? {
            Content::Borrowed(bytes) => visitor.visit_borrowed_bytes(bytes),
            Content::Owned(bytes) => visitor.visit_byte_buf(bytes),
        }
    }

    fn visit_text<V: Visitor<'de>>(
        &mut self,
        len: Option<u64>,
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.content(true, len)? {
            Content::Borrowed(bytes) => {
                let text = std::str::from_utf8(bytes).map_err(|_| ScanError::Malformed)?;
                visitor.visit_borrowed_str(text)
            }
            Content::Owned(bytes) => {
                let text = String::from_utf8(bytes).map_err(|_| ScanError::Malformed)?;
                visitor.visit_string(text)
            }
        }
    }

    fn visit_seq<V: Visitor<'de>>(
        &mut self,
        len: Option<u64>,
        visitor: V,
    ) -> Result<V::Value, Error> {
        let mut items = Items::new(self, len);
        let value = visitor.visit_seq(&mut items)?;
        items.finish()?;
        Ok(value)
    }

    fn visit_map<V: Visitor<'de>>(
        &mut self,
        len: Option<u64>,
        visitor: V,
    ) -> Result<V::Value, Error> {
        let mut entries = Items::new(self, len);
        let value = visitor.visit_map(&mut entries)?;
        entries.finish()?;
        Ok(value)
    }

    fn visit_any<V: Visitor<'de>>(&mut self, token: Token, visitor: V) -> Result<V::Value, Error> {
        match token {
            Token::Int {
                negative,
                magnitude,
            } => visit_int(negative, magnitude, visitor),
            Token::Bytes(len) => self.visit_bytes(len, visitor),
            Token::Text(len) => self.visit_text(len, visitor),
            Token::Array(len) => self.visit_seq(len, visitor),
            Token::Map(len) => self.visit_map(len, visitor),
            Token::Float(value) => visitor.visit_f64(value),
            Token::Bool(value) => visitor.visit_bool(value),
            Token::Null => visitor.visit_unit(),
            Token::Simple => Err(de::Error::invalid_type(token.unexpected(), &visitor)),
        }
    }

    fn integer<V: Visitor<'de>>(&mut self, visitor: V) -> Result<V::Value, Error> {
        match self.token()? {
            Token::Int {
                negative,
                magnitude,
            } => visit_int(negative, magnitude, visitor),
            token => Err(de::Error::invalid_type(token.unexpected(), &visitor)),
        }
    }

    fn float<V: Visitor<'de>>(&mut self, visitor: V) -> Result<V::Value, Error> {
        match self.token()? {
            Token::Float(value) => visitor.visit_f64(value),
            token => Err(de::Error::invalid_type(token.unexpected(), &visitor)),
        }
    }

    fn text<V: Visitor<'de>>(&mut self, visitor: V) -> Result<V::Value, Error> {
        match self.token()? {
            Token::Text(len) => self.visit_text(len, visitor),
            token => Err(de::Error::invalid_type(token.unexpected(), &visitor)),
        }
    }

    fn bytes<V: Visitor<'de>>(&mut self, visitor: V) -> Result<V::Value, Error> {
        match self.token()? {
            Token::Bytes(len) => self.visit_bytes(len, visitor),
            token => Err(de::Error::invalid_type(token.unexpected(), &visitor)),
        }
    }

    fn array<V: Visitor<'de>>(&mut self, visitor: V) -> Result<V::Value, Error> {
        match self.token()? {
            Token::Array(len) => self.visit_seq(len, visitor),
            token => Err(de::Error::invalid_type(token.unexpected(), &visitor)),
        }
    }

    fn map<V: Visitor<'de>>(&mut self, visitor: V) -> Result<V::Value, Error> {
        match self.token()? {
            Token::Map(len) => self.visit_map(len, visitor),
            token => Err(de::Error::invalid_type(token.unexpected(), &visitor)),
        }
    }

    fn unit<V: Visitor<'de>>(&mut self, visitor: V) -> Result<V::Value, Error> {
        match self.token()? {
            Token::Null => visitor.visit_unit(),
            token => Err(de::Error::invalid_type(token.unexpected(), &visitor)),
        }
    }
}

fn visit_int<'de, V: Visitor<'de>>(
    negative: bool,
    magnitude: u128,
    visitor: V,
) -> Result<V::Value, Error> {
    if !negative {
        return match u64::try_from(magnitude) {
            Ok(value) => visitor.visit_u64(value),
            Err(_) => visitor.visit_u128(magnitude),
        };
    }
    let value = i128::try_from(magnitude)
        .ok()
        .and_then(|magnitude| (-1i128).checked_sub(magnitude))
        .ok_or_else(|| {
            <Error as de::Error>::custom("negative integer outside the range of i128")
        })?;
    match i64::try_from(value) {
        Ok(value) => visitor.visit_i64(value),
        Err(_) => visitor.visit_i128(value),
    }
}

impl<'de> de::Deserializer<'de> for &mut Deserializer<'de> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let token = self.token()?;
        self.visit_any(token, visitor)
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.token()? {
            Token::Bool(value) => visitor.visit_bool(value),
            token => Err(de::Error::invalid_type(token.unexpected(), &visitor)),
        }
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.integer(visitor)
    }

    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.integer(visitor)
    }

    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.integer(visitor)
    }

    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.integer(visitor)
    }

    fn deserialize_i128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.integer(visitor)
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.integer(visitor)
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.integer(visitor)
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.integer(visitor)
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.integer(visitor)
    }

    fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.integer(visitor)
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.float(visitor)
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.float(visitor)
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.text(visitor)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.text(visitor)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.text(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.bytes(visitor)
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.bytes(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if matches!(self.peek()?, Token::Null) {
            self.token()?;
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.unit(visitor)
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.unit(visitor)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.array(visitor)
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.array(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.array(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.map(visitor)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.map(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.peek()? {
            // A variant without a value: its tag alone, read as the
            // variant's name.
            Token::Text(_) => visitor.visit_enum(Variant {
                de: self,
                with_value: false,
            }),
            // A variant with a value: a map of one entry.
            Token::Map(len @ (Some(1) | None)) => {
                self.token()?;
                let value = visitor.visit_enum(Variant {
                    de: &mut *self,
                    with_value: true,
                })?;
                if len.is_none() && !self.reader.eat_break() {
                    return Err(de::Error::custom("enum map with more than one entry"));
                }
                Ok(value)
            }
            token => Err(de::Error::invalid_type(token.unexpected(), &visitor)),
        }
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.text(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        skip_value(&mut self.reader)?;
        visitor.visit_unit()
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

/// How many items of an array, or entries of a map, are still to come.
enum Left {
    Count(u64),
    /// An indefinite length, whose break has not yet been read.
    Indefinite,
    /// An indefinite length, whose break has been read.
    Done,
}

/// The items of an array, or the entries of a map, as serde reads them.
struct Items<'a, 'de> {
    de: &'a mut Deserializer<'de>,
    left: Left,
}

impl<'a, 'de> Items<'a, 'de> {
    fn new(de: &'a mut Deserializer<'de>, len: Option<u64>) -> Self {
        let left = len.map_or(Left::Indefinite, Left::Count);
        Self { de, left }
    }

    /// Reports whether another item comes, counting it off.
    fn next(&mut self) -> bool {
        match self.left {
            Left::Count(0) | Left::Done => false,
            Left::Count(left) => {
                self.left = Left::Count(left - 1);
                true
            }
            Left::Indefinite => {
                if self.de.reader.eat_break() {
                    self.left = Left::Done;
                    false
                } else {
                    true
                }
            }
        }
    }

    /// Fails when the visitor stopped before the container's end.
    fn finish(mut self) -> Result<(), Error> {
        if self.next() {
            Err(de::Error::custom(
                "array or map has more items than the type takes",
            ))
        } else {
            Ok(())
        }
    }

    fn size_hint(&self) -> Option<usize> {
        match self.left {
            Left::Count(left) => usize::try_from(left).ok(),
            Left::Indefinite => None,
            Left::Done => Some(0),
        }
    }
}

impl<'de> de::SeqAccess<'de> for &mut Items<'_, 'de> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        if self.next() {
            seed.deserialize(&mut *self.de).map(Some)
        } else {
            Ok(None)
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Items::size_hint(self)
    }
}

impl<'de> de::MapAccess<'de> for &mut Items<'_, 'de> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        if self.next() {
            seed.deserialize(&mut *self.de).map(Some)
        } else {
            Ok(None)
        }
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        seed.deserialize(&mut *self.de)
    }

    fn size_hint(&self) -> Option<usize> {
        Items::size_hint(self)
    }
}

/// An enum's variant: its tag as text, or a map of one entry whose key is
/// the tag and whose value is the content.
struct Variant<'a, 'de> {
    de: &'a mut Deserializer<'de>,
    with_value: bool,
}

impl<'a, 'de> de::EnumAccess<'de> for Variant<'a, 'de> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self), Error> {
        let tag = seed.deserialize(&mut *self.de)?;
        Ok((tag, self))
    }
}

impl<'de> de::VariantAccess<'de> for Variant<'_, 'de> {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        if self.with_value {
            Err(de::Error::invalid_type(
                Unexpected::Map,
                &"a variant without a value, as text",
            ))
        } else {
            Ok(())
        }
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        if self.with_value {
            seed.deserialize(&mut *self.de)
        } else {
            Err(de::Error::invalid_type(
                Unexpected::UnitVariant,
                &"a variant with a value, as a map of one entry",
            ))
        }
    }

    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value, Error> {
        if self.with_value {
            de::Deserializer::deserialize_seq(&mut *self.de, visitor)
        } else {
            Err(de::Error::invalid_type(Unexpected::UnitVariant, &visitor))
        }
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        if self.with_value {
            de::Deserializer::deserialize_map(&mut *self.de, visitor)
        } else {
            Err(de::Error::invalid_type(Unexpected::UnitVariant, &visitor))
        }
    }
}
