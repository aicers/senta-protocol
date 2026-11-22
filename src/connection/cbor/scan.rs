//! A CBOR (RFC 8949) scanner that checks well-formedness, and optionally
//! rejects duplicate map keys, without decoding into any value type.
//!
//! Nothing here allocates in proportion to a length the input declares: a
//! string is sliced out of the input only once the input is known to hold
//! it, and a container's element count is only ever counted down. What is
//! allocated grows with the bytes actually read.

/// The nesting of arrays and maps [`check_value`] follows before giving up.
///
/// The decoder in `de` recurses once per level, so this bound is also what
/// keeps its stack small.
pub(super) const MAX_DEPTH: usize = 256;

const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;

const TAG_BIGNUM_POSITIVE: u64 = 2;
const TAG_BIGNUM_NEGATIVE: u64 = 3;

const BREAK: u8 = 0xff;
const FLOAT64: u8 = 0xfb;

/// The ways a byte sequence fails a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanError {
    /// The bytes are not well-formed CBOR: truncated, a reserved encoding,
    /// a misplaced break, or a text string that is not UTF-8.
    Malformed,
    /// A complete value is followed by more bytes.
    TrailingBytes,
    /// Arrays and maps nest deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A map holds the same key twice.
    DuplicateKey,
}

/// The head of one data item: its major type and argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Head {
    Unsigned(u64),
    Negative(u64),
    Bytes(Option<u64>),
    Text(Option<u64>),
    Array(Option<u64>),
    Map(Option<u64>),
    Tag(u64),
    /// A float of any width, widened to the bits of an `f64`.
    Float(u64),
    Simple(u8),
    Break,
}

/// A cursor over a byte slice.
#[derive(Clone)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn is_at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn byte(&mut self) -> Result<u8, ScanError> {
        let byte = *self.buf.get(self.pos).ok_or(ScanError::Malformed)?;
        self.pos += 1;
        Ok(byte)
    }

    /// Consumes a break byte if one comes next.
    pub(super) fn eat_break(&mut self) -> bool {
        if self.buf.get(self.pos) == Some(&BREAK) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Returns the next `len` bytes, failing before anything is allocated
    /// when fewer remain.
    pub(super) fn take(&mut self, len: u64) -> Result<&'a [u8], ScanError> {
        self.take_exact(usize::try_from(len).map_err(|_| ScanError::Malformed)?)
    }

    fn take_exact(&mut self, len: usize) -> Result<&'a [u8], ScanError> {
        let end = self.pos.checked_add(len).ok_or(ScanError::Malformed)?;
        let slice = self.buf.get(self.pos..end).ok_or(ScanError::Malformed)?;
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ScanError> {
        let slice = self.take_exact(N)?;
        <[u8; N]>::try_from(slice).map_err(|_| ScanError::Malformed)
    }

    fn argument(&mut self, info: u8) -> Result<u64, ScanError> {
        match info {
            0..=23 => Ok(u64::from(info)),
            24 => Ok(u64::from(self.byte()?)),
            25 => Ok(u64::from(u16::from_be_bytes(self.array()?))),
            26 => Ok(u64::from(u32::from_be_bytes(self.array()?))),
            27 => Ok(u64::from_be_bytes(self.array()?)),
            _ => Err(ScanError::Malformed),
        }
    }

    /// Reads the head of the next data item.
    pub(crate) fn head(&mut self) -> Result<Head, ScanError> {
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        if info == 31 {
            return match major {
                MAJOR_BYTES => Ok(Head::Bytes(None)),
                MAJOR_TEXT => Ok(Head::Text(None)),
                MAJOR_ARRAY => Ok(Head::Array(None)),
                MAJOR_MAP => Ok(Head::Map(None)),
                MAJOR_SIMPLE => Ok(Head::Break),
                _ => Err(ScanError::Malformed),
            };
        }
        if major == MAJOR_SIMPLE {
            return match info {
                0..=23 => Ok(Head::Simple(info)),
                24 => match self.byte()? {
                    // RFC 8949 3.3: a two-byte simple value below 32 is not
                    // well-formed.
                    value if value < 32 => Err(ScanError::Malformed),
                    value => Ok(Head::Simple(value)),
                },
                25 => Ok(Head::Float(
                    half_to_f64(u16::from_be_bytes(self.array()?)).to_bits(),
                )),
                26 => Ok(Head::Float(
                    f64::from(f32::from_bits(u32::from_be_bytes(self.array()?))).to_bits(),
                )),
                27 => Ok(Head::Float(u64::from_be_bytes(self.array()?))),
                _ => Err(ScanError::Malformed),
            };
        }
        let value = self.argument(info)?;
        match major {
            MAJOR_UNSIGNED => Ok(Head::Unsigned(value)),
            MAJOR_NEGATIVE => Ok(Head::Negative(value)),
            MAJOR_BYTES => Ok(Head::Bytes(Some(value))),
            MAJOR_TEXT => Ok(Head::Text(Some(value))),
            MAJOR_ARRAY => Ok(Head::Array(Some(value))),
            MAJOR_MAP => Ok(Head::Map(Some(value))),
            MAJOR_TAG => Ok(Head::Tag(value)),
            _ => Err(ScanError::Malformed),
        }
    }

    /// Reads the content of a byte or text string whose head has just been
    /// read, appending it to `sink` when one is given.
    ///
    /// An indefinite-length string is a run of definite-length chunks of
    /// the same major type, ended by a break. Each text chunk must be UTF-8
    /// on its own.
    pub(crate) fn string(
        &mut self,
        text: bool,
        len: Option<u64>,
        mut sink: Option<&mut Vec<u8>>,
    ) -> Result<(), ScanError> {
        let Some(len) = len else {
            loop {
                let chunk = match self.head()? {
                    Head::Break => return Ok(()),
                    Head::Bytes(Some(len)) if !text => len,
                    Head::Text(Some(len)) if text => len,
                    _ => return Err(ScanError::Malformed),
                };
                self.string(text, Some(chunk), sink.as_deref_mut())?;
            }
        };
        let content = self.take(len)?;
        if text && std::str::from_utf8(content).is_err() {
            return Err(ScanError::Malformed);
        }
        if let Some(sink) = sink {
            sink.extend_from_slice(content);
        }
        Ok(())
    }
}

/// Widens the bits of an IEEE 754 half-precision float to an `f64`,
/// exactly, keeping a NaN's payload.
fn half_to_f64(half: u16) -> f64 {
    let negative = half & 0x8000 != 0;
    let exponent = (half >> 10) & 0x1f;
    let mantissa = u64::from(half & 0x03ff);
    let sign = u64::from(negative) << 63;
    match exponent {
        0 => {
            // Subnormal: mantissa × 2⁻²⁴, exact in an `f64`.
            let magnitude = f64::from(half & 0x03ff) * (1.0 / 16_777_216.0);
            if negative { -magnitude } else { magnitude }
        }
        31 => f64::from_bits(sign | 0x7ff0_0000_0000_0000 | (mantissa << 42)),
        _ => {
            let biased = u64::from(exponent) + 1023 - 15;
            f64::from_bits(sign | (biased << 52) | (mantissa << 42))
        }
    }
}

/// A container [`skip_value`] has opened and not yet closed.
enum Open {
    /// A definite-length array or map, with the items still to come; a
    /// map counts its keys and values separately.
    Items(u64),
    IndefiniteArray,
    /// An indefinite-length map, and whether a key is waiting for its
    /// value.
    IndefiniteMap {
        odd: bool,
    },
}

/// Skips exactly one well-formed data item, at any depth.
///
/// It keeps its own stack instead of recursing, so depth is limited only
/// by the input, and it looks at no map key.
pub(crate) fn skip_value(reader: &mut Reader<'_>) -> Result<(), ScanError> {
    let mut stack: Vec<Open> = Vec::new();
    let mut tagged = false;
    loop {
        let head = reader.head()?;
        let complete = match head {
            Head::Tag(_) => {
                tagged = true;
                continue;
            }
            Head::Break => {
                if tagged {
                    return Err(ScanError::Malformed);
                }
                match stack.last() {
                    Some(Open::IndefiniteArray | Open::IndefiniteMap { odd: false }) => {
                        stack.pop();
                        true
                    }
                    _ => return Err(ScanError::Malformed),
                }
            }
            Head::Unsigned(_) | Head::Negative(_) | Head::Float(_) | Head::Simple(_) => true,
            Head::Bytes(len) => {
                reader.string(false, len, None)?;
                true
            }
            Head::Text(len) => {
                reader.string(true, len, None)?;
                true
            }
            Head::Array(Some(0)) | Head::Map(Some(0)) => true,
            Head::Array(Some(len)) => {
                stack.push(Open::Items(items_that_fit(reader, Some(len))?));
                false
            }
            Head::Map(Some(len)) => {
                stack.push(Open::Items(items_that_fit(reader, len.checked_mul(2))?));
                false
            }
            Head::Array(None) => {
                stack.push(Open::IndefiniteArray);
                false
            }
            Head::Map(None) => {
                stack.push(Open::IndefiniteMap { odd: false });
                false
            }
        };
        tagged = false;
        if !complete {
            continue;
        }
        // The item just read completes its parent's next slot, and a parent
        // that is now full is itself a completed item of its own parent.
        loop {
            match stack.last_mut() {
                None => return Ok(()),
                Some(Open::Items(left)) => {
                    *left = left.saturating_sub(1);
                    if *left > 0 {
                        break;
                    }
                    stack.pop();
                }
                Some(Open::IndefiniteArray) => break,
                Some(Open::IndefiniteMap { odd }) => {
                    *odd = !*odd;
                    break;
                }
            }
        }
    }
}

/// Returns a declared item count, failing when the input could not hold
/// that many items, at least one byte each.
fn items_that_fit(reader: &Reader<'_>, count: Option<u64>) -> Result<u64, ScanError> {
    let count = count.ok_or(ScanError::Malformed)?;
    let remaining = u64::try_from(reader.remaining()).map_err(|_| ScanError::Malformed)?;
    if count > remaining {
        return Err(ScanError::Malformed);
    }
    Ok(count)
}

/// Checks that `bytes` hold exactly one well-formed data item, with no
/// limit on depth and no look at map keys.
pub(crate) fn check_well_formed(bytes: &[u8]) -> Result<(), ScanError> {
    let mut reader = Reader::new(bytes);
    skip_value(&mut reader)?;
    if reader.is_at_end() {
        Ok(())
    } else {
        Err(ScanError::TrailingBytes)
    }
}

/// Checks that `bytes` hold exactly one well-formed data item, nested no
/// deeper than [`MAX_DEPTH`], in which no map at any depth holds the same
/// key twice.
pub(crate) fn check_body(bytes: &[u8]) -> Result<(), ScanError> {
    let mut reader = Reader::new(bytes);
    check_value(&mut reader, 0, None)?;
    if reader.is_at_end() {
        Ok(())
    } else {
        Err(ScanError::TrailingBytes)
    }
}

/// Appends a head with the shortest argument encoding.
pub(crate) fn put_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let major = major << 5;
    if let Ok(small) = u8::try_from(value) {
        if small < 24 {
            out.push(major | small);
        } else {
            out.extend_from_slice(&[major | 24, small]);
        }
    } else if let Ok(value) = u16::try_from(value) {
        out.push(major | 25);
        out.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        out.push(major | 26);
        out.extend_from_slice(&value.to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

/// Appends a head with an eight-byte argument to be filled in by
/// [`patch_length`], returning where that argument sits.
fn put_length_slot(out: &mut Vec<u8>, major: u8) -> usize {
    out.push((major << 5) | 27);
    let slot = out.len();
    out.extend_from_slice(&[0; 8]);
    slot
}

fn patch_length(out: &mut [u8], slot: usize, value: usize) -> Result<(), ScanError> {
    let value = u64::try_from(value).map_err(|_| ScanError::Malformed)?;
    let target = out.get_mut(slot..slot + 8).ok_or(ScanError::Malformed)?;
    target.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Reads one data item, checking every map in it for duplicate keys, and
/// appends its canonical form to `canonical` when one is given.
///
/// The canonical form decides when two keys are the same key. Integers
/// compare by value, whether written as a major type 0 or 1 item of any
/// width or as a bignum (tags 2 and 3) of any number of leading zeros.
/// Byte and text strings compare by content, whether written at a definite
/// length or in chunks. Floats of any width compare by the bits of the
/// `f64` they widen to. Simple values compare by number, so `false`,
/// `true` and `null` compare by value. Arrays and maps compare element by
/// element in order, and other tags by number and content. An integer
/// never equals a float, nor a text string a byte string.
///
/// Every number in the canonical form is written at its shortest, and
/// every length and count at a fixed eight bytes, so the form is
/// self-delimiting and two items share it exactly when they are the same
/// key.
fn check_value(
    reader: &mut Reader<'_>,
    depth: usize,
    mut canonical: Option<&mut Vec<u8>>,
) -> Result<(), ScanError> {
    let mut head = reader.head()?;
    while let Head::Tag(tag) = head {
        head = reader.head()?;
        if matches!(tag, TAG_BIGNUM_POSITIVE | TAG_BIGNUM_NEGATIVE)
            && let Head::Bytes(len) = head
        {
            return bignum(reader, tag == TAG_BIGNUM_NEGATIVE, len, canonical);
        }
        if let Some(out) = canonical.as_deref_mut() {
            put_head(out, MAJOR_TAG, tag);
        }
    }
    match head {
        Head::Tag(_) | Head::Break => Err(ScanError::Malformed),
        Head::Unsigned(value) => {
            if let Some(out) = canonical {
                put_head(out, MAJOR_UNSIGNED, value);
            }
            Ok(())
        }
        Head::Negative(value) => {
            if let Some(out) = canonical {
                put_head(out, MAJOR_NEGATIVE, value);
            }
            Ok(())
        }
        Head::Float(bits) => {
            if let Some(out) = canonical {
                out.push(FLOAT64);
                out.extend_from_slice(&bits.to_be_bytes());
            }
            Ok(())
        }
        Head::Simple(value) => {
            if let Some(out) = canonical {
                put_head(out, MAJOR_SIMPLE, u64::from(value));
            }
            Ok(())
        }
        Head::Bytes(len) => string(reader, false, len, canonical),
        Head::Text(len) => string(reader, true, len, canonical),
        Head::Array(len) => {
            let depth = deeper(depth)?;
            let slot = canonical
                .as_deref_mut()
                .map(|out| put_length_slot(out, MAJOR_ARRAY));
            let mut count = 0usize;
            while !at_container_end(reader, len, count) {
                check_value(reader, depth, canonical.as_deref_mut())?;
                count += 1;
            }
            if let (Some(out), Some(slot)) = (canonical, slot) {
                patch_length(out, slot, count)?;
            }
            Ok(())
        }
        Head::Map(len) => map(reader, deeper(depth)?, len, canonical),
    }
}

fn deeper(depth: usize) -> Result<usize, ScanError> {
    if depth >= MAX_DEPTH {
        Err(ScanError::TooDeep)
    } else {
        Ok(depth + 1)
    }
}

/// Reports whether a container has no more items: its declared count is
/// reached, or, for an indefinite length, a break comes next (and is
/// consumed).
fn at_container_end(reader: &mut Reader<'_>, len: Option<u64>, count: usize) -> bool {
    match len {
        Some(len) => u64::try_from(count).is_ok_and(|count| count >= len),
        None => reader.eat_break(),
    }
}

fn string(
    reader: &mut Reader<'_>,
    text: bool,
    len: Option<u64>,
    canonical: Option<&mut Vec<u8>>,
) -> Result<(), ScanError> {
    let Some(out) = canonical else {
        return reader.string(text, len, None);
    };
    let slot = put_length_slot(out, if text { MAJOR_TEXT } else { MAJOR_BYTES });
    let start = out.len();
    reader.string(text, len, Some(out))?;
    let written = out.len() - start;
    patch_length(out, slot, written)
}

fn bignum(
    reader: &mut Reader<'_>,
    negative: bool,
    len: Option<u64>,
    canonical: Option<&mut Vec<u8>>,
) -> Result<(), ScanError> {
    let Some(out) = canonical else {
        return reader.string(false, len, None);
    };
    let mut digits = Vec::new();
    reader.string(false, len, Some(&mut digits))?;
    let significant = digits
        .iter()
        .position(|&digit| digit != 0)
        .map_or(&[][..], |first| digits.get(first..).unwrap_or_default());
    if significant.len() <= 8 {
        let mut word = [0u8; 8];
        let offset = 8 - significant.len();
        if let Some(target) = word.get_mut(offset..) {
            target.copy_from_slice(significant);
        }
        let major = if negative {
            MAJOR_NEGATIVE
        } else {
            MAJOR_UNSIGNED
        };
        put_head(out, major, u64::from_be_bytes(word));
    } else {
        let tag = if negative {
            TAG_BIGNUM_NEGATIVE
        } else {
            TAG_BIGNUM_POSITIVE
        };
        put_head(out, MAJOR_TAG, tag);
        let slot = put_length_slot(out, MAJOR_BYTES);
        out.extend_from_slice(significant);
        patch_length(out, slot, significant.len())?;
    }
    Ok(())
}

/// Reads the pairs of a map whose head has just been read, and fails when
/// two of its keys are the same.
///
/// Each key's canonical form is written to a buffer and its place there
/// recorded; sorting the places by content then brings equal keys next to
/// each other. That is O(n log n) comparisons for n keys, never O(n²).
fn map(
    reader: &mut Reader<'_>,
    depth: usize,
    len: Option<u64>,
    canonical: Option<&mut Vec<u8>>,
) -> Result<(), ScanError> {
    let mut own = Vec::new();
    // Inside a key, the map's canonical form, keys and values alike, is
    // part of that key's and goes where the key's does; elsewhere only the
    // keys are needed, in a buffer of the map's own.
    let in_key = canonical.is_some();
    let keys: &mut Vec<u8> = match canonical {
        Some(out) => out,
        None => &mut own,
    };
    let slot = in_key.then(|| put_length_slot(keys, MAJOR_MAP));
    let mut places: Vec<(usize, usize)> = Vec::new();
    while !at_container_end(reader, len, places.len()) {
        let start = keys.len();
        check_value(reader, depth, Some(&mut *keys))?;
        places.push((start, keys.len()));
        if in_key {
            check_value(reader, depth, Some(&mut *keys))?;
        } else {
            check_value(reader, depth, None)?;
        }
    }
    let key = |&(start, end): &(usize, usize)| keys.get(start..end).unwrap_or_default();
    places.sort_unstable_by(|a, b| key(a).cmp(key(b)));
    if places
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if key(a) == key(b)))
    {
        return Err(ScanError::DuplicateKey);
    }
    if let Some(slot) = slot {
        let count = places.len();
        patch_length(keys, slot, count)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(bytes: &[u8]) -> Result<(), ScanError> {
        check_body(bytes)
    }

    #[test]
    fn well_formed_values_pass() {
        for bytes in [
            &[0x00][..],
            &[0x18, 0x18],
            &[0x3b, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0x43, 1, 2, 3],
            &[0x5f, 0x41, 1, 0x42, 2, 3, 0xff],
            &[0x63, b'a', b'b', b'c'],
            &[0x7f, 0x61, b'a', 0xff],
            &[0x82, 0x01, 0x02],
            &[0x9f, 0x01, 0x9f, 0xff, 0xff],
            &[0xa1, 0x61, b'a', 0x01],
            &[0xbf, 0x61, b'a', 0x01, 0xff],
            &[0xc1, 0x1a, 0, 0, 0, 1],
            &[0xf9, 0x3c, 0x00],
            &[0xf4],
            &[0xf8, 0x20],
        ] {
            assert_eq!(check_well_formed(bytes), Ok(()), "{bytes:02x?}");
            assert_eq!(body(bytes), Ok(()), "{bytes:02x?}");
        }
    }

    #[test]
    fn malformed_values_fail() {
        for bytes in [
            &[][..],
            &[0x18],
            &[0x1c],
            &[0x1f],
            &[0x3f],
            &[0xdf],
            &[0xff],
            &[0x43, 1, 2],
            &[0x62, 0xff, 0xfe],
            &[0x5f, 0x61, b'a', 0xff],
            &[0x7f, 0x41, b'a', 0xff],
            &[0x5f, 0x5f, 0xff, 0xff],
            &[0x82, 0x01],
            &[0x9f, 0x01],
            &[0xa1, 0x01],
            &[0xbf, 0x01, 0xff],
            &[0x81, 0xff],
            &[0x9f, 0xc1, 0xff],
            &[0xf8, 0x1f],
            &[0xfc],
        ] {
            assert_eq!(
                check_well_formed(bytes),
                Err(ScanError::Malformed),
                "{bytes:02x?}"
            );
            assert_eq!(body(bytes), Err(ScanError::Malformed), "{bytes:02x?}");
        }
    }

    #[test]
    fn trailing_bytes_fail() {
        assert_eq!(
            check_well_formed(&[0x01, 0x02]),
            Err(ScanError::TrailingBytes)
        );
        assert_eq!(body(&[0x01, 0x02]), Err(ScanError::TrailingBytes));
    }

    #[test]
    fn declared_lengths_past_the_input_fail_without_allocating() {
        // A byte string, a text string, an array and a map each declaring
        // 2³²−1 or 2⁶⁴−1 of something, followed by a few bytes.
        for bytes in [
            &[0x5a, 0xff, 0xff, 0xff, 0xff, 1, 2, 3][..],
            &[0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1],
            &[0x9a, 0xff, 0xff, 0xff, 0xff, 1, 2, 3],
            &[0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 2],
        ] {
            assert_eq!(check_well_formed(bytes), Err(ScanError::Malformed));
            assert_eq!(body(bytes), Err(ScanError::Malformed));
        }
    }

    #[test]
    fn deep_nesting_is_well_formed_but_too_deep_for_a_body() {
        let mut bytes = vec![0x81; 100_000];
        bytes.push(0x00);
        assert_eq!(check_well_formed(&bytes), Ok(()));
        assert_eq!(body(&bytes), Err(ScanError::TooDeep));

        let mut shallow = vec![0x81; MAX_DEPTH];
        shallow.push(0x00);
        assert_eq!(body(&shallow), Ok(()));
    }

    #[test]
    fn duplicate_keys_fail_at_any_depth() {
        // {"a": 1, "a": 2}
        assert_eq!(
            body(&[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02]),
            Err(ScanError::DuplicateKey)
        );
        // [{"x": {"a": 1, "a": 2}}]
        assert_eq!(
            body(&[
                0x81, 0xa1, 0x61, b'x', 0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02
            ]),
            Err(ScanError::DuplicateKey)
        );
        // A duplicate inside a map used as a key: {{1: 0, 1: 0}: 0}
        assert_eq!(
            body(&[0xa1, 0xa2, 0x01, 0x00, 0x01, 0x00, 0x00]),
            Err(ScanError::DuplicateKey)
        );
        // Distinct keys pass, and the well-formedness scan ignores keys.
        assert_eq!(body(&[0xa2, 0x61, b'a', 0x01, 0x61, b'b', 0x02]), Ok(()));
        assert_eq!(
            check_well_formed(&[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02]),
            Ok(())
        );
    }

    #[test]
    fn key_equality_follows_values_not_encodings() {
        let same = [
            // 1 and 1 written in a wider argument.
            (&[0x01][..], &[0x18, 0x01][..]),
            // −1 and −1 written in a wider argument.
            (&[0x20], &[0x39, 0x00, 0x00]),
            // 1 and the bignum 1, with a leading zero.
            (&[0x01], &[0xc2, 0x42, 0x00, 0x01]),
            // −1 and the negative bignum 0.
            (&[0x20], &[0xc3, 0x40]),
            // "ab" and "ab" in chunks.
            (&[0x62, b'a', b'b'], &[0x7f, 0x61, b'a', 0x61, b'b', 0xff]),
            // h'01' and h'01' in chunks.
            (&[0x41, 0x01], &[0x5f, 0x41, 0x01, 0xff]),
            // 1.0 as a half and as a double.
            (&[0xf9, 0x3c, 0x00], &[0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0]),
            // [1, 2] at a definite and an indefinite length.
            (&[0x82, 0x01, 0x02], &[0x9f, 0x01, 0x02, 0xff]),
            // {1: 2} at a definite and an indefinite length.
            (&[0xa1, 0x01, 0x02], &[0xbf, 0x01, 0x02, 0xff]),
            // null and null.
            (&[0xf6], &[0xf6]),
        ];
        for (a, b) in same {
            let mut map = vec![0xa2];
            map.extend_from_slice(a);
            map.push(0x00);
            map.extend_from_slice(b);
            map.push(0x00);
            assert_eq!(
                body(&map),
                Err(ScanError::DuplicateKey),
                "{a:02x?} {b:02x?}"
            );
        }

        let different = [
            // 1 and 1.0.
            (&[0x01][..], &[0xf9, 0x3c, 0x00][..]),
            // "a" and h'61'.
            (&[0x61, b'a'], &[0x41, b'a']),
            // 0.0 and −0.0.
            (&[0xf9, 0x00, 0x00], &[0xf9, 0x80, 0x00]),
            // false and true; null and undefined.
            (&[0xf4], &[0xf5]),
            (&[0xf6], &[0xf7]),
            // 1 and −1.
            (&[0x01], &[0x20]),
            // {1: 2, 3: 4} and {3: 4, 1: 2}.
            (
                &[0xa2, 0x01, 0x02, 0x03, 0x04],
                &[0xa2, 0x03, 0x04, 0x01, 0x02],
            ),
            // [1, 2] and [2, 1].
            (&[0x82, 0x01, 0x02], &[0x82, 0x02, 0x01]),
            // 1 and tag 1 over 1.
            (&[0x01], &[0xc1, 0x01]),
            // "a" and ["a"].
            (&[0x61, b'a'], &[0x81, 0x61, b'a']),
        ];
        for (a, b) in different {
            let mut map = vec![0xa2];
            map.extend_from_slice(a);
            map.push(0x00);
            map.extend_from_slice(b);
            map.push(0x00);
            assert_eq!(body(&map), Ok(()), "{a:02x?} {b:02x?}");
        }
    }

    #[test]
    fn many_distinct_keys_pass() {
        // 50,000 distinct unsigned keys: a quadratic check would take
        // billions of comparisons.
        let count: u16 = 50_000;
        let mut bytes = vec![0xb9];
        bytes.extend_from_slice(&count.to_be_bytes());
        for key in 0..count {
            bytes.push(0x19);
            bytes.extend_from_slice(&key.to_be_bytes());
            bytes.push(0xf6);
        }
        assert_eq!(body(&bytes), Ok(()));
        bytes.push(0x19);
        bytes.extend_from_slice(&7u16.to_be_bytes());
        bytes.push(0xf6);
        if let Some(head) = bytes.get_mut(1..3) {
            head.copy_from_slice(&(count + 1).to_be_bytes());
        }
        assert_eq!(body(&bytes), Err(ScanError::DuplicateKey));
    }

    #[test]
    fn half_floats_widen_exactly() {
        assert_eq!(half_to_f64(0x3c00), 1.0);
        assert_eq!(half_to_f64(0xc000), -2.0);
        assert_eq!(half_to_f64(0x7bff), 65504.0);
        assert_eq!(half_to_f64(0x0001), 2f64.powi(-24));
        assert_eq!(half_to_f64(0x8000).to_bits(), (-0.0f64).to_bits());
        assert_eq!(half_to_f64(0x7c00), f64::INFINITY);
        assert!(half_to_f64(0x7e00).is_nan());
    }
}
