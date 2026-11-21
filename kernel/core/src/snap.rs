//! A compact binary encoding of kernel state, for warm clones on a
//! platform whose clones cannot be forks of the template's kernel process
//! (Hypervisor.framework on macOS: a VM does not survive `fork`). The
//! frozen template writes its kernel state with [`Snap::put`]; the clone's
//! kernel process, a new process, reads it back with [`Snap::get`]. See
//! `Kernel::save_frozen` and README, "Warm clones on macOS".
//!
//! The format is the fields in declaration order: integers little endian,
//! `bool` one byte (0 or 1), sequences and maps a `u64` count and the
//! items (maps sorted by key, so that one state always gives the same
//! bytes), `Option` and enums a tag byte and the fields of the variant.
//! It is private to one build of hellovm: the template and its clones run
//! the same binary, and a snapshot starts with a fingerprint of it.
//!
//! Reading never panics and never allocates more than the input could
//! hold: every count is checked against the bytes left, and anything that
//! does not parse is an error. What it does not check is that the state is
//! consistent (that every fd names an open file, say): the snapshot comes
//! from the template, which every clone trusts already (see the README).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::time::Duration;

/// Why a snapshot could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bad(pub String);

impl fmt::Display for Bad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed kernel snapshot: {}", self.0)
    }
}

impl std::error::Error for Bad {}

pub(crate) fn bad<T>(what: impl Into<String>) -> Result<T, Bad> {
    Err(Bad(what.into()))
}

/// The output: a growing buffer, or a fixed one (the snapshot's memory)
/// that nothing is allocated for. A process that writes its snapshot
/// after it confined itself must not grow large allocations: on macOS a
/// large `realloc` copies with a Mach call the confined process may not
/// make.
pub struct Writer<'a> {
    sink: Sink<'a>,
    len: usize,
}

enum Sink<'a> {
    Owned(Vec<u8>),
    Fixed(&'a mut [u8]),
}

impl Default for Writer<'_> {
    fn default() -> Self {
        Writer {
            sink: Sink::Owned(Vec::new()),
            len: 0,
        }
    }
}

impl<'a> Writer<'a> {
    pub fn new() -> Writer<'a> {
        Writer::default()
    }

    /// A writer into `buf`: what does not fit is counted, not written
    /// (see [`Writer::written`]).
    pub fn into_slice(buf: &'a mut [u8]) -> Writer<'a> {
        Writer {
            sink: Sink::Fixed(buf),
            len: 0,
        }
    }

    pub fn bytes(&mut self, data: &[u8]) {
        match &mut self.sink {
            Sink::Owned(buf) => buf.extend_from_slice(data),
            Sink::Fixed(buf) => {
                if let Some(dst) = buf.get_mut(self.len..self.len + data.len()) {
                    dst.copy_from_slice(data);
                }
            }
        }
        self.len += data.len();
    }

    /// The bytes written (a growing buffer's; empty for a fixed one).
    pub fn into_inner(self) -> Vec<u8> {
        match self.sink {
            Sink::Owned(buf) => buf,
            Sink::Fixed(_) => Vec::new(),
        }
    }

    /// How many bytes were written: `Err` with how many there were for a
    /// fixed buffer they did not fit.
    pub fn written(&self) -> Result<usize, usize> {
        match &self.sink {
            Sink::Fixed(buf) if self.len > buf.len() => Err(self.len),
            _ => Ok(self.len),
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// The input.
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf }
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Bad> {
        if n > self.buf.len() {
            return bad("truncated");
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    pub fn remaining(&self) -> usize {
        self.buf.len()
    }

    /// A count of items that each take at least one byte: never more than
    /// the bytes left.
    pub fn count(&mut self) -> Result<usize, Bad> {
        let n = u64::get(self)?;
        if n > self.buf.len() as u64 {
            return bad(format!("a count of {n} with {} bytes left", self.buf.len()));
        }
        Ok(n as usize)
    }

    /// Fails unless everything was read.
    pub fn finish(self) -> Result<(), Bad> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            bad(format!("{} bytes left over", self.buf.len()))
        }
    }
}

/// A value that can be written to and read from a snapshot.
pub trait Snap: Sized {
    fn put(&self, w: &mut Writer);
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad>;

    /// Writes a slice of values (one by one, unless the type knows better).
    fn put_slice(items: &[Self], w: &mut Writer) {
        for item in items {
            item.put(w);
        }
    }

    /// Reads `n` values, `n` already checked against the input.
    fn get_vec(r: &mut Reader<'_>, n: usize) -> Result<Vec<Self>, Bad> {
        let mut out = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            out.push(Self::get(r)?);
        }
        Ok(out)
    }
}

macro_rules! int {
    ($($t:ty),*) => {$(
        impl Snap for $t {
            fn put(&self, w: &mut Writer) {
                w.bytes(&self.to_le_bytes());
            }
            fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
                let bytes = r.take(std::mem::size_of::<$t>())?;
                let mut raw = [0u8; std::mem::size_of::<$t>()];
                raw.copy_from_slice(bytes);
                Ok(<$t>::from_le_bytes(raw))
            }
        }
    )*};
}

int!(u16, u32, u64, u128, i32, i64);

impl Snap for u8 {
    fn put(&self, w: &mut Writer) {
        w.bytes(&[*self]);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        Ok(r.take(1)?[0])
    }
    fn put_slice(items: &[Self], w: &mut Writer) {
        w.bytes(items);
    }
    fn get_vec(r: &mut Reader<'_>, n: usize) -> Result<Vec<Self>, Bad> {
        Ok(r.take(n)?.to_vec())
    }
}

impl Snap for usize {
    fn put(&self, w: &mut Writer) {
        (*self as u64).put(w);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        let v = u64::get(r)?;
        usize::try_from(v).or_else(|_| bad("a size out of range"))
    }
}

impl Snap for bool {
    fn put(&self, w: &mut Writer) {
        (*self as u8).put(w);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        match u8::get(r)? {
            0 => Ok(false),
            1 => Ok(true),
            other => bad(format!("a bool of {other}")),
        }
    }
}

impl Snap for Duration {
    fn put(&self, w: &mut Writer) {
        self.as_secs().put(w);
        self.subsec_nanos().put(w);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        let secs = u64::get(r)?;
        let nanos = u32::get(r)?;
        if nanos >= 1_000_000_000 {
            return bad("a duration's nanoseconds out of range");
        }
        Ok(Duration::new(secs, nanos))
    }
}

impl Snap for String {
    fn put(&self, w: &mut Writer) {
        self.len().put(w);
        w.bytes(self.as_bytes());
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        let n = r.count()?;
        String::from_utf8(r.take(n)?.to_vec()).or_else(|_| bad("a string that is not UTF-8"))
    }
}

impl<T: Snap> Snap for Vec<T> {
    fn put(&self, w: &mut Writer) {
        self.len().put(w);
        T::put_slice(self, w);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        let n = r.count()?;
        T::get_vec(r, n)
    }
}

impl<T: Snap> Snap for VecDeque<T> {
    fn put(&self, w: &mut Writer) {
        self.len().put(w);
        let (a, b) = self.as_slices();
        T::put_slice(a, w);
        T::put_slice(b, w);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        Ok(Vec::<T>::get(r)?.into())
    }
}

impl<T: Snap> Snap for Box<T> {
    fn put(&self, w: &mut Writer) {
        (**self).put(w);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        Ok(Box::new(T::get(r)?))
    }
}

impl<T: Snap> Snap for Option<T> {
    fn put(&self, w: &mut Writer) {
        match self {
            None => 0u8.put(w),
            Some(v) => {
                1u8.put(w);
                v.put(w);
            }
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        match u8::get(r)? {
            0 => Ok(None),
            1 => Ok(Some(T::get(r)?)),
            other => bad(format!("an option tag of {other}")),
        }
    }
}

impl<T: Snap, const N: usize> Snap for [T; N] {
    fn put(&self, w: &mut Writer) {
        T::put_slice(self, w);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        let items = T::get_vec(r, N)?;
        items
            .try_into()
            .or_else(|_| bad("an array of the wrong length"))
    }
}

impl<A: Snap, B: Snap> Snap for (A, B) {
    fn put(&self, w: &mut Writer) {
        self.0.put(w);
        self.1.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        Ok((A::get(r)?, B::get(r)?))
    }
}

impl<A: Snap, B: Snap, C: Snap> Snap for (A, B, C) {
    fn put(&self, w: &mut Writer) {
        self.0.put(w);
        self.1.put(w);
        self.2.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        Ok((A::get(r)?, B::get(r)?, C::get(r)?))
    }
}

impl<K: Snap + Ord, V: Snap> Snap for BTreeMap<K, V> {
    fn put(&self, w: &mut Writer) {
        self.len().put(w);
        for (k, v) in self {
            k.put(w);
            v.put(w);
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        let n = r.count()?;
        let mut map = BTreeMap::new();
        for _ in 0..n {
            let k = K::get(r)?;
            let v = V::get(r)?;
            if map.insert(k, v).is_some() {
                return bad("a key twice in a map");
            }
        }
        Ok(map)
    }
}

impl<K: Snap + Ord> Snap for BTreeSet<K> {
    fn put(&self, w: &mut Writer) {
        self.len().put(w);
        for k in self {
            k.put(w);
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        let n = r.count()?;
        let mut set = BTreeSet::new();
        for _ in 0..n {
            if !set.insert(K::get(r)?) {
                return bad("a key twice in a set");
            }
        }
        Ok(set)
    }
}

impl<K: Snap + Ord + std::hash::Hash, V: Snap> Snap for HashMap<K, V> {
    fn put(&self, w: &mut Writer) {
        self.len().put(w);
        let mut entries: Vec<(&K, &V)> = self.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in entries {
            k.put(w);
            v.put(w);
        }
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Bad> {
        let n = r.count()?;
        let mut map = HashMap::with_capacity(n.min(4096));
        for _ in 0..n {
            let k = K::get(r)?;
            let v = V::get(r)?;
            if map.insert(k, v).is_some() {
                return bad("a key twice in a map");
            }
        }
        Ok(map)
    }
}

/// `impl Snap` for a struct with named fields: the fields in the order
/// given, which must be all of them.
#[macro_export]
#[doc(hidden)]
macro_rules! snap_struct {
    ($t:ty { $($f:ident),* $(,)? }) => {
        impl $crate::snap::Snap for $t {
            fn put(&self, w: &mut $crate::snap::Writer) {
                $( $crate::snap::Snap::put(&self.$f, w); )*
            }
            fn get(r: &mut $crate::snap::Reader<'_>) -> Result<Self, $crate::snap::Bad> {
                Ok(Self { $( $f: $crate::snap::Snap::get(r)?, )* })
            }
        }
    };
}

/// `impl Snap` for a struct with one unnamed field.
#[macro_export]
#[doc(hidden)]
macro_rules! snap_newtype {
    ($t:ident) => {
        impl $crate::snap::Snap for $t {
            fn put(&self, w: &mut $crate::snap::Writer) {
                $crate::snap::Snap::put(&self.0, w);
            }
            fn get(r: &mut $crate::snap::Reader<'_>) -> Result<Self, $crate::snap::Bad> {
                Ok($t($crate::snap::Snap::get(r)?))
            }
        }
    };
}

/// `impl Snap` for an enum: each variant with its tag byte and its fields,
/// unnamed (`V(a, b)`) or named (`V { a, b }`), every variant listed.
#[macro_export]
#[doc(hidden)]
macro_rules! snap_enum {
    ($t:ident { $($tag:literal => $v:ident $(($($tf:ident),*))? $({$($sf:ident),*})?),* $(,)? }) => {
        impl $crate::snap::Snap for $t {
            fn put(&self, w: &mut $crate::snap::Writer) {
                match self {
                    $(
                        $t::$v $(($($tf),*))? $({$($sf),*})? => {
                            $crate::snap::Snap::put(&($tag as u8), w);
                            $($( $crate::snap::Snap::put($tf, w); )*)?
                            $($( $crate::snap::Snap::put($sf, w); )*)?
                        }
                    )*
                }
            }
            fn get(r: &mut $crate::snap::Reader<'_>) -> Result<Self, $crate::snap::Bad> {
                let tag = <u8 as $crate::snap::Snap>::get(r)?;
                $(
                    if tag == $tag {
                        return Ok($t::$v
                            $(($({
                                let $tf = $crate::snap::Snap::get(r)?;
                                $tf
                            }),*))?
                            $({$(
                                $sf: $crate::snap::Snap::get(r)?,
                            )*})?);
                    }
                )*
                Err($crate::snap::Bad(format!(
                    "{} has no variant {tag}",
                    stringify!($t)
                )))
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round<T: Snap + PartialEq + fmt::Debug>(v: T) {
        let mut w = Writer::new();
        v.put(&mut w);
        let bytes = w.into_inner();
        let mut r = Reader::new(&bytes);
        assert_eq!(T::get(&mut r).unwrap(), v);
        r.finish().unwrap();
        // Every cut is an error, not a panic.
        for cut in 0..bytes.len() {
            let mut r = Reader::new(&bytes[..cut]);
            assert!(T::get(&mut r).is_err(), "{cut}");
        }
    }

    #[derive(Debug, PartialEq)]
    enum E {
        A,
        B(u32, Vec<u8>),
        C { x: Option<u64>, y: bool },
    }
    snap_enum!(E { 0 => A, 1 => B(a, b), 2 => C { x, y } });

    #[derive(Debug, PartialEq)]
    struct S {
        a: u16,
        e: Vec<E>,
        m: BTreeMap<u32, String>,
        h: HashMap<u64, (u8, i64)>,
        d: VecDeque<u8>,
        t: Duration,
        arr: [u32; 3],
    }
    snap_struct!(S {
        a,
        e,
        m,
        h,
        d,
        t,
        arr
    });

    #[test]
    fn values_round_trip_and_cuts_fail() {
        round(S {
            a: 7,
            e: vec![
                E::A,
                E::B(3, b"xyz".to_vec()),
                E::C {
                    x: Some(9),
                    y: true,
                },
            ],
            m: [(1, "one".to_string()), (2, "two".to_string())].into(),
            h: [(5, (1, -1)), (3, (2, -2))].into(),
            d: [1, 2, 3].into(),
            t: Duration::new(5, 6),
            arr: [1, 2, 3],
        });
    }

    #[test]
    fn hostile_counts_and_tags_are_errors() {
        // A count far beyond the input allocates nothing.
        let mut w = Writer::new();
        u64::MAX.put(&mut w);
        let bytes = w.into_inner();
        assert!(<Vec<u64> as Snap>::get(&mut Reader::new(&bytes)).is_err());
        assert!(E::get(&mut Reader::new(&[9])).is_err());
        assert!(bool::get(&mut Reader::new(&[2])).is_err());
        let mut w = Writer::new();
        1u64.put(&mut w);
        2_000_000_000u32.put(&mut w);
        assert!(Duration::get(&mut Reader::new(&w.into_inner())).is_err());
        // Duplicate map keys.
        let mut w = Writer::new();
        2u64.put(&mut w);
        for _ in 0..2 {
            1u32.put(&mut w);
            "a".to_string().put(&mut w);
        }
        assert!(<BTreeMap<u32, String> as Snap>::get(&mut Reader::new(&w.into_inner())).is_err());
    }

    #[test]
    fn a_fixed_buffer_takes_what_fits_and_counts_the_rest() {
        let mut buf = [0u8; 6];
        let mut w = Writer::into_slice(&mut buf);
        1u32.put(&mut w);
        assert_eq!(w.written(), Ok(4));
        2u32.put(&mut w);
        assert_eq!(w.written(), Err(8));
        assert_eq!(buf, [1, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn hash_maps_encode_in_key_order() {
        let a: HashMap<u64, u8> = (0..100).map(|i| (i, i as u8)).collect();
        let b: HashMap<u64, u8> = (0..100).rev().map(|i| (i, i as u8)).collect();
        let (mut wa, mut wb) = (Writer::new(), Writer::new());
        a.put(&mut wa);
        b.put(&mut wb);
        assert_eq!(wa.into_inner(), wb.into_inner());
    }
}
