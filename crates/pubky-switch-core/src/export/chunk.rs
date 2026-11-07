//! Export chunks (Switch wire 10.3): the exact bytes of one JSON document holding
//! consecutive parts, and how the old service packs an account's parts into them (Switch
//! wire 10.2 "Packing").

use serde_json::Value;

use super::manifest::ChunkRef;
use super::part::Part;
use super::{CHUNK_KIND, MAX_CHUNK_BYTES, bad, reason};
use crate::enc::hash;
use crate::error::Result;
use crate::http::ErrorCode;
use crate::json::{Doc, MAX_INT, parse_json_as};
use crate::ops::Refusal;

/// A chunk (Switch wire 10.3): `v`, `kind`, its `index` in the manifest's `chunks`, the
/// `first` part's index, and its consecutive `parts`.
#[derive(Clone, Debug, PartialEq)]
pub struct Chunk {
    /// Its position in the manifest's `chunks`.
    pub index: u64,
    /// The index of its first part.
    pub first: u64,
    /// Its parts.
    pub parts: Vec<Part>,
}

/// The chunk ID the old service gives the chunk at `index`: the index as five decimal digits
/// (Switch wire 10.2). IDs are opaque to the next service, which takes them from the
/// manifest.
pub fn chunk_id(index: u64) -> String {
    format!("{index:05}")
}

/// The bytes a chunk's own members take around its parts: `{"v":1,"kind":
/// "pubky-switch.export_chunk","index":i,"first":f,"parts":[` and `]}` (Switch wire 10.3
/// "Part sizes"), at most [`super::MAX_CHUNK_OVERHEAD`].
pub fn chunk_overhead(index: u64, first: u64) -> usize {
    frame(index, first, &[]).len()
}

fn frame(index: u64, first: u64, parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out =
        format!(r#"{{"v":1,"kind":"{CHUNK_KIND}","index":{index},"first":{first},"parts":["#)
            .into_bytes();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(part);
    }
    out.extend_from_slice(b"]}");
    out
}

impl Chunk {
    /// The chunk's exact JSON bytes.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] as [`Part::to_json`].
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let parts = self
            .parts
            .iter()
            .map(Part::to_json)
            .collect::<Result<Vec<_>>>()?;
        Ok(frame(self.index, self.first, &parts))
    }

    /// Read a chunk's own members and its parts as JSON values: strict JSON whose opaque
    /// members are the parts' invite code contexts (Switch wire 1.1), `v` 1 and `kind`
    /// [`CHUNK_KIND`].
    fn read_values(bytes: &[u8]) -> std::result::Result<(u64, u64, Vec<Value>), Refusal> {
        let fail = |why: &str| Err(bad(format!("Switch wire 10.3: {why}")));
        let v: Value = parse_json_as(bytes, Doc::ExportChunk).map_err(|e| bad(reason(e)))?;
        if v.get("v").and_then(Value::as_u64) != Some(1)
            || v.get("kind").and_then(Value::as_str) != Some(CHUNK_KIND)
        {
            return fail("a chunk's v or kind");
        }
        let int = |member: &str| {
            v.get(member)
                .and_then(Value::as_u64)
                .filter(|n| *n <= MAX_INT)
        };
        let (Some(index), Some(first)) = (int("index"), int("first")) else {
            return fail("a chunk's index or first isn't an integer");
        };
        let Some(Value::Array(parts)) = v.get("parts").cloned() else {
            return fail("a chunk's parts aren't an array");
        };
        Ok((index, first, parts))
    }

    /// Read a chunk's `index`, `first` and number of parts, without reading the parts, as
    /// `PUT /import/chunks` checks a chunk (Switch wire 10.4).
    ///
    /// # Errors
    ///
    /// `400 bad_request` if it doesn't read as a chunk.
    pub fn read_frame(bytes: &[u8]) -> std::result::Result<(u64, u64, usize), Refusal> {
        let (index, first, parts) = Self::read_values(bytes)?;
        Ok((index, first, parts.len()))
    }

    /// Read a chunk and every part in it (Switch wire 10.3, 10.5 step 3).
    ///
    /// # Errors
    ///
    /// `400 bad_request` if it doesn't read as a chunk, or a part doesn't read.
    pub fn parse(bytes: &[u8]) -> std::result::Result<Self, Refusal> {
        let (index, first, values) = Self::read_values(bytes)?;
        let parts = values
            .iter()
            .enumerate()
            .map(|(i, v)| {
                Part::read(v).map_err(|e| {
                    bad(format!(
                        "Switch wire 10.5: part {i} of chunk {index} doesn't read: {}",
                        e.reason
                    ))
                })
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Self {
            index,
            first,
            parts,
        })
    }
}

/// Pack an account's parts, in the order of Switch wire 10.3, into chunks of up to `target`
/// bytes each, a part too large for that getting a chunk of its own (Switch wire 10.2
/// "Packing"). `target` is clamped to 1 MiB. Returns each chunk's reference, with IDs from
/// [`chunk_id`], and its bytes.
///
/// # Errors
///
/// `413 too_large` for a part that doesn't fit one chunk of 1 MiB with the chunk's own
/// members, which no part within the default caps does (Switch wire 10.3 "Part sizes"), and
/// `400` for a part that can't be written.
pub fn pack(
    parts: &[Part],
    target: usize,
) -> std::result::Result<Vec<(ChunkRef, Vec<u8>)>, Refusal> {
    let target = target.clamp(1, MAX_CHUNK_BYTES);
    let mut chunks = Vec::new();
    let mut current: Vec<Vec<u8>> = Vec::new();
    let mut first = 0u64;
    let mut size = 0usize;
    for (i, part) in parts.iter().enumerate() {
        let bytes = part.to_json().map_err(|e| bad(reason(e)))?;
        let index = u64::try_from(chunks.len()).map_err(|_| bad("too many chunks"))?;
        // The chunk's size with this part: its own members, the parts and their commas.
        let with = chunk_overhead(index, first)
            .saturating_add(size)
            .saturating_add(usize::from(!current.is_empty()))
            .saturating_add(bytes.len());
        if !current.is_empty() && with > target {
            close_chunk(&mut current, first, &mut chunks)?;
            first = u64::try_from(i).map_err(|_| bad("too many parts"))?;
            size = 0;
        }
        size = size
            .saturating_add(usize::from(!current.is_empty()))
            .saturating_add(bytes.len());
        current.push(bytes);
    }
    if !current.is_empty() {
        close_chunk(&mut current, first, &mut chunks)?;
    }
    Ok(chunks)
}

/// Close the chunk of `current`'s parts, from part `first`, as the next of `chunks`.
fn close_chunk(
    current: &mut Vec<Vec<u8>>,
    first: u64,
    chunks: &mut Vec<(ChunkRef, Vec<u8>)>,
) -> std::result::Result<(), Refusal> {
    let count = u64::try_from(current.len()).map_err(|_| bad("too many parts"))?;
    let index = u64::try_from(chunks.len()).map_err(|_| bad("too many chunks"))?;
    let bytes = frame(index, first, current);
    if bytes.len() > MAX_CHUNK_BYTES {
        return Err(Refusal::new(
            ErrorCode::TooLarge,
            "Switch wire 10.3: a part doesn't fit one chunk",
        ));
    }
    let reference = ChunkRef {
        id: chunk_id(index),
        len: u64::try_from(bytes.len()).map_err(|_| bad("a chunk's length"))?,
        hash: hash(&bytes),
        first,
        last: first
            .checked_add(count)
            .and_then(|n| n.checked_sub(1))
            .ok_or_else(|| bad("an empty chunk"))?,
    };
    chunks.push((reference, bytes));
    current.clear();
    Ok(())
}
