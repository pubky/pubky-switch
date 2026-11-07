//! The export manifest (Switch wire 10.2) and the checks the next service makes on it and on
//! each chunk (Switch wire 10.4).

use std::collections::HashSet;

use serde_json::{Value, json};

use super::chunk::Chunk;
use super::{MANIFEST_KIND, MAX_CHUNK_BYTES, bad};
use crate::chain::SignedHead;
use crate::enc::{b64, hash, pubky_id, pubky_key, unb64_array};
use crate::error::{Error, Result, invalid};
use crate::http::ErrorCode;
use crate::json::MAX_INT;
use crate::labels;
use crate::ops::Refusal;
use crate::ops::body::{Obj, array};
use crate::records::{Freeze, IdentityDoc};
use crate::sig::SignedDoc;
use crate::signing::Signs;
use crate::time::{parse_rfc3339, rfc3339};

/// A chunk reference in the manifest (Switch wire 10.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChunkRef {
    /// The chunk ID, opaque, used in the chunk URLs.
    pub id: String,
    /// The chunk's byte length.
    pub len: u64,
    /// `hash(chunk bytes)`.
    pub hash: [u8; 32],
    /// The index of its first part.
    pub first: u64,
    /// The index of its last part.
    pub last: u64,
}

impl ChunkRef {
    /// The reference as JSON: `id`, `len`, `hash`, `first`, `last`.
    pub fn to_json(&self) -> Vec<u8> {
        let mut o = Obj::new();
        o.str("id", &self.id)
            .int("len", self.len)
            .str("hash", &b64(&self.hash))
            .int("first", self.first)
            .int("last", self.last);
        o.finish()
    }

    /// The reference as a JSON value, as a `409 conflict` carries it in `current.chunk`.
    pub fn to_value(&self) -> Value {
        json!({
            "id": self.id,
            "len": self.len,
            "hash": b64(&self.hash),
            "first": self.first,
            "last": self.last,
        })
    }

    fn from_value(v: &Value) -> Result<Self> {
        let what = "a chunk reference";
        Ok(Self {
            id: text(v, "id", what)?.to_owned(),
            len: int(v, "len", what)?,
            hash: bytes32(v, "hash", what)?,
            first: int(v, "first", what)?,
            last: int(v, "last", what)?,
        })
    }

    /// Whether `bytes` are this chunk: its length and hash (Switch wire 10.3, 10.4).
    pub fn matches(&self, bytes: &[u8]) -> bool {
        u64::try_from(bytes.len()).is_ok_and(|len| len == self.len) && hash(bytes) == self.hash
    }
}

/// The members of a manifest (Switch wire 10.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestBody {
    /// The account's identity.
    pub identity: [u8; 32],
    /// The document hash of the signed freeze the export belongs to.
    pub freeze_hash: [u8; 32],
    /// g, the exported generation.
    pub generation: u64,
    /// g+1, as the freeze names it.
    pub next_generation: u64,
    /// The last service time the old service committed for the identity, in Unix
    /// milliseconds.
    pub last_time: u64,
    /// The old service's head at the end of the export: the freeze transition's item.
    pub head: SignedHead,
    /// A head for the newest stub the old service dropped, or `None` when it keeps the whole
    /// chain.
    pub checkpoint: Option<SignedHead>,
    /// The number of parts.
    pub parts: u64,
    /// The sum of the chunks' `len`.
    pub bytes: u64,
    /// The chunks, in part order.
    pub chunks: Vec<ChunkRef>,
}

impl ManifestBody {
    /// The manifest of an export cut into `chunks` (from [`super::pack`]): `next_generation`
    /// g+1, `parts` the last chunk's `last` plus one and `bytes` the sum of the lengths.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] without a chunk, or for a count beyond the integer range.
    pub fn new(
        identity: [u8; 32],
        freeze_hash: [u8; 32],
        generation: u64,
        last_time: u64,
        head: SignedHead,
        checkpoint: Option<SignedHead>,
        chunks: Vec<ChunkRef>,
    ) -> Result<Self> {
        let parts = chunks
            .last()
            .and_then(|c| c.last.checked_add(1))
            .ok_or_else(|| Error::Invalid("Switch wire 10.2: an export without parts".into()))?;
        let bytes = chunks
            .iter()
            .try_fold(0u64, |sum, c| sum.checked_add(c.len))
            .filter(|b| *b <= MAX_INT)
            .ok_or_else(|| Error::Invalid("Switch wire 10.2: bytes beyond the range".into()))?;
        let next_generation = generation.checked_add(1).ok_or_else(|| {
            Error::Invalid("Switch wire 10.2: generation beyond the range".into())
        })?;
        Ok(Self {
            identity,
            freeze_hash,
            generation,
            next_generation,
            last_time,
            head,
            checkpoint,
            parts,
            bytes,
            chunks,
        })
    }

    /// The body's exact JSON bytes, in the order of Switch wire 10.2.
    pub fn to_json(&self) -> Vec<u8> {
        let chunks: Vec<Vec<u8>> = self.chunks.iter().map(ChunkRef::to_json).collect();
        let mut o = Obj::new();
        o.int("v", 1)
            .str("kind", MANIFEST_KIND)
            .str("identity", &pubky_id(&self.identity))
            .str("freeze_hash", &b64(&self.freeze_hash))
            .int("generation", self.generation)
            .int("next_generation", self.next_generation)
            .str("last_time", &rfc3339(self.last_time))
            .raw("head", &self.head.to_json());
        match &self.checkpoint {
            Some(checkpoint) => o.raw("checkpoint", &checkpoint.to_json()),
            None => o.null("checkpoint"),
        };
        o.int("parts", self.parts)
            .int("bytes", self.bytes)
            .raw("chunks", &array(&chunks));
        o.finish()
    }

    fn from_value(v: &Value) -> Result<Self> {
        let what = "the manifest";
        if v.get("v").and_then(Value::as_u64) != Some(1)
            || v.get("kind").and_then(Value::as_str) != Some(MANIFEST_KIND)
        {
            return invalid("Switch wire 10.2: the manifest's v or kind");
        }
        let checkpoint = match v.get("checkpoint") {
            None => return invalid("Switch wire 10.2: the manifest's checkpoint is missing"),
            Some(Value::Null) => None,
            Some(head) => Some(SignedHead::from_value(head)?),
        };
        let Some(chunks) = v.get("chunks").and_then(Value::as_array) else {
            return invalid("Switch wire 10.2: the manifest's chunks aren't an array");
        };
        let last_time = parse_rfc3339(text(v, "last_time", what)?)
            .map_err(|_| Error::Invalid("Switch wire 10.2: last_time isn't a time".into()))?;
        Ok(Self {
            identity: pubky_key(text(v, "identity", what)?).map_err(|_| {
                Error::Invalid("Switch wire 10.2: identity isn't a Pubky ID".into())
            })?,
            freeze_hash: bytes32(v, "freeze_hash", what)?,
            generation: int(v, "generation", what)?,
            next_generation: int(v, "next_generation", what)?,
            last_time,
            head: SignedHead::from_value(
                v.get("head")
                    .ok_or_else(|| Error::Invalid("Switch wire 10.2: head is missing".into()))?,
            )?,
            checkpoint,
            parts: int(v, "parts", what)?,
            bytes: int(v, "bytes", what)?,
            chunks: chunks
                .iter()
                .map(ChunkRef::from_value)
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

fn text<'a>(v: &'a Value, member: &str, what: &str) -> Result<&'a str> {
    v.get(member)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Invalid(format!("Switch wire 10.2: {what}: {member} isn't a string")))
}

fn int(v: &Value, member: &str, what: &str) -> Result<u64> {
    match v.get(member).and_then(Value::as_u64) {
        Some(n) if n <= MAX_INT => Ok(n),
        _ => invalid(format!(
            "Switch wire 10.2: {what}: {member} isn't an integer from 0 to 2^53 - 1"
        )),
    }
}

fn bytes32(v: &Value, member: &str, what: &str) -> Result<[u8; 32]> {
    unb64_array::<32>(text(v, member, what)?)
        .map_err(|_| Error::Invalid(format!("Switch wire 10.2: {what}: {member} isn't b64(32)")))
}

/// A verified manifest (Switch wire 10.2): signed by the old service's key over
/// `lp("pubky-switch/v1/export-manifest", identity, body)`. Its manifest hash is its document
/// hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    body: ManifestBody,
    signed: SignedDoc,
    hash: [u8; 32],
}

impl Manifest {
    /// Sign a manifest with the old service's key for the account.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if the signed document doesn't decode, which can't happen for one
    /// this function writes.
    pub fn sign(service_key: &impl Signs, body: ManifestBody) -> Result<Self> {
        let bytes = body.to_json();
        let sig = service_key.sign_fields(labels::sig::EXPORT_MANIFEST, &[&body.identity, &bytes]);
        let signed = SignedDoc::from_parts(&bytes, &sig);
        let hash = signed.doc_hash()?;
        Ok(Self { body, signed, hash })
    }

    /// Verify a manifest with the old service's key for `identity` and read it (Switch wire
    /// 10.4 step 3).
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] if the key didn't sign it for the identity (`401
    /// bad_signature`), and [`Error::Invalid`] if it doesn't read or names another identity.
    pub fn verify(signed: &SignedDoc, service_key: &[u8; 32], identity: &[u8; 32]) -> Result<Self> {
        let v: Value = signed.open(service_key, labels::sig::EXPORT_MANIFEST, &[identity])?;
        let body = ManifestBody::from_value(&v)?;
        if &body.identity != identity {
            return invalid("Switch wire 10.2: the manifest names another identity");
        }
        Ok(Self {
            body,
            signed: signed.clone(),
            hash: signed.doc_hash()?,
        })
    }

    /// The members as read.
    pub fn body(&self) -> &ManifestBody {
        &self.body
    }

    /// The signed document, in its exact bytes.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }

    /// The manifest hash: its document hash (Switch wire 10.2).
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Step 5 of `POST /import` (Switch wire 10.4): the manifest is bound to this move. Its
    /// `identity` is the account's, its `freeze_hash` the freeze's, its `generation` the
    /// held `identity.json`'s g, and its `next_generation` and the freeze's are g+1.
    ///
    /// # Errors
    ///
    /// `400 bad_request` naming the member.
    pub fn check_binding(
        &self,
        identity: &[u8; 32],
        freeze: &Freeze,
        held: &IdentityDoc,
    ) -> std::result::Result<(), Refusal> {
        let b = &self.body;
        let next = held.generation().checked_add(1);
        let refused = if &b.identity != identity {
            Some("identity isn't the account's")
        } else if b.freeze_hash != freeze.hash() {
            Some("freeze_hash isn't the freeze's")
        } else if b.generation != held.generation() {
            Some("generation isn't the held identity.json's")
        } else if Some(b.next_generation) != next || Some(freeze.body().next_generation) != next {
            Some("next_generation isn't g + 1")
        } else {
            None
        };
        match refused {
            Some(why) => Err(bad(format!(
                "Switch wire 10.4 step 5: the manifest's {why}"
            ))),
            None => Ok(()),
        }
    }

    /// Step 6 of `POST /import` (Switch wire 10.4): the chunk list is well formed. Its IDs
    /// are unique, the first chunk starts at part 0 and each next one at the previous
    /// `last` + 1, the last ends at `parts` - 1, and `bytes` is the sum of `len` (`400`); no
    /// chunk is over 1 MiB and `bytes` is within `max_import_bytes` (`413 too_large`).
    ///
    /// # Errors
    ///
    /// As above.
    pub fn check_chunks(&self, max_import_bytes: u64) -> std::result::Result<(), Refusal> {
        let b = &self.body;
        let fail = |why: &str| Err(bad(format!("Switch wire 10.4 step 6: {why}")));
        if b.chunks.is_empty() {
            return fail("the manifest lists no chunk");
        }
        let mut ids = HashSet::new();
        let mut next = 0u64;
        let mut sum = 0u64;
        for c in &b.chunks {
            if !ids.insert(c.id.as_str()) {
                return fail("a chunk ID appears twice");
            }
            if c.first != next || c.last < c.first {
                return fail("a chunk's parts don't follow the previous chunk's");
            }
            next = c.last.saturating_add(1);
            sum = sum.saturating_add(c.len);
        }
        if next != b.parts {
            return fail("the chunks don't end at parts - 1");
        }
        if sum != b.bytes {
            return fail("bytes isn't the sum of the chunks' len");
        }
        let too_large = |why: &str| {
            Err(Refusal::new(
                ErrorCode::TooLarge,
                format!("Switch wire 10.4 step 6: {why}"),
            ))
        };
        if b.chunks
            .iter()
            .any(|c| usize::try_from(c.len).map_or(true, |len| len > MAX_CHUNK_BYTES))
        {
            return too_large("a chunk over 1 MiB");
        }
        if b.bytes > max_import_bytes {
            return too_large("the export is over max_import_bytes");
        }
        Ok(())
    }

    /// The chunk the manifest lists under `id`, with its index.
    pub fn chunk(&self, id: &str) -> Option<(u64, &ChunkRef)> {
        self.body
            .chunks
            .iter()
            .enumerate()
            .find(|(_, c)| c.id == id)
            .and_then(|(i, c)| u64::try_from(i).ok().map(|i| (i, c)))
    }

    /// The IDs of the chunks the next service doesn't hold yet, in manifest order, as the
    /// import status and a `409` of `POST /import/activate` name them (Switch wire 10.4,
    /// 10.5).
    pub fn missing(&self, held: impl Fn(&str) -> bool) -> Vec<String> {
        self.body
            .chunks
            .iter()
            .filter(|c| !held(&c.id))
            .map(|c| c.id.clone())
            .collect()
    }

    /// The check whoever fetches a chunk makes before it is stored at the next service
    /// (Switch wire 10.3): the manifest lists it, and its length and hash are the
    /// manifest's.
    ///
    /// # Errors
    ///
    /// `404 not_found` for a chunk the manifest doesn't list; `409 conflict` with `current:
    /// { "chunk": chunk reference }` for other bytes.
    pub fn check_fetched(&self, id: &str, bytes: &[u8]) -> std::result::Result<u64, Refusal> {
        let Some((index, c)) = self.chunk(id) else {
            return Err(Refusal::new(
                ErrorCode::NotFound,
                "Switch wire 10.4: the manifest doesn't list the chunk",
            ));
        };
        if !c.matches(bytes) {
            return Err(Refusal::conflict(
                "Switch wire 10.4: the chunk's length or hash isn't the manifest's",
            )
            .with_current(json!({ "chunk": c.to_value() })));
        }
        Ok(index)
    }

    /// The checks of `PUT /import/chunks/{chunk_id}` on its body (Switch wire 10.4): at most
    /// 1 MiB (`413`); listed (`404`); its length and hash the manifest's (`409`, nothing
    /// changes); and, for a chunk not held yet, a chunk whose `index`, `first` and number of
    /// parts are where the manifest puts it (`400`). The parts themselves are read at the
    /// activation (Switch wire 10.5 step 3).
    ///
    /// # Errors
    ///
    /// As above.
    pub fn check_chunk(&self, id: &str, bytes: &[u8]) -> std::result::Result<(), Refusal> {
        if bytes.len() > MAX_CHUNK_BYTES {
            return Err(Refusal::new(
                ErrorCode::TooLarge,
                "Switch wire 10.4: a chunk over 1 MiB",
            ));
        }
        let index = self.check_fetched(id, bytes)?;
        let (chunk_index, first, count) = Chunk::read_frame(bytes)?;
        self.check_place(id, index, chunk_index, first, count)
    }

    fn check_place(
        &self,
        id: &str,
        index: u64,
        chunk_index: u64,
        first: u64,
        count: usize,
    ) -> std::result::Result<(), Refusal> {
        let Some((_, c)) = self.chunk(id) else {
            return Err(Refusal::new(
                ErrorCode::NotFound,
                "Switch wire 10.4: the manifest doesn't list the chunk",
            ));
        };
        let expected = c.last.checked_sub(c.first).and_then(|n| n.checked_add(1));
        if chunk_index != index || first != c.first || u64::try_from(count).ok() != expected {
            return Err(bad(
                "Switch wire 10.4: the chunk's index, first or number of parts isn't the manifest's",
            ));
        }
        Ok(())
    }

    /// Read every part of the export from its chunks, in manifest order (Switch wire 10.5
    /// step 3): each chunk is the one the manifest lists there, where the manifest puts it,
    /// and every part reads as Switch wire 10.3 gives it.
    ///
    /// # Errors
    ///
    /// `409 conflict` for a chunk whose length or hash isn't the manifest's, `400
    /// bad_request` for one out of place, a part that doesn't read, or a part count other
    /// than the manifest's.
    pub fn read_parts(&self, chunks: &[&[u8]]) -> std::result::Result<Vec<super::Part>, Refusal> {
        if chunks.len() != self.body.chunks.len() {
            return Err(bad("Switch wire 10.5: the chunks aren't the manifest's"));
        }
        let mut parts = Vec::new();
        for (c, bytes) in self.body.chunks.iter().zip(chunks) {
            let index = self.check_fetched(&c.id, bytes)?;
            let chunk = Chunk::parse(bytes)?;
            self.check_place(&c.id, index, chunk.index, chunk.first, chunk.parts.len())?;
            parts.extend(chunk.parts);
        }
        if u64::try_from(parts.len()).ok() != Some(self.body.parts) {
            return Err(bad(
                "Switch wire 10.5: the number of parts isn't the manifest's",
            ));
        }
        Ok(parts)
    }
}
