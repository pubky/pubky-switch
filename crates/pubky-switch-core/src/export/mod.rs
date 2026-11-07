//! Export and import (Switch wire 10, Switch spec 12.5): the manifest, the chunks and their
//! parts, the pure checks of the export and import calls, the activation and the abort.
//!
//! A frozen old service exports an account as a signed [`Manifest`] and chunks of [`Part`]s;
//! the next service fetches or receives the chunks, checks each against the manifest, and
//! activates the import in one step once it holds them all. Everything here is pure: the
//! services keep the export, the chunks and the import state, and pass what a check compares
//! with as arguments.
//!
//! - [`ManifestBody`], [`Manifest`] and [`ChunkRef`]: the manifest (Switch wire 10.2), signed
//!   by the old service's key, and its chunk list.
//! - [`Chunk`] and [`Part`]: a chunk's exact JSON and every part kind of Switch wire 10.3, read
//!   as the table gives their members and written in the order the old service writes them.
//!   [`pack`] cuts an account's parts into chunks, which [`ManifestBody::new`] names.
//! - [`check_part_order`]: the part order of Switch wire 10.3.
//! - [`ExportRead`], [`ImportStart`], [`ImportStatus`], [`ChunkAnswer`], [`ActivateRequest`]
//!   and [`ActivateAnswer`]: the export and import calls' bodies and their checks (Switch
//!   wire 10.3, 10.4).
//! - [`activate`]: every check the next service makes on an export before it makes it live
//!   (Switch wire 10.5), returning the state to import, an [`Import`], or the refusal.
//! - [`check_abort_at_next`]: the next service's checks of an abort (Switch wire 10.6).
//!
//! Export data is network input from a possibly faulty old service: every member is read and
//! checked, and no check trusts a value the old service wrote where the chain or a signature
//! can vouch for it instead.

mod activate;
mod calls;
mod chunk;
mod manifest;
mod order;
mod part;

pub use activate::{
    Activation, Import, ImportedApp, ImportedClaim, ImportedRecord, UploadedHead, UploadedProof,
    Uploads, activate,
};
pub use calls::{
    ActivateAnswer, ActivateRequest, ChunkAnswer, CurrentImport, ExportCaller, ExportRead,
    ImportStart, ImportStatus, StartChecks, StartDecision, StartedImport, check_abort_at_next,
    decide_start,
};
pub use chunk::{Chunk, chunk_id, chunk_overhead, pack};
pub use manifest::{ChunkRef, Manifest, ManifestBody};
pub use order::check_part_order;
pub use part::{
    AppPart, AttemptState, BatchPart, ChainPart, ClaimEntryPart, ClaimPart, ClaimState,
    ConnectPart, ConversationPart, DivergentPart, EntryPart, EntryResult, FlagPart, InviteCodePart,
    KeyBundlePart, MetaPart, Missed, Part, PeerFloorPart, PeerPart, RecordEntry, TombstonePart,
    TombstoneState, Writer,
};

/// The `kind` of a manifest (Switch wire 10.2).
pub const MANIFEST_KIND: &str = "pubky-switch.export_manifest";

/// The `kind` of a chunk (Switch wire 10.3).
pub const CHUNK_KIND: &str = "pubky-switch.export_chunk";

/// `max_chunk_bytes`: no chunk is over 1 MiB (Switch wire 10.2, 10.4 step 6).
pub const MAX_CHUNK_BYTES: usize = 1 << 20;

/// The default chunk size an old service packs to, 1 MiB (Switch wire 10.2 "Packing").
pub const DEFAULT_CHUNK_TARGET: usize = MAX_CHUNK_BYTES;

/// `max_import_bytes` by default: 4 GiB (Switch wire 10.4 step 6, 9.2).
pub const MAX_IMPORT_BYTES: u64 = 1 << 32;

/// The most `divergent` parts one record has, 8 (Switch wire 9.1, 10.3).
pub const MAX_DIVERGENT_PER_RECORD: u64 = 8;

/// The most bytes a chunk's own members take around its parts, with `index` and `first` at
/// 2^53 - 1: 103 (Switch wire 10.3 "Part sizes").
pub const MAX_CHUNK_OVERHEAD: usize = 103;

use crate::error::Error;
use crate::http::ErrorCode;
use crate::ops::Refusal;

/// The reason of a core error, without its kind.
fn reason(error: Error) -> String {
    match error {
        Error::Invalid(why) | Error::Signature(why) | Error::Crypto(why) => why,
    }
}

/// A `400 bad_request` for a part or a body that doesn't read.
fn bad(why: impl Into<String>) -> Refusal {
    Refusal::bad_request(why)
}

/// A `409 conflict` naming the rule of Switch wire 10.5 that failed.
fn conflict(why: impl Into<String>) -> Refusal {
    Refusal::conflict(why)
}

/// A `401 bad_signature`.
fn bad_signature(why: impl Into<String>) -> Refusal {
    Refusal::new(ErrorCode::BadSignature, why)
}

/// A signed document that fails: `401 bad_signature` when its signature fails, else `400
/// bad_request` (Switch wire 10.5).
fn doc_refusal(error: Error) -> Refusal {
    Refusal::from(error)
}

/// A conflict for an error of a document the chain or a signature should vouch for: `409`,
/// whatever the error's kind (Switch wire 10.5).
fn conflict_of(what: &str, error: Error) -> Refusal {
    conflict(format!("{what}: {}", reason(error)))
}

#[cfg(test)]
mod tests;
