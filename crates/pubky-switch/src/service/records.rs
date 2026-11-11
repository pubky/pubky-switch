//! `GET /v1/{id}/records/{key}` and `GET /v1/{id}/records` (Switch wire 7.4.9): an own app
//! reads a shared record by key, or lists the current records of a collection, each as a
//! record view, and only those whose `read_scope` its certificate holds (3.1, 7.5).

use std::collections::BTreeMap;

use pubky_switch_core::{
    enc::{b64, unb64_array},
    records::AppCert,
};

use super::{
    Answer, Deferred, Service,
    batch::state::{HeldRecord, record_view},
    store_error,
};
use crate::{
    http::error::{ApiError, ErrorCode},
    keys::ServiceSigner,
    store::{AccountTxn, SnapshotRead, StoredRecord},
};

/// Records read from the snapshot at a time while a page is built: a record view is under
/// 1 MiB (wire 7.1), so a read holds a few tens of MiB at most, whatever the page's `limit`.
const RECORDS_PER_READ: u64 = 32;

fn only_apps() -> ApiError {
    ApiError::new(
        ErrorCode::PermissionMissing,
        "7.4.9: apps read records; the signer doesn't",
    )
}

/// A record's view as JSON.
fn view_json(record: StoredRecord) -> Result<Vec<u8>, ApiError> {
    serde_json::to_vec(&record_view(&HeldRecord::from(record)))
        .map_err(|_| ApiError::unavailable("7.6: a temporary failure"))
}

/// The query of a list (wire 7.4.9). Parameters the list doesn't define are ignored, as at
/// the feed (7.4.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecordsQuery {
    collection: [u8; 32],
    /// The key the page starts after, as its text.
    after: Option<String>,
    limit: u64,
}

impl RecordsQuery {
    /// Read the query; `max_limit` is `list_page` (9.2), the default and the most `limit`
    /// may name.
    ///
    /// # Errors
    ///
    /// `400` for a missing or malformed `collection`, a malformed `after`, or a `limit` that
    /// isn't an integer from 1 to `max_limit`.
    pub(super) fn parse(
        query: &BTreeMap<String, String>,
        max_limit: u64,
    ) -> Result<Self, ApiError> {
        let collection = query
            .get("collection")
            .ok_or_else(|| ApiError::bad_request("7.4.9: collection is required"))?;
        let collection = unb64_array::<32>(collection)
            .map_err(|_| ApiError::bad_request("7.4.9: collection is a collection ID, b64(32)"))?;
        // A key has one text (wire 1.2), so the one given is the text keys compare with.
        let after = query
            .get("after")
            .map(|text| unb64_array::<32>(text).map(|key| b64(&key)))
            .transpose()
            .map_err(|_| ApiError::bad_request("7.4.9: after is a record key, b64(32)"))?;
        let limit_range = || ApiError::bad_request(format!("7.4.9: limit is 1 to {max_limit}"));
        let limit = match query.get("limit") {
            None => max_limit,
            Some(text) => {
                if text.is_empty() || text.len() > 16 || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(limit_range());
                }
                text.parse::<u64>()
                    .ok()
                    .filter(|n| (1..=max_limit).contains(n))
                    .ok_or_else(limit_range)?
            }
        };
        Ok(Self {
            collection,
            after,
            limit,
        })
    }
}

/// A list page taken under the lock, whose records are read after it from the snapshot of
/// the state under it, so a long page holds no lock other requests wait for.
#[derive(Debug)]
pub(super) struct RecordsRead {
    snapshot: SnapshotRead,
    query: RecordsQuery,
    /// The scopes of the reader's certificate, the one its request was checked against:
    /// the page shows the records whose `read_scope` they hold (3.1).
    scopes: Vec<String>,
    /// `max_page_bytes` (9.2).
    budget: u64,
}

/// A page, built in key order from the records the reader may read: it ends after `limit`
/// views, or before a view that would take the bytes of its views past the budget, its
/// first view shown whatever its size.
#[derive(Debug, Default)]
struct Page {
    views: Vec<Vec<u8>>,
    bytes: u64,
    last: Option<[u8; 32]>,
    /// The limit or the budget ended it, with a record left after it.
    cut: bool,
}

impl Page {
    /// Take `key`'s view unless the page ends before it; whether it did.
    fn take(&mut self, key: [u8; 32], view: Vec<u8>, limit: u64, budget: u64) -> bool {
        let size = u64::try_from(view.len()).unwrap_or(u64::MAX);
        let full = u64::try_from(self.views.len()).unwrap_or(u64::MAX) >= limit;
        if !self.views.is_empty() && (full || self.bytes.saturating_add(size) > budget) {
            self.cut = true;
            return false;
        }
        self.views.push(view);
        self.bytes = self.bytes.saturating_add(size);
        self.last = Some(key);
        true
    }

    /// `{ "records": [...], "seq": int, "next": key | null }`: `next` is the last key of a
    /// page with more after it.
    fn body(self, seq: u64) -> Vec<u8> {
        let mut out = b"{\"records\":[".to_vec();
        for (i, view) in self.views.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(view);
        }
        out.extend_from_slice(format!("],\"seq\":{seq},\"next\":").as_bytes());
        match self.last.filter(|_| self.cut) {
            Some(key) => {
                out.push(b'"');
                out.extend_from_slice(b64(&key).as_bytes());
                out.push(b'"');
            }
            None => out.extend_from_slice(b"null"),
        }
        out.push(b'}');
        out
    }
}

impl Service {
    /// `GET /v1/{id}/records/{key}` (Switch wire 7.4.9) under the lock, for the own app
    /// `reader`: the record view of the key's current write, deleted or not. `404` for a key
    /// the service doesn't hold, never written or forgotten (6.2), and `403
    /// permission_missing` for a record whose `read_scope` the reader doesn't hold (3.1:
    /// plain `request` holds every `request:<label>`). A record is under 1 MiB, so it is
    /// read under the lock.
    pub(super) async fn get_record(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        reader: Option<&AppCert>,
        key: &str,
    ) -> Result<Answer, ApiError> {
        let reader = reader.ok_or_else(only_apps)?;
        let key = unb64_array::<32>(key)
            .map_err(|_| ApiError::bad_request("7.4.9: a record key is b64(32)"))?;
        let record = txn
            .records(&[key])
            .await
            .map_err(|e| store_error(&e))?
            .into_iter()
            .next()
            .ok_or_else(|| ApiError::not_found("7.4.9: no record at this key"))?;
        if !reader.holds_scope(&record.state.policy.read_scope) {
            return Err(ApiError::new(
                ErrorCode::PermissionMissing,
                "7.4.9: reading the record needs its read_scope",
            ));
        }
        let head = self
            .head(txn, signer)
            .await
            .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
        Ok(Answer::ok(view_json(record)?).with_head(Some(head)))
    }

    /// `GET /v1/{id}/records?collection=&after=&limit=` (Switch wire 7.4.9) under the lock,
    /// for the own app `reader`. The page is read after the lock ([`Service::records_body`])
    /// from the snapshot this transaction exports under it: every write to the records takes
    /// the account's lock, so the page is the state at the request's stamped service time.
    pub(super) async fn list_records(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        reader: Option<&AppCert>,
        query: &BTreeMap<String, String>,
    ) -> Result<Answer, ApiError> {
        let reader = reader.ok_or_else(only_apps)?;
        let query = RecordsQuery::parse(query, self.limits.list_page)?;
        let head = self
            .head(txn, signer)
            .await
            .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
        let snapshot = txn.snapshot_read().map_err(|e| store_error(&e))?;
        let mut answer = Answer::ok(Vec::new()).with_head(Some(head));
        answer.deferred = Some(Deferred::Records(Box::new(RecordsRead {
            snapshot,
            query,
            scopes: reader.scopes().to_vec(),
            budget: self.limits.max_page_bytes,
        })));
        Ok(answer)
    }

    /// The page of `read` (Switch wire 7.4.9): the current records of its collection the
    /// reader may read, deleted ones left out, by the text of their keys after `after`; and
    /// `seq`, the newest `seq` in the snapshot the page is read from.
    pub(super) async fn records_body(read: RecordsRead) -> Result<Vec<u8>, ApiError> {
        let RecordsRead {
            mut snapshot,
            query,
            scopes,
            budget,
        } = read;
        snapshot.start().await;
        let fail = |e: &crate::store::StoreError| store_error(e);
        let mut after = query.after.unwrap_or_default();
        let mut page = Page::default();
        'page: loop {
            let taken = u64::try_from(page.views.len()).unwrap_or(u64::MAX);
            // One past the limit, so a full page knows whether a record follows it.
            let want = query
                .limit
                .saturating_sub(taken)
                .saturating_add(1)
                .min(RECORDS_PER_READ);
            let records = snapshot
                .readable_records(&query.collection, &scopes, &after, want)
                .await
                .map_err(|e| fail(&e))?;
            let read = u64::try_from(records.len()).unwrap_or(u64::MAX);
            for record in records {
                let key = record.state.key;
                after = b64(&key);
                if !page.take(key, view_json(record)?, query.limit, budget) {
                    break 'page;
                }
            }
            if read < want {
                break;
            }
        }
        let seq = snapshot.last_seq().await.map_err(|e| fail(&e))?;
        snapshot.finish().await.map_err(|e| fail(&e))?;
        Ok(page.body(seq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn test_records_query_bounds() {
        let collection = b64(&[7; 32]);
        let parsed = RecordsQuery::parse(&query(&[("collection", &collection)]), 1000)
            .expect("collection alone");
        assert_eq!(parsed.limit, 1000);
        assert_eq!(parsed.after, None);
        let after = b64(&[9; 32]);
        let parsed = RecordsQuery::parse(
            &query(&[
                ("collection", &collection),
                ("after", &after),
                ("limit", "1"),
            ]),
            1000,
        )
        .expect("every parameter");
        assert_eq!(
            (parsed.after.as_deref(), parsed.limit),
            (Some(after.as_str()), 1)
        );
        for bad in [
            query(&[]),
            query(&[("collection", "not-a-key")]),
            query(&[("collection", &collection), ("after", "")]),
            query(&[("collection", &collection), ("limit", "0")]),
            query(&[("collection", &collection), ("limit", "1001")]),
            query(&[("collection", &collection), ("limit", "+5")]),
        ] {
            let refused = RecordsQuery::parse(&bad, 1000).expect_err("refused");
            assert_eq!(refused.code, ErrorCode::BadRequest, "{bad:?}");
        }
    }

    #[test]
    fn test_records_page_ends_by_limit_or_budget_with_its_first_view() {
        // The first view is shown whatever its size.
        let mut page = Page::default();
        assert!(page.take([1; 32], vec![b'x'; 10], 5, 4));
        assert!(!page.take([2; 32], vec![b'x'; 1], 5, 4));
        assert_eq!(page.views.len(), 1);
        let body = String::from_utf8(page.body(3)).expect("utf-8");
        assert_eq!(
            body,
            format!(
                "{{\"records\":[xxxxxxxxxx],\"seq\":3,\"next\":\"{}\"}}",
                b64(&[1; 32])
            )
        );
        // Views up to the budget exactly fit; the limit ends a page too.
        let mut page = Page::default();
        assert!(page.take([1; 32], b"ab".to_vec(), 2, 4));
        assert!(page.take([2; 32], b"cd".to_vec(), 2, 4));
        assert!(!page.take([3; 32], b"e".to_vec(), 2, 100));
        assert!(page.cut);
        // A page that ran out of records has no next.
        let mut page = Page::default();
        assert!(page.take([1; 32], b"{}".to_vec(), 2, 100));
        let body = String::from_utf8(page.body(0)).expect("utf-8");
        assert_eq!(body, "{\"records\":[{}],\"seq\":0,\"next\":null}");
    }
}
