//! The routes of the HTTP API (Switch wire 7.4), their body caps (Switch wire 7.1) and the
//! account states they pass (Switch wire 7.3 steps 7 and 8).

use std::collections::BTreeMap;

use crate::limits::fixed;

/// One KiB.
const KIB: u64 = 1024;
/// One MiB.
const MIB: u64 = 1024 * KIB;

/// The cap for a request the service has no route for: it answers `404`, and reads little.
pub const UNKNOWN_ROUTE_BODY_CAP: u64 = 64 * KIB;

/// An endpoint of the API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    /// `POST /v1/enroll`.
    Enroll,
    /// `PUT /v1/{id}/identity`.
    PutIdentity,
    /// `GET /v1/{id}/identity`, the public read.
    GetIdentity,
    /// `POST /v1/{id}/inbox`.
    Append,
    /// `GET /v1/{id}/feed`.
    Feed,
    /// `PUT /v1/{id}/peers`.
    PutPeers,
    /// `GET /v1/{id}/allow`.
    GetAllow,
    /// `POST /v1/{id}/connect`.
    PostConnect,
    /// `GET /v1/{id}/connect`.
    GetConnect,
    /// `DELETE /v1/{id}/connect/{pubky}`.
    DeleteConnect(String),
    /// `POST /v1/{id}/ops`.
    Ops,
    /// `GET /v1/{id}/claims/{claim_key}`.
    GetClaim(String),
    /// `GET /v1/{id}/records/{key}`.
    GetRecord(String),
    /// `GET /v1/{id}/records`.
    ListRecords,
    /// `GET /v1/{id}/directory`.
    Directory,
    /// `GET /v1/{id}/apps/{app_id}/keys`.
    GetKeys(String),
    /// `POST /v1/{id}/apps/{app_id}/keys`.
    RequestKeys(String),
    /// `PUT /v1/{id}/push`.
    PutPush,
    /// `POST /v1/{id}/apps/{app_id}/leave`.
    Leave(String),
    /// `GET /v1/{id}/apps`.
    GetApps,
    /// `POST /v1/{id}/apps/{app_id}/revoke`.
    Revoke(String),
    /// `POST /v1/{id}/freeze`.
    Freeze,
    /// `POST /v1/{id}/unfreeze`.
    Unfreeze,
    /// `GET /v1/{id}/export`.
    Export,
    /// `GET /v1/{id}/export/chunks/{chunk_id}`.
    ExportChunk(String),
    /// `POST /v1/{id}/import`.
    Import,
    /// `PUT /v1/{id}/import/chunks/{chunk_id}`.
    ImportChunk(String),
    /// `POST /v1/{id}/import/activate`.
    ImportActivate,
    /// `POST /v1/{id}/recovery/admission`.
    RecoveryAdmission,
    /// `POST /v1/{id}/recovery/upload`.
    RecoveryUpload,
    /// `POST /v1/{id}/erase`.
    Erase,
    /// `PUT /v1/{id}/handover`.
    PutHandover,
    /// `GET /v1/{id}/handover`.
    GetHandover,
}

impl Call {
    /// The largest body the call takes; a larger one is `413 too_large` before it is read
    /// (Switch wire 7.1).
    pub fn body_cap(&self) -> u64 {
        match self {
            Self::Append => fixed::MAX_ENVELOPE,
            Self::Ops | Self::Import => 4 * MIB,
            Self::Enroll | Self::PutIdentity | Self::PutPeers => 256 * KIB,
            Self::ImportChunk(_) => fixed::MAX_CHUNK_BYTES,
            Self::RecoveryUpload => 16 * MIB,
            Self::PutHandover => fixed::HANDOVER_BODY_CAP,
            Self::Freeze
            | Self::Unfreeze
            | Self::ImportActivate
            | Self::RecoveryAdmission
            | Self::Revoke(_)
            | Self::Leave(_)
            | Self::RequestKeys(_)
            | Self::PutPush
            | Self::Erase => 16 * KIB,
            Self::GetIdentity
            | Self::Feed
            | Self::GetAllow
            | Self::PostConnect
            | Self::GetConnect
            | Self::DeleteConnect(_)
            | Self::GetClaim(_)
            | Self::GetRecord(_)
            | Self::ListRecords
            | Self::Directory
            | Self::GetKeys(_)
            | Self::GetApps
            | Self::Export
            | Self::ExportChunk(_)
            | Self::GetHandover => 0,
        }
    }

    /// A write, which a frozen account answers with `410 moved` (Switch wire 7.3 step 8).
    pub fn is_write(&self) -> bool {
        matches!(
            self,
            Self::Append
                | Self::PutPeers
                | Self::PostConnect
                | Self::DeleteConnect(_)
                | Self::Ops
                | Self::Leave(_)
                | Self::Revoke(_)
                | Self::RecoveryUpload
                | Self::PutPush
                | Self::PutHandover
        )
    }

    /// A call a staged account answers; it answers every other with `503 staged`
    /// (Switch wire 7.3 step 7).
    pub fn passes_staged(&self) -> bool {
        matches!(
            self,
            Self::PutIdentity
                | Self::Import
                | Self::ImportChunk(_)
                | Self::ImportActivate
                | Self::Unfreeze
                | Self::RecoveryUpload
                | Self::Erase
        )
    }

    /// Whether the failed-authentication limit per network source applies: every call but
    /// the enrollment and the public read (Switch wire 7.2).
    pub fn limits_failed_authentication(&self) -> bool {
        !matches!(self, Self::Enroll | Self::GetIdentity)
    }

    /// A short, stable name for logs and metrics. It carries no path parameter.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Enroll => "enroll",
            Self::PutIdentity => "put_identity",
            Self::GetIdentity => "get_identity",
            Self::Append => "append",
            Self::Feed => "feed",
            Self::PutPeers => "put_peers",
            Self::GetAllow => "get_allow",
            Self::PostConnect => "post_connect",
            Self::GetConnect => "get_connect",
            Self::DeleteConnect(_) => "delete_connect",
            Self::Ops => "ops",
            Self::GetClaim(_) => "get_claim",
            Self::GetRecord(_) => "get_record",
            Self::ListRecords => "list_records",
            Self::Directory => "directory",
            Self::GetKeys(_) => "get_keys",
            Self::RequestKeys(_) => "request_keys",
            Self::PutPush => "put_push",
            Self::Leave(_) => "leave",
            Self::GetApps => "get_apps",
            Self::Revoke(_) => "revoke",
            Self::Freeze => "freeze",
            Self::Unfreeze => "unfreeze",
            Self::Export => "export",
            Self::ExportChunk(_) => "export_chunk",
            Self::Import => "import",
            Self::ImportChunk(_) => "import_chunk",
            Self::ImportActivate => "import_activate",
            Self::RecoveryAdmission => "recovery_admission",
            Self::RecoveryUpload => "recovery_upload",
            Self::Erase => "erase",
            Self::PutHandover => "put_handover",
            Self::GetHandover => "get_handover",
        }
    }
}

/// A routed request: the account it addresses, if any, and the call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// The `{id}` of the path; `None` for `POST /v1/enroll`.
    pub account: Option<String>,
    /// The call.
    pub call: Call,
    /// The query, percent-decoded (Switch wire 7.1); an error for a query that doesn't
    /// decode, which the endpoint answers with `400 bad_request`.
    pub query: Result<BTreeMap<String, String>, QueryError>,
}

/// A query that doesn't decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    /// A `%` escape that isn't two hex digits, or bytes that aren't UTF-8.
    #[error("the query doesn't percent-decode to UTF-8")]
    BadEncoding,
    /// A parameter named twice.
    #[error("a query parameter is named twice")]
    Repeated,
}

/// Route `method` and `path_and_query`, as sent. `None` for a route the API doesn't have.
pub fn route(method: &str, path_and_query: &str) -> Option<Route> {
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));
    let query = parse_query(query);
    let segments: Vec<&str> = path.strip_prefix("/v1/")?.split('/').collect();
    if segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }
    if let (["enroll"], "POST") = (segments.as_slice(), method) {
        return Some(Route {
            account: None,
            call: Call::Enroll,
            query,
        });
    }
    let (id, rest) = segments.split_first()?;
    let owned = |text: &&str| (*text).to_string();
    let call = match (method, rest) {
        ("PUT", ["identity"]) => Call::PutIdentity,
        ("GET", ["identity"]) => Call::GetIdentity,
        ("POST", ["inbox"]) => Call::Append,
        ("GET", ["feed"]) => Call::Feed,
        ("PUT", ["peers"]) => Call::PutPeers,
        ("GET", ["allow"]) => Call::GetAllow,
        ("POST", ["connect"]) => Call::PostConnect,
        ("GET", ["connect"]) => Call::GetConnect,
        ("DELETE", ["connect", pubky]) => Call::DeleteConnect(owned(pubky)),
        ("POST", ["ops"]) => Call::Ops,
        ("GET", ["claims", key]) => Call::GetClaim(owned(key)),
        ("GET", ["records", key]) => Call::GetRecord(owned(key)),
        ("GET", ["records"]) => Call::ListRecords,
        ("GET", ["directory"]) => Call::Directory,
        ("GET", ["apps", app, "keys"]) => Call::GetKeys(owned(app)),
        ("POST", ["apps", app, "keys"]) => Call::RequestKeys(owned(app)),
        ("PUT", ["push"]) => Call::PutPush,
        ("POST", ["apps", app, "leave"]) => Call::Leave(owned(app)),
        ("GET", ["apps"]) => Call::GetApps,
        ("POST", ["apps", app, "revoke"]) => Call::Revoke(owned(app)),
        ("POST", ["freeze"]) => Call::Freeze,
        ("POST", ["unfreeze"]) => Call::Unfreeze,
        ("GET", ["export"]) => Call::Export,
        ("GET", ["export", "chunks", chunk]) => Call::ExportChunk(owned(chunk)),
        ("POST", ["import"]) => Call::Import,
        ("PUT", ["import", "chunks", chunk]) => Call::ImportChunk(owned(chunk)),
        ("POST", ["import", "activate"]) => Call::ImportActivate,
        ("POST", ["recovery", "admission"]) => Call::RecoveryAdmission,
        ("POST", ["recovery", "upload"]) => Call::RecoveryUpload,
        ("POST", ["erase"]) => Call::Erase,
        ("PUT", ["handover"]) => Call::PutHandover,
        ("GET", ["handover"]) => Call::GetHandover,
        _ => return None,
    };
    Some(Route {
        account: Some((*id).to_string()),
        call,
        query,
    })
}

/// The body cap of a request, by its route; [`UNKNOWN_ROUTE_BODY_CAP`] without one.
pub fn body_cap(route: Option<&Route>) -> u64 {
    route.map_or(UNKNOWN_ROUTE_BODY_CAP, |route| route.call.body_cap())
}

/// Parse `name=value` pairs joined by `&`, percent-decoding names and values (Switch wire
/// 7.1).
fn parse_query(query: &str) -> Result<BTreeMap<String, String>, QueryError> {
    let mut parsed = BTreeMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = percent_decode(name).ok_or(QueryError::BadEncoding)?;
        let value = percent_decode(value).ok_or(QueryError::BadEncoding)?;
        if parsed.insert(name, value).is_some() {
            return Err(QueryError::Repeated);
        }
    }
    Ok(parsed)
}

/// Percent-decode `text`. `None` for a bad escape or bytes that aren't UTF-8.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(byte);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "6frao8w9ss5cn544qd64hynikrbr97ae1s5941c7ma5e1epifhgy";

    fn call(method: &str, path: &str) -> Option<Call> {
        route(method, path).map(|route| route.call)
    }

    #[test]
    fn test_route_every_endpoint() {
        let cases: Vec<(&str, String, Call)> = vec![
            ("POST", "/v1/enroll".into(), Call::Enroll),
            ("PUT", format!("/v1/{ID}/identity"), Call::PutIdentity),
            ("GET", format!("/v1/{ID}/identity"), Call::GetIdentity),
            (
                "POST",
                format!("/v1/{ID}/inbox?apps_version=4"),
                Call::Append,
            ),
            (
                "GET",
                format!("/v1/{ID}/feed?after=1:2&wait=25"),
                Call::Feed,
            ),
            ("PUT", format!("/v1/{ID}/peers"), Call::PutPeers),
            ("GET", format!("/v1/{ID}/allow"), Call::GetAllow),
            ("POST", format!("/v1/{ID}/connect"), Call::PostConnect),
            ("GET", format!("/v1/{ID}/connect"), Call::GetConnect),
            (
                "DELETE",
                format!("/v1/{ID}/connect/abc"),
                Call::DeleteConnect("abc".into()),
            ),
            ("POST", format!("/v1/{ID}/ops"), Call::Ops),
            (
                "GET",
                format!("/v1/{ID}/claims/k1"),
                Call::GetClaim("k1".into()),
            ),
            (
                "GET",
                format!("/v1/{ID}/records/r1"),
                Call::GetRecord("r1".into()),
            ),
            (
                "GET",
                format!("/v1/{ID}/records?collection=c&after=x"),
                Call::ListRecords,
            ),
            ("GET", format!("/v1/{ID}/directory"), Call::Directory),
            (
                "GET",
                format!("/v1/{ID}/apps/a1/keys"),
                Call::GetKeys("a1".into()),
            ),
            (
                "POST",
                format!("/v1/{ID}/apps/a1/keys"),
                Call::RequestKeys("a1".into()),
            ),
            ("PUT", format!("/v1/{ID}/push"), Call::PutPush),
            (
                "POST",
                format!("/v1/{ID}/apps/a1/leave"),
                Call::Leave("a1".into()),
            ),
            ("GET", format!("/v1/{ID}/apps"), Call::GetApps),
            (
                "POST",
                format!("/v1/{ID}/apps/a1/revoke"),
                Call::Revoke("a1".into()),
            ),
            ("POST", format!("/v1/{ID}/freeze"), Call::Freeze),
            ("POST", format!("/v1/{ID}/unfreeze"), Call::Unfreeze),
            ("GET", format!("/v1/{ID}/export"), Call::Export),
            (
                "GET",
                format!("/v1/{ID}/export/chunks/c1"),
                Call::ExportChunk("c1".into()),
            ),
            ("POST", format!("/v1/{ID}/import"), Call::Import),
            (
                "PUT",
                format!("/v1/{ID}/import/chunks/c1"),
                Call::ImportChunk("c1".into()),
            ),
            (
                "POST",
                format!("/v1/{ID}/import/activate"),
                Call::ImportActivate,
            ),
            (
                "POST",
                format!("/v1/{ID}/recovery/admission"),
                Call::RecoveryAdmission,
            ),
            (
                "POST",
                format!("/v1/{ID}/recovery/upload"),
                Call::RecoveryUpload,
            ),
            ("POST", format!("/v1/{ID}/erase"), Call::Erase),
            ("PUT", format!("/v1/{ID}/handover"), Call::PutHandover),
            ("GET", format!("/v1/{ID}/handover"), Call::GetHandover),
        ];
        assert_eq!(cases.len(), 33, "every route of Switch wire 7.4");
        for (method, path, expected) in cases {
            let routed = route(method, &path).unwrap_or_else(|| panic!("{method} {path}"));
            assert_eq!(routed.call, expected, "{method} {path}");
            let account = (expected != Call::Enroll).then(|| ID.to_string());
            assert_eq!(routed.account, account);
        }
    }

    #[test]
    fn test_route_unknown_routes() {
        for (method, path) in [
            ("GET", "/v1/enroll"),
            ("POST", "/v2/enroll"),
            ("GET", "/"),
            ("GET", "/v1/"),
            ("GET", "/v1/x"),
            ("PATCH", "/v1/x/identity"),
            ("GET", "/v1/x/records/a/b"),
            ("GET", "/v1//feed"),
            ("GET", "/v1/x/feed/"),
            ("DELETE", "/v1/x/connect"),
            ("POST", "/v1/x/apps/keys"),
        ] {
            assert_eq!(call(method, path), None, "{method} {path}");
        }
    }

    #[test]
    fn test_route_decodes_query() {
        let routed = route("GET", "/v1/x/records?collection=a%2Fb&after=").expect("route");
        let query = routed.query.expect("query");
        assert_eq!(query.get("collection").map(String::as_str), Some("a/b"));
        assert_eq!(query.get("after").map(String::as_str), Some(""));
        // A bad escape, invalid UTF-8 or a repeated parameter still routes, so the endpoint
        // can answer `400`.
        let query = |path: &str| route("GET", path).expect("route").query;
        assert_eq!(query("/v1/x/feed?after=%zz"), Err(QueryError::BadEncoding));
        assert_eq!(query("/v1/x/feed?after=%ff"), Err(QueryError::BadEncoding));
        assert_eq!(query("/v1/x/feed?after=%2"), Err(QueryError::BadEncoding));
        assert_eq!(query("/v1/x/feed?wait=1&wait=2"), Err(QueryError::Repeated));
    }

    #[test]
    fn test_route_body_caps_match_wire_table() {
        let cap = |method: &str, path: &str| body_cap(route(method, path).as_ref());
        assert_eq!(cap("POST", "/v1/x/inbox"), 65_536);
        assert_eq!(cap("POST", "/v1/x/ops"), 4 * 1024 * 1024);
        assert_eq!(cap("POST", "/v1/x/import"), 4 * 1024 * 1024);
        assert_eq!(cap("POST", "/v1/enroll"), 256 * 1024);
        assert_eq!(cap("PUT", "/v1/x/identity"), 256 * 1024);
        assert_eq!(cap("PUT", "/v1/x/peers"), 256 * 1024);
        assert_eq!(cap("PUT", "/v1/x/import/chunks/c"), 1024 * 1024);
        assert_eq!(cap("POST", "/v1/x/recovery/upload"), 16 * 1024 * 1024);
        assert_eq!(cap("PUT", "/v1/x/handover"), 6 * 1024 * 1024);
        for path in [
            "/v1/x/freeze",
            "/v1/x/unfreeze",
            "/v1/x/import/activate",
            "/v1/x/recovery/admission",
            "/v1/x/apps/a/revoke",
            "/v1/x/apps/a/leave",
            "/v1/x/apps/a/keys",
            "/v1/x/erase",
        ] {
            assert_eq!(cap("POST", path), 16 * 1024, "{path}");
        }
        assert_eq!(cap("PUT", "/v1/x/push"), 16 * 1024);
        assert_eq!(cap("GET", "/v1/x/feed"), 0);
        assert_eq!(cap("POST", "/v1/x/connect"), 0);
        assert_eq!(cap("DELETE", "/v1/x/connect/p"), 0);
        assert_eq!(cap("GET", "/nowhere"), UNKNOWN_ROUTE_BODY_CAP);
    }

    #[test]
    fn test_route_staged_and_frozen_rules() {
        let staged: Vec<_> = [
            ("PUT", "/v1/x/identity"),
            ("POST", "/v1/x/import"),
            ("PUT", "/v1/x/import/chunks/c"),
            ("POST", "/v1/x/import/activate"),
            ("POST", "/v1/x/unfreeze"),
            ("POST", "/v1/x/recovery/upload"),
            ("POST", "/v1/x/erase"),
        ]
        .into_iter()
        .filter_map(|(method, path)| call(method, path))
        .collect();
        assert_eq!(staged.len(), 7);
        assert!(staged.iter().all(Call::passes_staged));
        assert!(!Call::Feed.passes_staged());
        assert!(!Call::Ops.passes_staged());

        for write in [
            Call::Append,
            Call::PutPeers,
            Call::PostConnect,
            Call::DeleteConnect("p".into()),
            Call::Ops,
            Call::Leave("a".into()),
            Call::Revoke("a".into()),
            Call::RecoveryUpload,
            Call::PutPush,
            Call::PutHandover,
        ] {
            assert!(write.is_write(), "{write:?}");
        }
        for read in [
            Call::Feed,
            Call::Export,
            Call::ExportChunk("c".into()),
            Call::Unfreeze,
            Call::Erase,
            Call::GetIdentity,
        ] {
            assert!(!read.is_write(), "{read:?}");
        }
    }

    #[test]
    fn test_route_failed_authentication_limit_scope() {
        assert!(!Call::Enroll.limits_failed_authentication());
        assert!(!Call::GetIdentity.limits_failed_authentication());
        assert!(Call::Feed.limits_failed_authentication());
        assert!(Call::ExportChunk("c".into()).limits_failed_authentication());
    }
}
