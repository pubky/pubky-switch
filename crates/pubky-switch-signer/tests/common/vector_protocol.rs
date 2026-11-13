//! The protocol of the Switch vector set (`spec/vectors/`), read from the files so the
//! signer's vector tests name none. Shared by the unit and the integration vector tests.

// It reads fixed vector files, where a failure is a test failure: the workspace's no-panic
// lints don't apply to it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;

/// The vectors' protocol, as `documents.json` gives it: its name, the one member of the wallet
/// app record's `protocols`, and its scope roots, the names of every scope the vector
/// certificates hold.
pub fn vector_protocol(documents: &Value) -> (String, Vec<String>) {
    let documents = documents["documents"].as_array().unwrap();
    let body = |name: &str| -> Vec<Value> {
        documents
            .iter()
            .filter(|d| d["name"].as_str().unwrap().contains(name))
            .map(|d| serde_json::from_str(d["body"].as_str().unwrap()).unwrap())
            .collect()
    };
    let record = body("wallet app record").remove(0);
    let protocols = record["protocols"].as_object().unwrap();
    assert_eq!(
        protocols.len(),
        1,
        "the vectors' apps belong to one protocol"
    );
    let name = protocols.keys().next().unwrap().clone();
    let mut roots: Vec<String> = body("certificate")
        .iter()
        .flat_map(|cert| cert["scopes"].as_array().unwrap().clone())
        .map(|scope| {
            let scope = scope.as_str().unwrap();
            scope
                .split_once(':')
                .map_or(scope, |(root, _)| root)
                .to_owned()
        })
        .collect();
    roots.sort();
    roots.dedup();
    (name, roots)
}
