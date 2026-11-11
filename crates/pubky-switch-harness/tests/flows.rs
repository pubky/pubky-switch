//! Every honest flow, run against the service and against the scripted switch: the two
//! answer alike, but for the allowed differences, and the flows send the service every call
//! it serves.

// Helpers of tests fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::panic::AssertUnwindSafe;

use futures_util::FutureExt;

use pubky_switch::http::route::route;
use pubky_switch_client::transport::{Request, Response};
use pubky_switch_core::enc::{b64, unb64};
use pubky_switch_harness::allowed::{ALLOWED, EVERY_FLOW};
use pubky_switch_harness::compare::{Difference, differences, judge};
use pubky_switch_harness::flows::{self, CALLS, FLOWS, ORIGIN, flow_of};
use pubky_switch_harness::{Backend, Comparison, FlowResult, Trace, World, compare_backends, run};
use tokio::sync::OnceCell;

/// Every flow's comparison, made once for the tests of this file; `None` when no test
/// database is configured. A flow that fails is kept as the failure: every test that asks
/// then fails at once with it, and no flow is run again.
async fn comparisons() -> Option<&'static [(&'static str, Comparison)]> {
    type Made = Result<Option<Vec<(&'static str, Comparison)>>, String>;
    static COMPARISONS: OnceCell<Made> = OnceCell::const_new();
    let made = COMPARISONS
        .get_or_init(|| async {
            let mut all = Vec::new();
            for (name, flow) in FLOWS {
                // A flow that panics is kept as a failure like one that returns an error:
                // an unwinding init would leave the cell empty, and every test would run
                // the flows again.
                let compared = AssertUnwindSafe(compare_backends(name, flow))
                    .catch_unwind()
                    .await;
                match compared {
                    Err(_) => return Err(format!("{name}: the flow panicked")),
                    Ok(Err(error)) => return Err(format!("{name}: {error}")),
                    Ok(Ok(None)) => {
                        eprintln!("ran against the scripted switch only: no test database");
                        return Ok(None);
                    }
                    Ok(Ok(Some(comparison))) => all.push((*name, comparison)),
                }
            }
            Ok(Some(all))
        })
        .await;
    match made {
        Ok(all) => all.as_deref(),
        Err(failure) => panic!("{failure}"),
    }
}

/// What the flow `name` showed against the service.
async fn service_trace(name: &str) -> Option<&'static Trace> {
    let all = comparisons().await?;
    let (_, comparison) = all
        .iter()
        .find(|(flow, _)| *flow == name)
        .expect("the flow");
    Some(&comparison.service)
}

/// What `flow` shows against a scripted switch whose answers the trace keeps as `distort`
/// changes them.
async fn distorted(
    flow: impl AsyncFn(&World) -> FlowResult,
    distort: fn(&Request, &mut Response),
) -> Trace {
    run(Backend::Scripted, async |world| {
        world.distort(distort);
        flow(world).await
    })
    .await
    .expect("the flow")
    .expect("a scripted world")
}

#[tokio::test]
async fn test_flows_answer_alike_at_the_service_and_the_scripted_switch() {
    let Some(all) = comparisons().await else {
        return;
    };
    let failures: Vec<String> = all
        .iter()
        .filter(|(_, comparison)| !comparison.verdict.agrees())
        .map(|(name, comparison)| format!("{name}:\n{}", comparison.verdict))
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn test_allowed_differences_name_flows_that_exist() {
    for entry in ALLOWED {
        assert!(
            entry.flow == EVERY_FLOW || FLOWS.iter().any(|(name, _)| *name == entry.flow),
            "the allowed-differences list names a flow that doesn't exist: {}",
            entry.flow
        );
        assert!(!entry.reason.is_empty() && !entry.reference.is_empty());
    }
}

/// An entry for every flow, such as the one for member order, shows in one flow at least:
/// like a flow's own entries, it can't stay in the list once the difference is gone.
#[tokio::test]
async fn test_allowed_differences_for_every_flow_show_in_one() {
    let Some(all) = comparisons().await else {
        return;
    };
    for entry in ALLOWED.iter().filter(|entry| entry.flow == EVERY_FLOW) {
        let shows = all.iter().any(|(_, comparison)| {
            let allowed = comparison.verdict.allowed.iter();
            allowed.into_iter().any(|(_, used)| *used == entry)
        });
        assert!(shows, "no flow shows: {} ({})", entry.fact, entry.reason);
    }
}

/// A switch that answers differently, where the client itself accepts the answer, fails the
/// comparison: here a scripted switch whose `GET /apps` shows one more app than it holds.
#[tokio::test]
async fn test_comparison_fails_a_scripted_switch_that_answers_differently() {
    let Some(service) = service_trace("join").await else {
        return;
    };
    let scripted = distorted(flows::join, |request, answer| {
        if request.method != "GET" || !request.path_and_query.ends_with("/apps") {
            return;
        }
        let mut body: serde_json::Value = serde_json::from_slice(&answer.body).expect("json");
        let apps = body["apps"].as_array_mut().expect("apps");
        apps.push(serde_json::json!({ "current": true }));
        answer.body = serde_json::to_vec(&body).expect("json");
    })
    .await;
    let verdict = judge("join", differences(service, &scripted), ALLOWED);
    assert!(!verdict.agrees());
    assert!(
        verdict
            .unlisted
            .iter()
            .any(|d| d.label == "{alice} GET /v1/{alice}/apps" && d.fact == "body.apps"),
        "{verdict}"
    );
}

/// So does one that leaves a header out.
#[tokio::test]
async fn test_comparison_fails_a_scripted_switch_that_leaves_the_head_out() {
    let Some(service) = service_trace("enrollment").await else {
        return;
    };
    let scripted = distorted(flows::enrollment, |request, answer| {
        if request.method == "PUT" {
            answer.headers.retain(|header| header.name != "switch-head");
        }
    })
    .await;
    let verdict = judge("enrollment", differences(service, &scripted), ALLOWED);
    assert!(
        verdict
            .unlisted
            .iter()
            .any(|d| d.fact == "header switch-head" && d.scripted.as_deref() == Some("absent")),
        "{verdict}"
    );
}

/// The answer's JSON body, changed by `change` where `change` finds what it looks for.
fn change_body(answer: &mut Response, change: impl FnOnce(&mut serde_json::Value) -> Option<()>) {
    let Ok(mut body) = serde_json::from_slice::<serde_json::Value>(&answer.body) else {
        return;
    };
    if change(&mut body).is_some() {
        answer.body = serde_json::to_vec(&body).expect("json");
    }
}

/// The JSON object `text` carries in base64url, changed by `change`, in base64url again.
fn change_carried(text: &str, change: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut carried: serde_json::Value =
        serde_json::from_slice(&unb64(text).expect("base64url")).expect("json");
    change(&mut carried);
    b64(&serde_json::to_vec(&carried).expect("json"))
}

fn is_get_apps(request: &Request) -> bool {
    request.method == "GET" && request.path_and_query.ends_with("/apps")
}

/// A scripted switch that answers a wrong signature, hash or certificate hash of the right
/// length fails the comparison: the string isn't the one the run showed before, where the
/// service's is. Each of the three is swapped in the `join` flow's `GET /apps` answers.
#[tokio::test]
async fn test_comparison_fails_a_scripted_switch_that_answers_another_string_of_the_same_length() {
    let Some(service) = service_trace("join").await else {
        return;
    };
    type Distortion = fn(&Request, &mut Response);
    let cases: [(&str, &str, Distortion); 3] = [
        (
            "the signature of the identity.json it holds",
            "body.identity.sig",
            |request, answer| {
                if is_get_apps(request) {
                    change_body(answer, |body| {
                        *body.get_mut("identity")?.get_mut("sig")? = b64(&[7; 64]).into();
                        Some(())
                    });
                }
            },
        ),
        (
            "the hash of a listed certificate, inside the identity.json it holds",
            "body.identity.body~.apps[0].cert",
            |request, answer| {
                if is_get_apps(request) {
                    change_body(answer, |body| {
                        let signed = body.get_mut("identity")?.get_mut("body")?;
                        let mut listed = false;
                        let changed = change_carried(signed.as_str()?, |identity| {
                            if let Some(cert) = identity.pointer_mut("/apps/0/cert") {
                                *cert = b64(&[5; 32]).into();
                                listed = true;
                            }
                        });
                        *signed = changed.into();
                        listed.then_some(())
                    });
                }
            },
        ),
        (
            "the chain hash of the head in Switch-Head",
            "header switch-head~.chain_hash",
            |request, answer| {
                if !is_get_apps(request) {
                    return;
                }
                for header in &mut answer.headers {
                    if header.name == "switch-head" {
                        header.value = change_carried(&header.value, |head| {
                            head["chain_hash"] = b64(&[9; 32]).into();
                        });
                    }
                }
            },
        ),
    ];
    for (what, fact, distortion) in cases {
        let scripted = distorted(flows::join, distortion).await;
        let verdict = judge("join", differences(service, &scripted), ALLOWED);
        assert!(
            verdict.unlisted.iter().any(|d| d.fact == fact
                && d.label == "{alice} GET /v1/{alice}/apps"
                && d.scripted
                    .as_deref()
                    .is_some_and(|shown| shown.ends_with("a string not shown before"))),
            "{what} wasn't noticed:\n{verdict}"
        );
    }
}

/// `value` with every chain hash, previous chain hash and item hash replaced by another,
/// the same replacement wherever the same hash shows, also inside the JSON a string carries
/// in base64url: a chain that is wrong from its first item and consistent throughout.
fn replace_chain_hashes(value: &mut serde_json::Value) {
    use serde_json::Value;
    match value {
        Value::Object(members) => {
            for (name, member) in members.iter_mut() {
                let hashed = matches!(
                    name.as_str(),
                    "chain_hash" | "prev_chain_hash" | "item_hash"
                );
                match member.as_str().map(str::to_owned) {
                    Some(text) if hashed => {
                        if let Ok(bytes) = unb64(&text) {
                            *member = b64(&pubky_switch_core::enc::hash(&bytes)).into();
                        }
                    }
                    Some(text) if text.starts_with("eyJ") => {
                        let carried = unb64(&text)
                            .ok()
                            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
                        if let Some(mut carried) = carried {
                            replace_chain_hashes(&mut carried);
                            *member = b64(&serde_json::to_vec(&carried).expect("json")).into();
                        }
                    }
                    _ => replace_chain_hashes(member),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(replace_chain_hashes),
        _ => {}
    }
}

/// A scripted switch whose chain is wrong from the start and consistent throughout reads
/// like the service's in the comparison: every hash repeats where the right one would. The
/// harness's own checks fail it: the stubs' chain hashes don't follow from their envelopes,
/// and the heads and proofs don't verify.
#[tokio::test]
async fn test_checks_fail_a_scripted_switch_with_a_wrong_but_consistent_chain() {
    let Some(service) = service_trace("join").await else {
        return;
    };
    let scripted = distorted(flows::join, |_, answer| {
        change_body(answer, |body| {
            replace_chain_hashes(body);
            Some(())
        });
        for header in &mut answer.headers {
            if header.name == "switch-head" {
                header.value = change_carried(&header.value, replace_chain_hashes);
            }
        }
    })
    .await;
    let verdict = judge("join", differences(service, &scripted), ALLOWED);
    let violations: Vec<&Difference> = verdict
        .unlisted
        .iter()
        .filter(|d| d.fact.starts_with("violation"))
        .collect();
    let failed = |what: &str| {
        violations.iter().any(|d| {
            d.service.is_none()
                && d.scripted
                    .as_deref()
                    .is_some_and(|text| text.contains(what))
        })
    };
    assert!(failed("the head's signature doesn't verify"), "{verdict}");
    assert!(failed("the proof's signature doesn't verify"), "{verdict}");
    assert!(failed("chain hash"), "{verdict}");
    // Without those checks the two runs read alike: nothing else is unlisted.
    assert_eq!(violations.len(), verdict.unlisted.len(), "{verdict}");
}

/// A sample App ID and a sample of any other path parameter.
const APP: &str = "yyyyyyyyyyyyyyyyyyyyyyyyyy";
const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn path_of(template: &str, id: &str) -> String {
    template
        .replace("{id}", id)
        .replace("{app}", APP)
        .replace("{key}", KEY)
}

#[test]
fn test_calls_list_names_each_call_once() {
    let mut names = BTreeSet::new();
    for (method, template) in CALLS {
        let routed = route(method, &path_of(template, "id"))
            .unwrap_or_else(|| panic!("{method} {template} is no route"));
        assert!(
            names.insert(routed.call.name()),
            "{method} {template} twice"
        );
        if let Some(flow) = flow_of(&routed.call) {
            assert!(
                FLOWS.iter().any(|(name, _)| *name == flow),
                "{method} {template}: no flow {flow}"
            );
        }
    }
}

/// The service answers a call it doesn't serve yet with `503 unavailable` before it looks at
/// the caller. So a request no key signs tells whether a call is served: a served call must
/// be listed in `flow_of`, under a flow that sends it or as waiting for one, and a call
/// listed under a flow must be served and sent by it.
#[tokio::test]
async fn test_every_served_call_is_listed_and_sent_by_its_flow() {
    let Some(all) = comparisons().await else {
        return;
    };
    let sent_by = |flow: &str| -> BTreeSet<&str> {
        let (_, comparison) = all
            .iter()
            .find(|(name, _)| *name == flow)
            .expect("the flow");
        let lines = comparison.service.lines.iter();
        lines.filter_map(|line| line.call).collect()
    };
    let world = World::start(Backend::Service)
        .expect("a world")
        .expect("a database");
    flows::enrollment(&world).await.expect("enrolled");
    let id = world.identity("alice").expect("alice").key().id();
    let mut failures = Vec::new();
    let mut waiting = Vec::new();
    for (method, template) in CALLS {
        let path = path_of(template, &id);
        let call = route(method, &path).expect("a route").call;
        let answer = world
            .request(method, ORIGIN, &path)
            .await
            .expect("an answer");
        let body: serde_json::Value = serde_json::from_slice(&answer.body).unwrap_or_default();
        let served = !(answer.status == 503 && body["code"] == "unavailable");
        match flow_of(&call) {
            None if served => waiting.push(format!("{method} {template}")),
            None => {}
            Some(flow) if !served => {
                failures.push(format!(
                    "{method} {template}: listed for {flow}, not served"
                ));
            }
            Some(flow) if !sent_by(flow).contains(call.name()) => {
                failures.push(format!("{method} {template}: {flow} doesn't send it"));
            }
            Some(_) => {}
        }
    }
    world.close().await.expect("closed");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // The served calls still waiting for a flow: this list shrinks to nothing as the flows
    // land, and a call that starts being served must be added to it or given a flow.
    assert_eq!(
        waiting,
        [
            "POST /v1/{id}/apps/{app}/keys",
            "POST /v1/{id}/erase",
            "PUT /v1/{id}/handover",
            "GET /v1/{id}/handover",
        ],
        "the served calls no flow sends yet"
    );
}
