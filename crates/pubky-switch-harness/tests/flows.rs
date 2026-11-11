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
        Vec::<String>::new(),
        "the served calls no flow sends yet"
    );
}

/// Every value the fact `fact` has on the lines of `trace` labelled `label`, in order.
fn values(trace: &Trace, label: &str, fact: &str) -> Vec<String> {
    trace
        .lines
        .iter()
        .filter(|line| line.label == label)
        .filter_map(|line| line.facts.get(fact).cloned())
        .collect()
}

/// What each `GET /v1/{id}/apps` answer of `trace` says of alice's phone in `member`.
fn of_the_phone(trace: &Trace, member: &str) -> Vec<String> {
    trace
        .lines
        .iter()
        .filter(|line| line.label == "{alice} GET /v1/{alice}/apps")
        .filter_map(|line| {
            (0..8).find_map(|index| {
                let is_phone = line.facts.get(&format!("body.apps[{index}].app_id"))
                    == Some(&"id {alice/phone}".to_owned());
                is_phone
                    .then(|| {
                        line.facts
                            .get(&format!("body.apps[{index}].{member}"))
                            .cloned()
                    })
                    .flatten()
            })
        })
        .collect()
}

/// The types of the inbox's items in every feed page `app` read, in order: entries and what
/// stands for them (`missed`, `unreadable`), the chain's own items left out.
fn item_types(trace: &Trace, app: &str) -> Vec<String> {
    let label = format!("{{alice/{app}}} GET /v1/{{alice}}/feed");
    trace
        .lines
        .iter()
        .filter(|line| line.label == label)
        .flat_map(|line| {
            (0..16).filter_map(|index| {
                line.facts
                    .get(&format!("body.items[{index}].type"))
                    .cloned()
            })
        })
        .filter(|kind| kind != "text chain" && kind != "text stub")
        .collect()
}

/// One of the flows that run against each switch on its own, at both: `None` when no test
/// database is configured.
async fn each_switch(
    name: &str,
    flow: impl AsyncFn(&World) -> FlowResult + Copy,
) -> Option<(Trace, Trace)> {
    let service = run(Backend::Service, flow)
        .await
        .unwrap_or_else(|error| panic!("{name} at the service: {error}"))?;
    let scripted = run(Backend::Scripted, flow)
        .await
        .unwrap_or_else(|error| panic!("{name} at the scripted switch: {error}"))
        .expect("the scripted switch needs no database");
    Some((service, scripted))
}

/// What ends the message of a check that holds the scripted switch to what it does today.
const FOLLOWS_NOW: &str = "if the scripted switch follows the service here now, drop this \
                           half, and add the flow to `FLOWS` once its two runs compare";

/// The service marks an app lagging once its unread entries pass its share of the inbox
/// quota, deletes what only that app was holding, and ends the mark at the app's read
/// (Switch wire 7.4.4). The scripted switch marks none and keeps every entry.
#[tokio::test]
async fn test_lagging_app_is_marked_by_the_service_and_not_by_the_scripted_switch() {
    let Some((service, scripted)) = each_switch("the lagging app", flows::lagging_app).await else {
        return;
    };
    let read = "outcome the phone reads at last";
    let text = |value: &str| vec![value.to_owned()];

    let marks = of_the_phone(&service, "lagging");
    assert!(
        marks.contains(&"bool true".to_owned()),
        "the service never showed the phone as lagging: {marks:?}"
    );
    assert_eq!(
        marks.last().map(String::as_str),
        Some("bool false"),
        "the phone's read didn't end its mark"
    );
    assert_eq!(item_types(&service, "phone"), text("text missed"));
    assert_eq!(
        values(&service, read, "outcome.events[0]"),
        text("text Missed")
    );
    assert_eq!(values(&service, read, "outcome.notes"), text("number 0"));

    assert!(
        !of_the_phone(&scripted, "lagging").contains(&"bool true".to_owned()),
        "the scripted switch marked the phone lagging: {FOLLOWS_NOW}"
    );
    assert_eq!(
        item_types(&scripted, "phone"),
        vec!["text entry".to_owned(); 6],
        "the scripted switch didn't keep every entry for the phone: {FOLLOWS_NOW}"
    );
    assert_eq!(
        values(&scripted, read, "outcome.notes"),
        text("number 6"),
        "{FOLLOWS_NOW}"
    );
}

/// The service tells a lagging app what it missed in one `missed` item, which a later miss
/// replaces with one covering both, and the app lists its collections again (Switch wire
/// 7.4.4, 7.5). The scripted switch writes none: the app reads every entry.
#[tokio::test]
async fn test_missed_item_is_written_by_the_service_and_not_by_the_scripted_switch() {
    let Some((service, scripted)) = each_switch("the missed item", flows::missed_item).await else {
        return;
    };
    let feed = "{alice/phone} GET /v1/{alice}/feed";
    let read = "outcome the phone reads at last";
    let text = |value: &str| vec![value.to_owned()];
    // The phone lists its collection when it joins; another listing follows a `missed` item.
    let listings = |trace: &Trace| values(trace, "{alice/phone} GET /v1/{alice}/records", "status");

    assert_eq!(item_types(&service, "phone"), text("text missed"));
    assert_eq!(
        values(&service, feed, "body.items[0].entries"),
        text("number 8"),
        "one item covers the entries missed in both rounds"
    );
    assert_eq!(
        values(&service, read, "outcome.events[0]"),
        text("text Missed")
    );
    assert_eq!(values(&service, read, "outcome.notes"), text("number 0"));
    assert_eq!(
        listings(&service).len(),
        2,
        "the phone lists again after it"
    );

    assert_eq!(
        item_types(&scripted, "phone"),
        vec!["text entry".to_owned(); 8],
        "the scripted switch didn't keep every entry for the phone: {FOLLOWS_NOW}"
    );
    assert_eq!(
        values(&scripted, read, "outcome.notes"),
        text("number 8"),
        "{FOLLOWS_NOW}"
    );
    assert_eq!(listings(&scripted).len(), 1, "{FOLLOWS_NOW}");
}

/// At a revocation the service turns an entry left without a current reader into an
/// `unreadable` item for the apps that stay, and before it counts the entry as unread for
/// the app it targets (Switch wire 7.4.4, 7.4.12). The scripted switch does neither.
#[tokio::test]
async fn test_unreadable_item_is_written_by_the_service_and_not_by_the_scripted_switch() {
    let Some((service, scripted)) =
        each_switch("the unreadable item", flows::unreadable_after_revoke).await
    else {
        return;
    };
    let after = "outcome the wallet after the revocation";
    let unreadable = "text unreadable".to_owned();
    let one = "number 1".to_owned();

    assert!(
        of_the_phone(&service, "unread_entries").contains(&one),
        "the service counts the note the phone hasn't read"
    );
    assert!(
        of_the_phone(&service, "sole_target_unread").contains(&one),
        "the phone is the note's only target"
    );
    assert_eq!(
        item_types(&service, "wallet")
            .iter()
            .filter(|kind| **kind == unreadable)
            .count(),
        1,
        "the wallet finds one unreadable item"
    );
    assert!(
        values(&service, after, "outcome.events[0]").contains(&"text Unreadable".to_owned()),
        "the wallet raises it"
    );

    assert!(
        !of_the_phone(&scripted, "unread_entries").contains(&one),
        "the scripted switch counted the phone's unread note: {FOLLOWS_NOW}"
    );
    assert!(
        !item_types(&scripted, "wallet").contains(&unreadable),
        "the scripted switch wrote an unreadable item: {FOLLOWS_NOW}"
    );
}
