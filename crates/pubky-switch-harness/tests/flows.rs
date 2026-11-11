//! Every honest flow, run against the service and against the scripted switch: the two
//! answer alike, but for the allowed differences, and the flows send the service every call
//! it serves.

// Helpers of tests fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use pubky_switch::http::route::route;
use pubky_switch_harness::allowed::{ALLOWED, EVERY_FLOW};
use pubky_switch_harness::compare::{differences, judge};
use pubky_switch_harness::flows::{self, CALLS, FLOWS, ORIGIN, flow_of};
use pubky_switch_harness::{Backend, Comparison, FlowResult, Trace, World, compare_backends, run};
use tokio::sync::OnceCell;

/// Every flow's comparison, made once for the tests of this file; `None` when no test
/// database is configured.
async fn comparisons() -> Option<&'static [(&'static str, Comparison)]> {
    static COMPARISONS: OnceCell<Option<Vec<(&'static str, Comparison)>>> = OnceCell::const_new();
    COMPARISONS
        .get_or_init(|| async {
            let mut all = Vec::new();
            for (name, flow) in FLOWS {
                match compare_backends(name, flow).await {
                    Err(error) => panic!("{name}: {error}"),
                    Ok(None) => {
                        eprintln!("ran against the scripted switch only: no test database");
                        return None;
                    }
                    Ok(Some(comparison)) => all.push((*name, comparison)),
                }
            }
            Some(all)
        })
        .await
        .as_deref()
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
    distort: fn(
        &pubky_switch_client::transport::Request,
        &mut pubky_switch_client::transport::Response,
    ),
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
    let id = world.identity("alice").key().id();
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
        ["POST /v1/{id}/apps/{app}/keys",],
        "the served calls no flow sends yet"
    );
}
