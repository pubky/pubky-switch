//! Print what a flow shows against the service and against the scripted switch, and the
//! differences between the two.
//!
//! ```text
//! cargo run -p pubky-switch-harness --example trace -- join          # the calls
//! cargo run -p pubky-switch-harness --example trace -- join facts    # every fact kept
//! ```
//!
//! The service's run needs `PUBKY_SWITCH_TEST_DATABASE_URL`, as its tests do.

use pubky_switch_harness::flows::FLOWS;
use pubky_switch_harness::{HarnessError, Trace, compare_backends};

fn print(title: &str, trace: &Trace, facts: bool) {
    println!("== {title}");
    if facts {
        println!("{trace}");
        return;
    }
    for (index, line) in trace.lines.iter().enumerate() {
        match line.facts.get("status") {
            Some(status) => println!("{index:3} {} -> {status}", line.label),
            None => println!("{index:3} {}", line.label),
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let name = args.next().unwrap_or_default();
    let facts = args.next().as_deref() == Some("facts");
    let Some((name, flow)) = FLOWS.iter().find(|(flow, _)| *flow == name) else {
        let names: Vec<&str> = FLOWS.iter().map(|(flow, _)| *flow).collect();
        return Err(format!("name a flow: {}", names.join(", ")).into());
    };
    let comparison = match compare_backends(name, flow).await {
        Ok(Some(comparison)) => comparison,
        Ok(None) => return Err("no test database: set PUBKY_SWITCH_TEST_DATABASE_URL".into()),
        Err(HarnessError::Flow {
            backend,
            error,
            trace,
        }) => {
            print(
                &format!("{backend:?}, until the flow failed"),
                &trace,
                facts,
            );
            return Err(error.into());
        }
        Err(error) => return Err(error.into()),
    };
    print("the service", &comparison.service, facts);
    print("the scripted switch", &comparison.scripted, facts);
    println!("== differences the list allows");
    let allowed = &comparison.verdict.allowed;
    for (index, (difference, entry)) in allowed.iter().enumerate() {
        // Each entry once, with the first difference it allows and how many it allows.
        if allowed[..index].iter().any(|(_, earlier)| earlier == entry) {
            continue;
        }
        let times = allowed.iter().filter(|(_, other)| other == entry).count();
        println!("{} ({})", entry.reason, entry.reference);
        println!("    {times} times, first: {difference}");
    }
    println!("== the verdict");
    if comparison.verdict.agrees() {
        println!("the two agree");
    } else {
        print!("{}", comparison.verdict);
    }
    Ok(())
}
