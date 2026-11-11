//! Comparing two runs of one flow, and judging the differences against the allowed list.

use std::collections::BTreeSet;

use crate::allowed::Allowed;
use crate::trace::Trace;

/// One fact the two runs disagree on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Difference {
    /// The line's index in the traces.
    pub line: usize,
    /// The line's label against the service.
    pub label: String,
    /// Where the fact was found, such as `status` or `body.head.seq`; `label` when the two
    /// runs made different calls at this line, and `lines` when one run made more.
    pub fact: String,
    /// What the service's run showed; `None` when it showed nothing there.
    pub service: Option<String>,
    /// What the scripted switch's run showed; `None` when it showed nothing there.
    pub scripted: Option<String>,
}

impl std::fmt::Display for Difference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let show = |value: &Option<String>| value.clone().unwrap_or_else(|| "(nothing)".into());
        write!(
            f,
            "line {} [{}] {}: service {}, scripted {}",
            self.line,
            self.label,
            self.fact,
            show(&self.service),
            show(&self.scripted)
        )
    }
}

/// Every fact the two traces disagree on, in order.
///
/// Lines are compared one by one. Where the two runs made different calls at a line, the
/// facts of that line and of every later one say nothing: the difference is the call, and
/// the comparison ends there. A run with more lines than the other differs in `lines`.
pub fn differences(service: &Trace, scripted: &Trace) -> Vec<Difference> {
    let mut found = Vec::new();
    for (index, (ours, theirs)) in service.lines.iter().zip(&scripted.lines).enumerate() {
        if ours.label != theirs.label {
            found.push(Difference {
                line: index,
                label: ours.label.clone(),
                fact: "label".into(),
                service: Some(ours.label.clone()),
                scripted: Some(theirs.label.clone()),
            });
            return found;
        }
        let facts: BTreeSet<&String> = ours.facts.keys().chain(theirs.facts.keys()).collect();
        for fact in facts {
            let (service, scripted) = (ours.facts.get(fact), theirs.facts.get(fact));
            if service != scripted {
                found.push(Difference {
                    line: index,
                    label: ours.label.clone(),
                    fact: fact.clone(),
                    service: service.cloned(),
                    scripted: scripted.cloned(),
                });
            }
        }
    }
    if service.lines.len() != scripted.lines.len() {
        let shorter = service.lines.len().min(scripted.lines.len());
        let next = |trace: &Trace| trace.lines.get(shorter).map(|line| line.label.clone());
        found.push(Difference {
            line: shorter,
            label: next(service).or_else(|| next(scripted)).unwrap_or_default(),
            fact: "lines".into(),
            service: Some(format!("{} lines", service.lines.len())),
            scripted: Some(format!("{} lines", scripted.lines.len())),
        });
    }
    found
}

/// The differences of one flow, judged against the allowed list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    /// The differences no entry allows.
    pub unlisted: Vec<Difference>,
    /// The entries of this flow that allowed no difference: the list says the two differ
    /// where they no longer do.
    pub unused: Vec<&'static Allowed>,
    /// The differences an entry allows, each with its entry.
    pub allowed: Vec<(Difference, &'static Allowed)>,
}

impl Verdict {
    /// Whether the two runs agree but for what the list allows, and the list allows nothing
    /// that didn't show.
    pub fn agrees(&self) -> bool {
        self.unlisted.is_empty() && self.unused.is_empty()
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.unlisted.is_empty() {
            writeln!(
                f,
                "differences between the service and the scripted switch that the \
                 allowed-differences list doesn't hold: {}",
                self.unlisted.len()
            )?;
            for difference in &self.unlisted {
                writeln!(f, "  {difference}")?;
            }
        }
        if !self.unused.is_empty() {
            writeln!(
                f,
                "entries of the allowed-differences list that matched nothing in this flow: {}",
                self.unused.len()
            )?;
            for entry in &self.unused {
                writeln!(f, "  [{}] {}: {}", entry.label, entry.fact, entry.reason)?;
            }
        }
        Ok(())
    }
}

/// Judge `differences`, found in the flow `flow`, against `list`.
pub fn judge(flow: &str, differences: Vec<Difference>, list: &'static [Allowed]) -> Verdict {
    let mut verdict = Verdict::default();
    let mut used = BTreeSet::new();
    for difference in differences {
        let entry = list
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.flow == flow && entry.allows(&difference));
        match entry {
            Some((index, entry)) => {
                used.insert(index);
                verdict.allowed.push((difference, entry));
            }
            None => verdict.unlisted.push(difference),
        }
    }
    verdict.unused = list
        .iter()
        .enumerate()
        .filter(|(index, entry)| entry.flow == flow && !used.contains(index))
        .map(|(_, entry)| entry)
        .collect();
    verdict
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::trace::Line;

    fn line(label: &str, facts: &[(&str, &str)]) -> Line {
        Line {
            label: label.into(),
            facts: facts
                .iter()
                .map(|(fact, value)| ((*fact).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>(),
            call: None,
        }
    }

    fn trace(lines: Vec<Line>) -> Trace {
        Trace { lines }
    }

    static LIST: [Allowed; 2] = [
        Allowed {
            flow: "example",
            label: "{alice} GET /v1/{alice}/apps",
            fact: "body.recovery*",
            service: "null",
            scripted: "*",
            reason: "an example",
            reference: "nowhere",
        },
        Allowed {
            flow: "other flow",
            label: "*",
            fact: "*",
            service: "*",
            scripted: "*",
            reason: "everything, in another flow",
            reference: "nowhere",
        },
    ];

    #[test]
    fn test_differences_none_between_equal_traces() {
        let one = trace(vec![line(
            "public GET /v1/{alice}/identity",
            &[("status", "200")],
        )]);
        assert!(differences(&one, &one.clone()).is_empty());
    }

    #[test]
    fn test_differences_find_a_status_a_missing_member_and_a_type() {
        let service = trace(vec![line(
            "{alice} GET /v1/{alice}/apps",
            &[
                ("status", "200"),
                ("body.lagging", "bool false"),
                ("body.seq", "number 4"),
            ],
        )]);
        let scripted = trace(vec![line(
            "{alice} GET /v1/{alice}/apps",
            &[("status", "404"), ("body.seq", "string of 1")],
        )]);
        let found = differences(&service, &scripted);
        let facts: Vec<&str> = found.iter().map(|d| d.fact.as_str()).collect();
        assert_eq!(facts, ["body.lagging", "body.seq", "status"]);
        assert_eq!(found[0].scripted, None, "the member is missing there");
        assert_eq!(found[2].service.as_deref(), Some("200"));
        assert_eq!(found[2].scripted.as_deref(), Some("404"));
    }

    #[test]
    fn test_differences_end_at_a_different_call() {
        let service = trace(vec![
            line("{alice} GET /v1/{alice}/apps", &[("status", "200")]),
            line("{alice} PUT /v1/{alice}/identity", &[("status", "200")]),
        ]);
        let scripted = trace(vec![
            line("{alice} GET /v1/{alice}/feed", &[("status", "500")]),
            line("{alice} PUT /v1/{alice}/identity", &[("status", "409")]),
        ]);
        let found = differences(&service, &scripted);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].fact, "label");
    }

    #[test]
    fn test_differences_find_a_run_with_more_lines() {
        let one = line("{alice} GET /v1/{alice}/apps", &[("status", "200")]);
        let service = trace(vec![one.clone()]);
        let scripted = trace(vec![one.clone(), one]);
        let found = differences(&service, &scripted);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].fact, "lines");
        assert_eq!(found[0].line, 1);
    }

    #[test]
    fn test_judge_allows_only_what_the_list_holds_for_the_flow() {
        let difference = |fact: &str, service: &str| Difference {
            line: 0,
            label: "{alice} GET /v1/{alice}/apps".into(),
            fact: fact.into(),
            service: Some(service.into()),
            scripted: Some("object of 1".into()),
        };
        let verdict = judge(
            "example",
            vec![
                difference("body.recovery", "null"),
                // The entry names the service's value: another value isn't allowed.
                difference("body.recovery", "bool true"),
                difference("body.lagging", "null"),
            ],
            &LIST,
        );
        assert_eq!(verdict.allowed.len(), 1);
        assert_eq!(verdict.unlisted.len(), 2, "{verdict}");
        assert!(verdict.unused.is_empty());
        assert!(!verdict.agrees());
    }

    #[test]
    fn test_judge_fails_an_entry_that_matched_nothing() {
        let verdict = judge("example", Vec::new(), &LIST);
        assert_eq!(verdict.unused.len(), 1, "only this flow's entries count");
        assert!(!verdict.agrees());
        assert!(verdict.to_string().contains("matched nothing"));
    }
}
