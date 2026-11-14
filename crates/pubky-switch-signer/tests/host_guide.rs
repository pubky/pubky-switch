//! The signer host guide (`docs/signer-host-guide.md`) names every variant of every public
//! enum a host receives from the signer, and no variant the crate doesn't have.
//!
//! The enums are read from the crate's own sources, so a variant added, renamed or removed
//! fails here until the guide says what a host does with it.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// The guide.
const GUIDE: &str = include_str!("../../../docs/signer-host-guide.md");

/// Every source file of the crate but its test-only modules, by path, so that a public enum
/// in any of them is seen.
const SOURCES: &[(&str, &str)] = &[
    ("lib.rs", include_str!("../src/lib.rs")),
    ("alert.rs", include_str!("../src/alert.rs")),
    ("error.rs", include_str!("../src/error.rs")),
    ("homeserver.rs", include_str!("../src/homeserver.rs")),
    ("key.rs", include_str!("../src/key.rs")),
    ("protocol.rs", include_str!("../src/protocol.rs")),
    ("state.rs", include_str!("../src/state.rs")),
    ("signer.rs", include_str!("../src/signer.rs")),
    (
        "signer/approval.rs",
        include_str!("../src/signer/approval.rs"),
    ),
    ("signer/apps.rs", include_str!("../src/signer/apps.rs")),
    (
        "signer/clients.rs",
        include_str!("../src/signer/clients.rs"),
    ),
    (
        "signer/erasure.rs",
        include_str!("../src/signer/erasure.rs"),
    ),
    ("signer/gate.rs", include_str!("../src/signer/gate.rs")),
    (
        "signer/handover.rs",
        include_str!("../src/signer/handover.rs"),
    ),
    (
        "signer/recovery.rs",
        include_str!("../src/signer/recovery.rs"),
    ),
    (
        "signer/renewal.rs",
        include_str!("../src/signer/renewal.rs"),
    ),
    (
        "signer/restore.rs",
        include_str!("../src/signer/restore.rs"),
    ),
    (
        "signer/revocation.rs",
        include_str!("../src/signer/revocation.rs"),
    ),
    (
        "signer/takeover.rs",
        include_str!("../src/signer/takeover.rs"),
    ),
];

/// The source files compiled only under `cfg(test)`, by path under `src`: a public enum in one
/// of them is never shown to a host, so `SOURCES` needn't hold them.
const TEST_ONLY: &[&str] = &[
    // `#[cfg(test)] mod send_futures;` in `lib.rs`.
    "send_futures.rs",
    // `#[cfg(test)] mod vector_cases;` in `signer.rs`.
    "signer/vector_cases.rs",
];

/// The public enums the guide covers: the alerts, statuses, errors, refusals, skip reasons,
/// sources, outcomes and standings a host receives or returns.
const COVERED: &[&str] = &[
    "Alert",
    "Source",
    "RenewalSkip",
    "SignerError",
    "Refusal",
    "SizedBody",
    "KeyError",
    "AddOutcome",
    "ExportReason",
    "ProtocolError",
    "SignerStatus",
    "AppStanding",
    "AbortOutcome",
];

/// Public enums a host never receives or returns, so the guide needn't name their variants.
/// Each entry says why. Empty: every public enum of the crate is shown to a host.
const NOT_SHOWN: &[&str] = &[];

/// Remove line comments, block comments and string literals from Rust source, so that the
/// braces and words inside them aren't read as code.
fn strip_comments_and_strings(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'/') => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut last = ' ';
                for next in chars.by_ref() {
                    if last == '*' && next == '/' {
                        break;
                    }
                    last = next;
                }
            }
            '"' => {
                let mut escaped = false;
                for next in chars.by_ref() {
                    if escaped {
                        escaped = false;
                    } else if next == '\\' {
                        escaped = true;
                    } else if next == '"' {
                        break;
                    }
                }
                out.push_str("\"\"");
            }
            _ => out.push(c),
        }
    }
    out
}

/// Remove attributes, `#[...]` and `#![...]`, with whatever brackets they hold.
fn strip_attributes(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut chars = code.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '#' && matches!(chars.peek(), Some('[') | Some('!')) {
            if chars.peek() == Some(&'!') {
                chars.next();
            }
            let mut depth = 0usize;
            for next in chars.by_ref() {
                match next {
                    '[' => depth += 1,
                    ']' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The source as code only: no comments, no string contents, no attributes.
fn code_of(source: &str) -> String {
    strip_attributes(&strip_comments_and_strings(source))
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The names of the `pub enum`s in `source`, in order.
fn pub_enum_names(source: &str) -> Vec<String> {
    let code = code_of(source);
    let mut names = Vec::new();
    let mut rest = code.as_str();
    while let Some(at) = rest.find("pub enum ") {
        let before = &rest[..at];
        rest = &rest[at + "pub enum ".len()..];
        if before.chars().next_back().is_some_and(is_ident_char) {
            continue;
        }
        let name: String = rest
            .trim_start()
            .chars()
            .take_while(|c| is_ident_char(*c))
            .collect();
        if !name.is_empty() {
            names.push(name);
        }
    }
    names
}

/// The variant names of `pub enum <name>` in `source`, in order: the first word of each item
/// at the enum's top level, whatever payload follows it (a tuple, a struct, a discriminant).
/// `None` when `source` holds no such enum.
fn enum_variants(source: &str, name: &str) -> Option<Vec<String>> {
    let code = code_of(source);
    let head = format!("pub enum {name}");
    let mut search = 0;
    let body_start = loop {
        let at = search + code[search..].find(&head)?;
        let after = &code[at + head.len()..];
        if !after.starts_with(is_ident_char) {
            break at + head.len() + after.find('{')? + 1;
        }
        search = at + head.len();
    };
    let mut variants = Vec::new();
    let mut depth = 1usize;
    let mut expecting = true;
    let mut word = String::new();
    for c in code[body_start..].chars() {
        if depth == 1 && expecting {
            if is_ident_char(c) {
                word.push(c);
                continue;
            }
            if !word.is_empty() {
                variants.push(std::mem::take(&mut word));
                expecting = false;
            }
        }
        match c {
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            ',' if depth == 1 => expecting = true,
            _ => {}
        }
    }
    Some(variants)
}

/// Each covered enum with its variants, read from the crate's sources.
fn covered_enums() -> Vec<(String, Vec<String>)> {
    COVERED
        .iter()
        .map(|name| {
            let variants = SOURCES
                .iter()
                .find_map(|(_, source)| enum_variants(source, name))
                .unwrap_or_else(|| panic!("no source holds `pub enum {name}`"));
            assert!(!variants.is_empty(), "`{name}` has no variants");
            ((*name).to_owned(), variants)
        })
        .collect()
}

/// The `Name::Variant` pairs of `enums` that `guide` doesn't name in backticks.
fn missing_variants(guide: &str, enums: &[(String, Vec<String>)]) -> Vec<String> {
    enums
        .iter()
        .flat_map(|(name, variants)| variants.iter().map(move |v| format!("{name}::{v}")))
        .filter(|path| !guide.contains(&format!("`{path}`")))
        .collect()
}

/// The `Name::Variant` paths `guide` names in backticks whose `Name` is one of `enums` and
/// whose variant it doesn't have.
fn unknown_variants(guide: &str, enums: &[(String, Vec<String>)]) -> Vec<String> {
    let mut unknown = Vec::new();
    for (i, span) in guide.split('`').enumerate() {
        // The odd pieces are the insides of backtick spans.
        if i % 2 == 0 {
            continue;
        }
        let Some((name, rest)) = span.split_once("::") else {
            continue;
        };
        let variant: String = rest.chars().take_while(|c| is_ident_char(*c)).collect();
        if let Some((_, variants)) = enums.iter().find(|(n, _)| n == name)
            && !variants.contains(&variant)
        {
            unknown.push(format!("{name}::{variant}"));
        }
    }
    unknown
}

#[test]
fn test_host_guide_names_every_variant() {
    // Every public enum of the crate is either covered or listed as never shown to a host.
    for (path, source) in SOURCES {
        for name in pub_enum_names(source) {
            assert!(
                COVERED.contains(&name.as_str()) || NOT_SHOWN.contains(&name.as_str()),
                "{path} holds `pub enum {name}`, which is neither covered by the host guide \
                 nor listed as not shown to a host"
            );
        }
    }
    let missing = missing_variants(GUIDE, &covered_enums());
    assert!(
        missing.is_empty(),
        "the host guide doesn't name these variants: {missing:?}"
    );
}

/// The paths under `dir`, relative to `root` and joined with `/`, of every `.rs` file in it
/// and its subfolders.
fn rust_files(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(root, &path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let relative = path.strip_prefix(root).unwrap();
            let parts: Vec<String> = relative
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            out.push(parts.join("/"));
        }
    }
}

#[test]
fn test_host_guide_sources_cover_every_module() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &root, &mut files);
    assert!(
        files.iter().any(|f| f == "lib.rs"),
        "no sources found under {}",
        root.display()
    );
    let mut uncovered = Vec::new();
    for file in &files {
        if TEST_ONLY.contains(&file.as_str()) || SOURCES.iter().any(|(path, _)| path == file) {
            continue;
        }
        let source = std::fs::read_to_string(root.join(file)).unwrap();
        if !pub_enum_names(&source).is_empty() {
            uncovered.push(file.clone());
        }
    }
    assert!(
        uncovered.is_empty(),
        "these sources hold a `pub enum` but aren't in `SOURCES`: {uncovered:?}"
    );
    // Every listed path is a file that exists, so a moved module isn't silently skipped.
    for (path, _) in SOURCES {
        assert!(
            files.iter().any(|f| f == path),
            "`SOURCES` names {path}, which isn't under src"
        );
    }
    for path in TEST_ONLY {
        assert!(
            files.iter().any(|f| f == path),
            "`TEST_ONLY` names {path}, which isn't under src"
        );
    }
}

#[test]
fn test_host_guide_names_no_unknown_variant() {
    let unknown = unknown_variants(GUIDE, &covered_enums());
    assert!(
        unknown.is_empty(),
        "the host guide names variants the crate doesn't have: {unknown:?}"
    );
}

#[test]
fn test_host_guide_missing_variant_is_reported() {
    let enums = covered_enums();
    assert!(missing_variants(GUIDE, &enums).is_empty());
    let without = GUIDE.replace("`Alert::ClockOff`", "");
    assert_eq!(missing_variants(&without, &enums), ["Alert::ClockOff"]);
    // A stale name is reported too.
    let stale = format!("{GUIDE}\n`Alert::NoSuchAlert`\n");
    assert_eq!(unknown_variants(&stale, &enums), ["Alert::NoSuchAlert"]);
}

#[test]
fn test_host_guide_enum_parser_reads_variants() {
    let sample = r#"
        /// Not this one: `pub enum Hidden { No }` is in a comment.
        pub struct Outcome { pub inner: u8 }

        /// A sample.
        #[derive(Debug, thiserror::Error)]
        #[non_exhaustive]
        pub enum Sample {
            /// A unit variant, with braces in its doc: `{ x }`.
            #[error("unit {0}")]
            Unit,
            /// A tuple variant.
            Tuple(#[from] std::io::Error, Vec<(u8, u8)>),
            /// A struct variant, with nested braces in its payload.
            Struct {
                /// A field.
                #[serde(rename = "a,b")]
                field: Option<Vec<String>>,
                other: [u8; 16],
            },
            /* A block comment, with a comma, */ Last = 7
        }

        pub enum SampleTwo { One }
        pub(crate) enum Inner { Two }
    "#;
    assert_eq!(
        enum_variants(sample, "Sample").unwrap(),
        ["Unit", "Tuple", "Struct", "Last"]
    );
    assert_eq!(enum_variants(sample, "SampleTwo").unwrap(), ["One"]);
    assert_eq!(enum_variants(sample, "Hidden"), None);
    assert_eq!(enum_variants(sample, "Inner"), None);
    assert_eq!(pub_enum_names(sample), ["Sample", "SampleTwo"]);
}
