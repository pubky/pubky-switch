//! The core's error type.

/// A failure of an encoding, a signature, a crypto operation or a document check.
///
/// Messages name the rule that failed, usually with its section of the Switch wire format.
/// They never quote decrypted plaintext, secret keys or the text of a document that failed
/// to parse: a decoder's own message can repeat the value it refused, so only the member and
/// the rule are kept (see [`json_reason`]).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// Malformed input, or a document that breaks a rule of the wire format.
    #[error("invalid: {0}")]
    Invalid(String),
    /// A signature didn't verify (Switch wire 2.1).
    #[error("bad signature: {0}")]
    Signature(String),
    /// A sealing, opening or key failure.
    #[error("crypto: {0}")]
    Crypto(String),
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Invalid(json_reason(&error))
    }
}

/// The reason a JSON document didn't parse, without the document's own text.
///
/// A decoder's message can quote the value it refused (`invalid type: string "..."`), and
/// the document may be decrypted plaintext, which must never reach logs or errors. Only the
/// reasons that name a member of the schema, or the strict checker's own (Switch wire 1.1),
/// are kept.
pub fn json_reason(error: &serde_json::Error) -> String {
    use serde_json::error::Category;
    let text = error.to_string();
    let reason = text.split(" at line ").next().unwrap_or_default();
    let what = match error.classify() {
        Category::Syntax => "not valid JSON",
        Category::Eof => "truncated JSON",
        Category::Io => "unreadable JSON",
        Category::Data
            if ["missing field", "duplicate field", "Switch wire "]
                .iter()
                .any(|kept| reason.starts_with(kept)) =>
        {
            reason
        }
        Category::Data => "a member has the wrong type or value",
    };
    format!(
        "json: {what} at line {} column {}",
        error.line(),
        error.column()
    )
}

/// The core's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Shorthand for an [`Error::Invalid`].
pub(crate) fn invalid<T>(why: impl Into<String>) -> Result<T> {
    Err(Error::Invalid(why.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_reason_hides_the_refused_value() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Doc {
            n: u64,
        }
        let error = serde_json::from_str::<Doc>(r#"{"n":"secret-text"}"#).unwrap_err();
        let reason = json_reason(&error);
        assert!(!reason.contains("secret-text"), "{reason}");
        assert!(reason.contains("wrong type or value"), "{reason}");
    }

    #[test]
    fn test_json_reason_keeps_missing_members() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Doc {
            n: u64,
        }
        let error = serde_json::from_str::<Doc>("{}").unwrap_err();
        assert!(json_reason(&error).contains("missing field `n`"));
    }
}
