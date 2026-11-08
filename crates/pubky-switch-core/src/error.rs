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

/// A size or shape rule whose refusal the wire format answers with a fixed status: an
/// envelope at the inbox (Switch wire 4.4) or a sealed value's ciphertext (Switch wire 6.2).
///
/// Like [`Error`], the text names the rule and never the refused bytes.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SizeRefusal {
    /// Over the size limit: answered `413 too_large`.
    #[error("too large: {0}")]
    TooLarge(String),
    /// Malformed, or a length the rule doesn't allow: answered `400 bad_request`.
    #[error("bad request: {0}")]
    BadRequest(String),
}

impl SizeRefusal {
    /// The HTTP status of the answer: 413 or 400 (Switch wire 7.6).
    pub fn status(&self) -> u16 {
        match self {
            Self::TooLarge(_) => 413,
            Self::BadRequest(_) => 400,
        }
    }

    /// The error `code` of the answer: `too_large` or `bad_request` (Switch wire 7.6).
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooLarge(_) => "too_large",
            Self::BadRequest(_) => "bad_request",
        }
    }
}

impl From<SizeRefusal> for Error {
    fn from(refusal: SizeRefusal) -> Self {
        match refusal {
            SizeRefusal::TooLarge(why) | SizeRefusal::BadRequest(why) => Self::Invalid(why),
        }
    }
}

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
    fn test_size_refusal_maps_to_its_answer() {
        let too_large = SizeRefusal::TooLarge("rule".into());
        assert_eq!((too_large.status(), too_large.code()), (413, "too_large"));
        let bad = SizeRefusal::BadRequest("rule".into());
        assert_eq!((bad.status(), bad.code()), (400, "bad_request"));
        assert_eq!(Error::from(bad), Error::Invalid("rule".into()));
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
