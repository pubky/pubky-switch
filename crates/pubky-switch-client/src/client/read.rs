//! Reading checked answer bodies: strict JSON (Switch wire 1.1), then each member by its
//! type. Errors name the member and never quote its value.

use pubky_switch_core::chain::SignedHead;
use pubky_switch_core::enc::{app_id_decode, pubky_key, unb64, unb64_array};
use pubky_switch_core::json::{Doc, parse_json_as};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::parse_rfc3339;
use serde_json::{Map, Value};

use crate::error::ClientError;

/// Parse a checked body as strict JSON read as `doc`, which must be an object.
pub(crate) fn body<'a>(
    bytes: &[u8],
    doc: Doc<'_>,
    what: &'a str,
) -> Result<(Value, &'a str), ClientError> {
    let value: Value = parse_json_as(bytes, doc)
        .map_err(|_| ClientError::InvalidResponse(format!("{what} isn't strict JSON")))?;
    if !value.is_object() {
        return Err(ClientError::InvalidResponse(format!(
            "{what} isn't a JSON object"
        )));
    }
    Ok((value, what))
}

/// A JSON object of an answer, read member by member.
#[derive(Clone, Copy)]
pub(crate) struct Obj<'a> {
    map: &'a Map<String, Value>,
    what: &'a str,
}

fn bad(what: &str, name: &str) -> ClientError {
    ClientError::InvalidResponse(format!("{what}: `{name}` is missing or malformed"))
}

impl<'a> Obj<'a> {
    /// The object `value`, described as `what` in errors.
    pub(crate) fn of(value: &'a Value, what: &'a str) -> Result<Self, ClientError> {
        value
            .as_object()
            .map(|map| Self { map, what })
            .ok_or_else(|| ClientError::InvalidResponse(format!("{what} isn't a JSON object")))
    }

    /// A member that is present and not `null`.
    pub(crate) fn get(&self, name: &str) -> Option<&'a Value> {
        self.map.get(name).filter(|value| !value.is_null())
    }

    fn req(&self, name: &str) -> Result<&'a Value, ClientError> {
        self.get(name).ok_or_else(|| bad(self.what, name))
    }

    fn opt<T>(
        &self,
        name: &str,
        read: impl FnOnce(&Self, &str) -> Result<T, ClientError>,
    ) -> Result<Option<T>, ClientError> {
        match self.get(name) {
            None => Ok(None),
            Some(_) => read(self, name).map(Some),
        }
    }

    pub(crate) fn object(&self, name: &str) -> Result<Obj<'a>, ClientError> {
        Obj::of(self.req(name)?, self.what)
    }

    pub(crate) fn value(&self, name: &str) -> Option<Value> {
        self.get(name).cloned()
    }

    pub(crate) fn u64(&self, name: &str) -> Result<u64, ClientError> {
        self.req(name)?.as_u64().ok_or_else(|| bad(self.what, name))
    }

    pub(crate) fn opt_u64(&self, name: &str) -> Result<Option<u64>, ClientError> {
        self.opt(name, Self::u64)
    }

    pub(crate) fn bool(&self, name: &str) -> Result<bool, ClientError> {
        self.req(name)?
            .as_bool()
            .ok_or_else(|| bad(self.what, name))
    }

    pub(crate) fn opt_bool(&self, name: &str) -> Result<Option<bool>, ClientError> {
        self.opt(name, Self::bool)
    }

    pub(crate) fn str(&self, name: &str) -> Result<&'a str, ClientError> {
        self.req(name)?.as_str().ok_or_else(|| bad(self.what, name))
    }

    pub(crate) fn string(&self, name: &str) -> Result<String, ClientError> {
        self.str(name).map(str::to_owned)
    }

    pub(crate) fn bytes(&self, name: &str) -> Result<Vec<u8>, ClientError> {
        unb64(self.str(name)?).map_err(|_| bad(self.what, name))
    }

    pub(crate) fn b64n<const N: usize>(&self, name: &str) -> Result<[u8; N], ClientError> {
        unb64_array::<N>(self.str(name)?).map_err(|_| bad(self.what, name))
    }

    pub(crate) fn opt_b64n<const N: usize>(
        &self,
        name: &str,
    ) -> Result<Option<[u8; N]>, ClientError> {
        self.opt(name, Self::b64n::<N>)
    }

    pub(crate) fn pubky(&self, name: &str) -> Result<[u8; 32], ClientError> {
        pubky_key(self.str(name)?).map_err(|_| bad(self.what, name))
    }

    pub(crate) fn app_id(&self, name: &str) -> Result<[u8; 16], ClientError> {
        app_id_decode(self.str(name)?).map_err(|_| bad(self.what, name))
    }

    pub(crate) fn time(&self, name: &str) -> Result<u64, ClientError> {
        parse_rfc3339(self.str(name)?).map_err(|_| bad(self.what, name))
    }

    pub(crate) fn opt_time(&self, name: &str) -> Result<Option<u64>, ClientError> {
        self.opt(name, Self::time)
    }

    pub(crate) fn doc(&self, name: &str) -> Result<SignedDoc, ClientError> {
        doc(self.req(name)?).ok_or_else(|| bad(self.what, name))
    }

    pub(crate) fn opt_doc(&self, name: &str) -> Result<Option<SignedDoc>, ClientError> {
        self.opt(name, Self::doc)
    }

    pub(crate) fn head(&self, name: &str) -> Result<SignedHead, ClientError> {
        SignedHead::from_value(self.req(name)?).map_err(|_| bad(self.what, name))
    }

    pub(crate) fn opt_head(&self, name: &str) -> Result<Option<SignedHead>, ClientError> {
        self.opt(name, Self::head)
    }

    /// An array member; an absent or `null` one reads as empty.
    pub(crate) fn list(&self, name: &str) -> Result<&'a [Value], ClientError> {
        match self.get(name) {
            None => Ok(&[]),
            Some(value) => value
                .as_array()
                .map(Vec::as_slice)
                .ok_or_else(|| bad(self.what, name)),
        }
    }

    /// A required array member: an absent or `null` one is malformed.
    pub(crate) fn required_list(&self, name: &str) -> Result<&'a [Value], ClientError> {
        self.req(name)?
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| bad(self.what, name))
    }

    /// Each element of a required array member, read as an object.
    pub(crate) fn required_objects(&self, name: &str) -> Result<Vec<Obj<'a>>, ClientError> {
        self.required_list(name)?
            .iter()
            .map(|value| Obj::of(value, self.what))
            .collect()
    }

    /// Each element of a required array member, read with `read`.
    pub(crate) fn required_each<T>(
        &self,
        name: &str,
        read: impl Fn(&'a Value) -> Option<T>,
    ) -> Result<Vec<T>, ClientError> {
        self.required_list(name)?
            .iter()
            .map(|value| read(value).ok_or_else(|| bad(self.what, name)))
            .collect()
    }

    /// Each element of an array member, read as an object.
    pub(crate) fn objects(&self, name: &str) -> Result<Vec<Obj<'a>>, ClientError> {
        self.list(name)?
            .iter()
            .map(|value| Obj::of(value, self.what))
            .collect()
    }

    /// Each element of an array member, read with `read`.
    pub(crate) fn each<T>(
        &self,
        name: &str,
        read: impl Fn(&'a Value) -> Option<T>,
    ) -> Result<Vec<T>, ClientError> {
        self.list(name)?
            .iter()
            .map(|value| read(value).ok_or_else(|| bad(self.what, name)))
            .collect()
    }
}

/// A signed document in its carrying form, `{ "body", "sig" }`.
pub(crate) fn doc(value: &Value) -> Option<SignedDoc> {
    serde_json::from_value(value.clone()).ok()
}

/// A Pubky ID.
pub(crate) fn pubky(value: &Value) -> Option<[u8; 32]> {
    value.as_str().and_then(|text| pubky_key(text).ok())
}

/// A `b64(32)`.
pub(crate) fn b64_32(value: &Value) -> Option<[u8; 32]> {
    value.as_str().and_then(|text| unb64_array::<32>(text).ok())
}

/// An integer.
pub(crate) fn int(value: &Value) -> Option<u64> {
    value.as_u64()
}

/// A string.
pub(crate) fn string(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}
