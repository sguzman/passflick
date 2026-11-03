//! Reject duplicate JSON object keys at any nesting depth before sync admission.
//! serde_json::Value alone keeps the last occurrence, which can hide conflicting
//! account IDs, lifecycle state, or password visibility permissions.

use std::fmt;

use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON with no duplicate object keys")
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut elements = Vec::new();
        while let Some(item) = seq.next_element::<UniqueValue>()? {
            elements.push(item.0);
        }
        Ok(UniqueValue(Value::Array(elements)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut fields = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if fields.contains_key(&key) {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value::<UniqueValue>()?.0;
            fields.insert(key, value);
        }
        Ok(UniqueValue(Value::Object(fields)))
    }
}

/// Do not expose parse error strings: JSON values may contain encrypted
/// private metadata, account identities, or malformed sensitive content.
pub fn parse(raw: &[u8]) -> Result<Value, ()> {
    serde_json::from_slice::<UniqueValue>(raw)
        .map(|value| value.0)
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_duplicate_fields_are_rejected_not_silently_overwritten() {
        for raw in [
            r#"{"object":"sync","object":"sync"}"#,
            r#"{"profile":{"id":"one","id":"two"}}"#,
            r#"{"ciphers":[{"archivedDate":null,"archivedDate":"later"}]}"#,
            r#"{"ciphers":[{"login":{"password":"secret-a","password":"secret-b"}}]}"#,
            r#"{"ciphers":[{"viewPassword":true,"viewPassword":false}]}"#,
        ] {
            assert!(parse(raw.as_bytes()).is_err());
        }
    }

    #[test]
    fn distinct_pascal_and_camel_keys_survive_for_admission_checks() {
        let parsed = parse(br#"{"ciphers":[],"Ciphers":[]}"#).unwrap();
        assert!(parsed.get("ciphers").is_some());
        assert!(parsed.get("Ciphers").is_some());
    }

    #[test]
    fn preserves_json_primitive_types_and_unicode() {
        let parsed =
            parse(br#"{"values":[null,true,false,-5,4294967296,1.5,"\u00f1and\u00fa"]}"#).unwrap();
        assert_eq!(parsed["values"][0], Value::Null);
        assert_eq!(parsed["values"][1], Value::Bool(true));
        assert_eq!(parsed["values"][3], Value::from(-5));
        assert_eq!(parsed["values"][4], Value::from(4294967296_u64));
        assert_eq!(parsed["values"][5], Value::from(1.5));
        assert_eq!(parsed["values"][6], "ñandú");
    }
}
