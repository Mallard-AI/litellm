use std::{future::Future, pin::Pin, str::FromStr, time::SystemTime};

use litellm_auth_types::SecretValue;

pub use crate::error::KeyHashError;
use crate::{KeyError, hash_token};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyHash(String);

impl KeyHash {
    pub fn from_token(token: &SecretValue) -> Self {
        Self(hash_token(token.expose()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_digest(digest: &str) -> Result<Self, KeyHashError> {
        Self::from_str(digest)
    }
}

impl FromStr for KeyHash {
    type Err = KeyHashError;

    fn from_str(digest: &str) -> Result<Self, Self::Err> {
        if digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(digest.to_owned()))
        } else {
            Err(KeyHashError)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyStatus {
    Active { expires_at: Option<SystemTime> },
    Revoked,
}

pub type LookupFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<KeyStatus>, KeyError>> + Send + 'a>>;

pub trait KeyLookup: Send + Sync {
    fn lookup<'a>(&'a self, hash: &'a KeyHash) -> LookupFuture<'a>;
}

pub async fn verify_key(
    lookup: &dyn KeyLookup,
    token: &SecretValue,
    now: impl FnOnce() -> SystemTime,
) -> Result<KeyHash, KeyError> {
    let hash = KeyHash::from_token(token);
    match lookup.lookup(&hash).await? {
        Some(KeyStatus::Active { expires_at }) => {
            if expires_at.is_some_and(|expiry| expiry <= now()) {
                return Err(KeyError::Expired);
            }
            Ok(hash)
        }
        Some(KeyStatus::Revoked) | None => Err(KeyError::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{KeyHash, KeyHashError};

    #[rstest]
    #[case::short("abc")]
    #[case::uppercase("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    #[case::non_hex("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")]
    fn digest_requires_64_lowercase_hex(#[case] digest: &str) {
        assert_eq!(KeyHash::from_digest(digest), Err(KeyHashError));
    }
}
