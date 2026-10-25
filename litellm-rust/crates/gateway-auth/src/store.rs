use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use moka::future::Cache;
use serde_json::Value;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{KeyHash, KeyPolicy};

pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

#[derive(Clone, Debug)]
pub enum KeyRecord {
    Policy(KeyPolicy),
    Unsupported(Arc<[String]>),
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("key store backend failed: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("key cache failed: {0}")]
    Cache(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl StoreError {
    pub fn backend<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Backend(Box::new(error))
    }

    pub fn cache<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Cache(Box::new(error))
    }
}

pub trait KeyStore: Send + Sync {
    fn find<'a>(&'a self, hash: &'a KeyHash) -> StoreFuture<'a, Option<KeyRecord>>;
}

pub trait KeyCache: Send + Sync {
    fn get<'a>(&'a self, hash: &'a KeyHash) -> StoreFuture<'a, Option<KeyRecord>>;
    fn insert<'a>(&'a self, hash: &'a KeyHash, record: KeyRecord) -> StoreFuture<'a, ()>;
    fn remove<'a>(&'a self, hash: &'a KeyHash) -> StoreFuture<'a, ()>;
    fn clear(&self) -> StoreFuture<'_, ()>;
}

#[derive(Clone)]
pub struct MokaKeyCache {
    entries: Cache<KeyHash, KeyRecord>,
}

impl MokaKeyCache {
    pub fn new(capacity: u64, ttl: Duration) -> Self {
        Self {
            entries: Cache::builder()
                .max_capacity(capacity)
                .time_to_live(ttl)
                .build(),
        }
    }
}

impl KeyCache for MokaKeyCache {
    fn get<'a>(&'a self, hash: &'a KeyHash) -> StoreFuture<'a, Option<KeyRecord>> {
        Box::pin(async move { Ok(self.entries.get(hash).await) })
    }

    fn insert<'a>(&'a self, hash: &'a KeyHash, record: KeyRecord) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            self.entries.insert(hash.clone(), record).await;
            Ok(())
        })
    }

    fn remove<'a>(&'a self, hash: &'a KeyHash) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            self.entries.invalidate(hash).await;
            Ok(())
        })
    }

    fn clear(&self) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            self.entries.invalidate_all();
            self.entries.run_pending_tasks().await;
            Ok(())
        })
    }
}

#[derive(Default)]
struct Fence(u64);

impl Fence {
    fn snapshot(&self) -> u64 {
        self.0
    }

    fn matches(&self, version: u64) -> bool {
        self.0 == version
    }

    fn invalidate(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }
}

pub struct Cached<S, C> {
    store: S,
    cache: C,
    fence: Arc<Mutex<Fence>>,
}

impl<S, C> Cached<S, C> {
    pub fn new(store: S, cache: C) -> Self {
        Self {
            store,
            cache,
            fence: Arc::new(Mutex::new(Fence::default())),
        }
    }

    pub async fn invalidate(&self, invalidation: Invalidation) -> Result<(), StoreError>
    where
        C: KeyCache,
    {
        let mut fence = self.fence.lock().await;
        match invalidation {
            Invalidation::Key(hash) => {
                fence.invalidate();
                self.cache.remove(&hash).await
            }
            Invalidation::All => {
                fence.invalidate();
                self.cache.clear().await
            }
        }
    }
}

impl<S, C> KeyStore for Cached<S, C>
where
    S: KeyStore,
    C: KeyCache,
{
    fn find<'a>(&'a self, hash: &'a KeyHash) -> StoreFuture<'a, Option<KeyRecord>> {
        Box::pin(async move {
            if let Some(record) = self.cache.get(hash).await? {
                return Ok(Some(record));
            }
            let version = self.fence.lock().await.snapshot();
            let loaded = self.store.find(hash).await?;
            let Some(record) = loaded.clone() else {
                return Ok(None);
            };
            let fence = self.fence.lock().await;
            if fence.matches(version) {
                self.cache.insert(hash, record).await?;
            }
            Ok(loaded)
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Invalidation {
    Key(KeyHash),
    All,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum InvalidationError {
    #[error("invalidation JSON must be an object")]
    NotObject,
    #[error("invalidation JSON is malformed: {0}")]
    Malformed(String),
    #[error("invalidation cache_key must be a non-empty string")]
    InvalidCacheKey,
}

pub fn decode_invalidation(input: &[u8]) -> Result<Invalidation, InvalidationError> {
    let value: Value = serde_json::from_slice(input)
        .map_err(|error| InvalidationError::Malformed(error.to_string()))?;
    let object = value.as_object().ok_or(InvalidationError::NotObject)?;
    let cache_key = object
        .get("cache_key")
        .ok_or(InvalidationError::InvalidCacheKey)?
        .as_str()
        .ok_or(InvalidationError::InvalidCacheKey)?;
    if cache_key.is_empty() {
        return Err(InvalidationError::InvalidCacheKey);
    }
    match KeyHash::from_digest(cache_key) {
        Ok(hash) => Ok(Invalidation::Key(hash)),
        Err(_) => Ok(Invalidation::All),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        sync::Arc,
        time::Duration,
    };

    use rstest::{fixture, rstest};
    use tokio::sync::{Mutex, Notify};

    use super::*;

    type StoreResult = Result<Option<KeyRecord>, StoreError>;
    type StoreResults = Arc<Mutex<VecDeque<StoreResult>>>;

    #[derive(Clone, Default)]
    struct FakeStore {
        records: StoreResults,
    }

    impl FakeStore {
        async fn push(&self, result: Result<Option<KeyRecord>, StoreError>) {
            self.records.lock().await.push_back(result);
        }
    }

    impl KeyStore for FakeStore {
        fn find<'a>(&'a self, _: &'a KeyHash) -> StoreFuture<'a, Option<KeyRecord>> {
            Box::pin(async move { self.records.lock().await.pop_front().unwrap_or(Ok(None)) })
        }
    }

    #[derive(Clone, Default)]
    struct FakeCache {
        records: Arc<Mutex<HashMap<KeyHash, KeyRecord>>>,
    }

    impl KeyCache for FakeCache {
        fn get<'a>(&'a self, hash: &'a KeyHash) -> StoreFuture<'a, Option<KeyRecord>> {
            Box::pin(async move { Ok(self.records.lock().await.get(hash).cloned()) })
        }

        fn insert<'a>(&'a self, hash: &'a KeyHash, record: KeyRecord) -> StoreFuture<'a, ()> {
            Box::pin(async move {
                self.records.lock().await.insert(hash.clone(), record);
                Ok(())
            })
        }

        fn remove<'a>(&'a self, hash: &'a KeyHash) -> StoreFuture<'a, ()> {
            Box::pin(async move {
                self.records.lock().await.remove(hash);
                Ok(())
            })
        }

        fn clear(&self) -> StoreFuture<'_, ()> {
            Box::pin(async move {
                self.records.lock().await.clear();
                Ok(())
            })
        }
    }

    struct BlockingStore {
        started: Arc<Notify>,
        resume: Arc<Notify>,
        record: Option<KeyRecord>,
    }

    impl KeyStore for BlockingStore {
        fn find<'a>(&'a self, _: &'a KeyHash) -> StoreFuture<'a, Option<KeyRecord>> {
            Box::pin(async move {
                self.started.notify_one();
                self.resume.notified().await;
                Ok(self.record.clone())
            })
        }
    }

    #[fixture]
    fn hash() -> KeyHash {
        KeyHash::from_digest(&"a".repeat(64)).expect("valid digest")
    }

    #[fixture]
    fn policy() -> KeyPolicy {
        KeyPolicy::unrestricted()
    }

    #[rstest]
    #[tokio::test]
    async fn fake_store_hit_is_cached(hash: KeyHash, policy: KeyPolicy) {
        let store = FakeStore::default();
        store.push(Ok(Some(KeyRecord::Policy(policy)))).await;
        let cache = FakeCache::default();
        let cached = Cached::new(store.clone(), cache);
        assert!(cached.find(&hash).await.expect("store result").is_some());
        assert!(cached.find(&hash).await.expect("cache result").is_some());
    }

    #[rstest]
    #[tokio::test]
    async fn misses_are_not_cached(hash: KeyHash) {
        let store = FakeStore::default();
        store.push(Ok(None)).await;
        store
            .push(Ok(Some(KeyRecord::Unsupported(Arc::from([
                "changed".to_owned()
            ])))))
            .await;
        let cached = Cached::new(store, FakeCache::default());
        assert!(cached.find(&hash).await.expect("first miss").is_none());
        assert!(cached.find(&hash).await.expect("second lookup").is_some());
    }

    #[rstest]
    #[tokio::test]
    async fn backend_errors_are_not_misses(hash: KeyHash) {
        let store = FakeStore::default();
        store
            .push(Err(StoreError::backend(std::io::Error::other(
                "backend failure",
            ))))
            .await;
        let cached = Cached::new(store, FakeCache::default());
        let error = cached.find(&hash).await.expect_err("backend failure");
        assert!(matches!(&error, StoreError::Backend(_)));
        assert_eq!(
            std::error::Error::source(&error)
                .expect("source preserved")
                .to_string(),
            "backend failure"
        );
    }

    #[rstest]
    #[tokio::test]
    async fn remove_and_clear_evict_records(hash: KeyHash, policy: KeyPolicy) {
        let cache = FakeCache::default();
        cache
            .insert(&hash, KeyRecord::Policy(policy))
            .await
            .expect("insert");
        let cached = Cached::new(FakeStore::default(), cache.clone());
        cached
            .invalidate(Invalidation::Key(hash.clone()))
            .await
            .expect("remove");
        assert!(cache.get(&hash).await.expect("get").is_none());
        cache
            .insert(
                &hash,
                KeyRecord::Unsupported(Arc::from(["field".to_owned()])),
            )
            .await
            .expect("insert");
        cached.invalidate(Invalidation::All).await.expect("clear");
        assert!(cache.get(&hash).await.expect("get").is_none());
    }

    #[rstest]
    #[tokio::test]
    async fn moka_cache_expires_entries(hash: KeyHash, policy: KeyPolicy) {
        let cache = MokaKeyCache::new(4, Duration::from_millis(20));
        cache
            .insert(&hash, KeyRecord::Policy(policy))
            .await
            .expect("insert");
        assert!(cache.get(&hash).await.expect("hit").is_some());
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(cache.get(&hash).await.expect("expired").is_none());
    }

    #[rstest]
    #[tokio::test]
    async fn cached_moka_expiration_refetches_store(hash: KeyHash) {
        let store = FakeStore::default();
        store
            .push(Ok(Some(KeyRecord::Unsupported(Arc::from([
                "before".to_owned()
            ])))))
            .await;
        store
            .push(Ok(Some(KeyRecord::Unsupported(Arc::from([
                "after".to_owned()
            ])))))
            .await;
        let cache = MokaKeyCache::new(4, Duration::from_millis(20));
        let cached = Cached::new(store, cache);

        let first = cached.find(&hash).await.expect("first lookup");
        match first {
            Some(KeyRecord::Unsupported(fields)) => {
                assert_eq!(fields.as_ref(), &["before".to_owned()]);
            }
            _ => panic!("first lookup returned an unexpected record"),
        }

        tokio::time::sleep(Duration::from_millis(40)).await;

        let second = cached.find(&hash).await.expect("second lookup");
        match second {
            Some(KeyRecord::Unsupported(fields)) => {
                assert_eq!(fields.as_ref(), &["after".to_owned()]);
            }
            _ => panic!("second lookup returned an unexpected record"),
        }
    }

    #[rstest]
    #[tokio::test]
    async fn invalidation_during_load_does_not_refill(hash: KeyHash, policy: KeyPolicy) {
        let started = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        let store = BlockingStore {
            started: started.clone(),
            resume: resume.clone(),
            record: Some(KeyRecord::Policy(policy)),
        };
        let cache = FakeCache::default();
        let cached = Arc::new(Cached::new(store, cache.clone()));
        let task = tokio::spawn({
            let cached = cached.clone();
            let hash = hash.clone();
            async move { cached.find(&hash).await }
        });
        started.notified().await;
        cached
            .invalidate(Invalidation::Key(hash.clone()))
            .await
            .expect("invalidate");
        resume.notify_one();
        task.await.expect("load task").expect("load result");
        assert!(cache.get(&hash).await.expect("get").is_none());
    }

    #[rstest]
    #[case::token_digest(
        br#"{"cache_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","new_value":1,"ttl":4}"#,
        true
    )]
    #[case::team_policy(br#"{"cache_key":"team:abc"}"#, false)]
    #[case::uppercase_digest(
        br#"{"cache_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        false
    )]
    fn decodes_invalidation(#[case] input: &[u8], #[case] is_key: bool) {
        let invalidation = decode_invalidation(input).expect("valid invalidation");
        assert_eq!(matches!(invalidation, Invalidation::Key(_)), is_key);
    }

    #[rstest]
    #[case::missing(br#"{}"#)]
    #[case::number(br#"{"cache_key":3}"#)]
    #[case::not_object(br#"[1]"#)]
    #[case::malformed(br#"not-json"#)]
    #[case::empty(br#"{"cache_key":""}"#)]
    fn rejects_invalid_invalidation(#[case] input: &[u8]) {
        assert!(decode_invalidation(input).is_err());
    }
}
