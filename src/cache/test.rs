use super::{CachedJWKS, JwksSource, RequestError, TimeoutSpec};
use jsonwebtoken::jwk::JwkSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const JWKS_SAMPLE: &str = include_str!("../../jwks-sample.json");

#[tokio::test]
async fn test_reqwest_gcp_jwk_integration() {
    let cache = CachedJWKS::new(
        "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
            .parse()
            .unwrap(),
        Duration::from_secs(60 * 60),
        TimeoutSpec::default(),
    )
    .unwrap();

    let jwks = cache.get().await.unwrap();

    assert_eq!(jwks.keys.len(), 2);
}

#[tokio::test]
async fn test_reqwest_gcp_pub_keys_integration() {
    let cache = CachedJWKS::new_rsa_pkeys(
        "https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys"
            .parse()
            .unwrap(),
        Duration::from_secs(60 * 60),
        TimeoutSpec::default(),
    )
    .unwrap();

    let jwks = cache.get().await.unwrap();

    assert_eq!(jwks.keys.len(), 5);
}

#[derive(Clone)]
struct JwksSourceMock {
    jwks: JwkSet,
    expires: Duration,
    take_time: Duration,
    fetched: Arc<Mutex<usize>>,
}

impl JwksSourceMock {
    pub fn new(expires: Duration, take_time: Duration) -> Self {
        Self {
            jwks: serde_json::from_str(JWKS_SAMPLE).unwrap(),
            expires,
            take_time,
            fetched: Arc::new(Mutex::new(0)),
        }
    }
}

impl JwksSource for JwksSourceMock {
    type Error = ();

    async fn get_jwks(
        self,
        _url: url::Url,
        _as_pkeys: bool,
        now: SystemTime,
    ) -> Result<(JwkSet, SystemTime), Self::Error> {
        {
            let mut counter = self.fetched.lock().unwrap();
            *counter += 1;
        }

        tokio::time::sleep(self.take_time).await;

        Ok((self.jwks.clone(), now + self.expires))
    }
}

#[tokio::test]
async fn test_fetch_concurrent_from_empty() {
    let source = JwksSourceMock::new(Duration::from_secs(60 * 60), Duration::ZERO);
    let cache = CachedJWKS::from_source(
        "https://example.com".parse().unwrap(),
        false,
        Duration::from_secs(60),
        Default::default(),
        source.clone(),
    );

    const N: usize = 10;
    let mut tasks = tokio::task::JoinSet::new();
    let barrier = Arc::new(tokio::sync::Barrier::new(N));

    for _ in 0..N {
        let barrier = barrier.clone();
        let cache = cache.clone();
        tasks.spawn(async move {
            barrier.wait().await;

            cache.get().await.unwrap()
        });
    }

    let results = tasks.join_all().await;

    for r in results {
        assert_eq!(r.keys.len(), 1);
    }

    assert_eq!(
        source.fetched.lock().unwrap().clone(),
        1,
        "Should only performed fetch IO once"
    );
}

#[tokio::test]
async fn test_background_refresh_and_expire() {
    let source = JwksSourceMock::new(Duration::from_millis(20), Duration::ZERO);
    let cache = CachedJWKS::from_source(
        "https://example.com".parse().unwrap(),
        false,
        Duration::from_millis(10),
        TimeoutSpec {
            retries: 0,
            retry_after: Duration::from_millis(1),
            backoff: Duration::ZERO,
            deadline: Duration::from_millis(1),
        },
        source.clone(),
    );

    cache.get().await.unwrap();
    cache.get().await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    cache.get().await.unwrap();
    cache.get().await.unwrap();
    cache.get().await.unwrap();
    tokio::time::sleep(Duration::from_millis(1)).await;

    assert_eq!(
        source.fetched.lock().unwrap().clone(),
        2,
        "Should only performed fetch IO in background"
    );

    tokio::time::sleep(Duration::from_millis(30)).await;
    cache.get().await.unwrap();
    cache.get().await.unwrap();

    assert_eq!(
        source.fetched.lock().unwrap().clone(),
        3,
        "Should have refreshed from IO"
    );
}

#[tokio::test]
async fn test_timeout_policy() {
    let source = JwksSourceMock::new(Duration::from_millis(300), Duration::from_millis(100));
    let cache = CachedJWKS::from_source(
        "https://example.com".parse().unwrap(),
        false,
        Duration::from_millis(200),
        TimeoutSpec {
            retries: 3,
            retry_after: Duration::from_millis(10),
            backoff: Duration::from_millis(1),
            deadline: Duration::from_millis(50),
        },
        source.clone(),
    );

    let _err = cache
        .get()
        .await
        .expect_err("Expected timeout to be reached");

    assert!(
        matches!(RequestError::<()>::Timeout, _err),
        "Expected timeout error"
    );
    assert_eq!(
        source.fetched.lock().unwrap().clone(),
        4, // initial request + 3 retries
        "Should have retried 3 times"
    );
}
