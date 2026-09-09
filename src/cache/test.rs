use super::{CachedJWKS, JwksSource, TimeoutSpec};
use jsonwebtoken::jwk::JwkSet;
use std::sync::{Arc, atomic};
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

    assert!(!jwks.keys.is_empty());
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

    assert!(!jwks.keys.is_empty());
}

#[derive(Clone)]
struct JwksSourceMock {
    jwks: JwkSet,
    expires: Duration,
    take_time: Duration,
    fetched: Arc<atomic::AtomicUsize>,
}

impl JwksSourceMock {
    pub fn new(expires: Duration, take_time: Duration) -> Self {
        Self {
            jwks: serde_json::from_str(JWKS_SAMPLE).unwrap(),
            expires,
            take_time,
            fetched: Arc::new(atomic::AtomicUsize::new(0)),
        }
    }

    fn fetch_count(&self) -> usize {
        self.fetched.load(atomic::Ordering::Acquire)
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
        self.fetched.fetch_add(1, atomic::Ordering::AcqRel);
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
        source.fetch_count(),
        1,
        "Should only performed fetch IO once"
    );
}

#[tokio::test(flavor = "multi_thread")]
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
        source.fetch_count(),
        2,
        "Should only performed fetch IO in background"
    );

    tokio::time::sleep(Duration::from_millis(10)).await;
    let request_deadline = tokio::time::Instant::now() + Duration::from_millis(5);
    //Attempt to trigger race in `Fetched` branch
    //This is not 100% but it is possible in truly parallel code
    for _ in 0..256 {
        let cache_clone = cache.clone();
        tokio::spawn(async move {
            tokio::time::sleep_until(request_deadline).await;
            cache_clone.get().await.unwrap();
        });
    }
    tokio::time::sleep_until(request_deadline).await;
    cache.get().await.unwrap();
    cache.get().await.unwrap();

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        source.fetch_count(),
        3,
        "Should have refreshed from IO once"
    );
}

#[tokio::test(flavor = "multi_thread")]
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

    let cache_clone = cache.clone();
    let cache_clone2 = cache.clone();
    let request1 = tokio::spawn(async move { cache.get().await });
    let request_deadline = tokio::time::Instant::now() + Duration::from_millis(50);
    let request2 = tokio::spawn(async move {
        tokio::time::sleep_until(request_deadline).await;
        cache_clone.get().await
    });
    let request3 = tokio::spawn(async move {
        tokio::time::sleep_until(request_deadline).await;
        cache_clone2.get().await
    });

    let error1 = request1
        .await
        .expect("spawned future completes")
        .expect_err("should fail with error");
    let error2 = request2
        .await
        .expect("spawned future completes")
        .expect_err("should fail with error");
    let error3 = request3
        .await
        .expect("spawned future completes")
        .expect_err("should fail with error");
    assert!(error1.is_timeout(), "Expected timeout error");
    assert!(error2.is_timeout(), "Expected timeout error");
    assert!(error3.is_timeout(), "Expected timeout error");
    assert_eq!(
        source.fetch_count(),
        12, // initial request + 3 retries
        "Should have retried 9 times"
    );
}
