#[cfg(test)]
mod test;

use super::pem_set::PemMap;
use core::future::Future;
use jsonwebtoken::jwk::JwkSet;
use spin::RwLock;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Notify;
use url::Url;

fn get_expiration(now: SystemTime, req: &reqwest::Request, res: &reqwest::Response) -> SystemTime {
    now + http_cache_semantics::CachePolicy::new(req, res).time_to_live(now)
}

pub trait JwksSource: Clone + Send + Sync + 'static {
    type Error: core::fmt::Debug + Send + Sync + 'static;

    fn get_jwks_within_deadline(
        self,
        url: Url,
        as_pkeys: bool,
        now: SystemTime,
        deadline: Duration,
    ) -> impl Future<Output = Result<(JwkSet, SystemTime), RequestError<Self::Error>>>
    + Send
    + Sync
    + 'static {
        async move {
            let result = tokio::time::timeout(deadline, self.get_jwks(url, as_pkeys, now)).await;

            match result {
                Ok(res) => res.map_err(RequestError::Client),
                Err(_) => Err(RequestError::Timeout),
            }
        }
    }

    fn get_jwks(
        self,
        url: Url,
        as_pkeys: bool,
        now: SystemTime,
    ) -> impl Future<Output = Result<(JwkSet, SystemTime), Self::Error>> + Send + Sync + 'static;
}

impl JwksSource for reqwest::Client {
    type Error = reqwest::Error;

    async fn get_jwks(
        self,
        url: Url,
        as_pkeys: bool,
        now: SystemTime,
    ) -> Result<(JwkSet, SystemTime), Self::Error> {
        let req = reqwest::Request::new(http::Method::GET, url.clone());
        let res = reqwest::Client::builder()
            .build()?
            .execute(
                // safety: because we control the request creation we can ensure its not a stateful stream and can be copied at all times
                req.try_clone().expect("Request should be always copyable"),
            )
            .await?
            .error_for_status()?;

        let expiration = get_expiration(now, &req, &res);
        let jwks = if as_pkeys {
            res.json::<PemMap>().await?.into_rsa_jwk_set()
        } else {
            res.json::<JwkSet>().await?
        };

        Ok((jwks, expiration))
    }
}

/// State machine of the JWKS cache
#[derive(Debug, Clone, Default)]
enum JWKSCache {
    /// There is no data in cache, this is initial state
    #[default]
    Empty,
    /// Cache is empty or expired, fetching of new content is ongoing.
    /// Contains handle for awaiting for fetching to conclude
    Fetching(Arc<Notify>),
    /// Cache is valid, but content is being refreshed in the background
    Refreshing { expires: SystemTime, jwks: JwkSet },
    /// Cache is populated, but needs to be revalidated before use
    Fetched { expires: SystemTime, jwks: JwkSet },
}

#[derive(Debug, thiserror::Error)]
pub enum RequestError<E: core::fmt::Debug> {
    #[error("Client error: {0}")]
    Client(E),
    #[error("Timeout for request completion reached")]
    Timeout,
}

impl<T: core::fmt::Debug> From<T> for RequestError<T> {
    fn from(value: T) -> Self {
        Self::Client(value)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TimeoutSpec {
    /// How many times to retry on failure (timeout or client error)
    pub retries: u8,
    /// How long to wait for a single response before retrying
    pub retry_after: Duration,
    /// Waiting between retries
    pub backoff: Duration,
    /// Total time for completion before considering failure
    pub deadline: Duration,
}

impl Default for TimeoutSpec {
    fn default() -> Self {
        Self {
            retries: 0,
            retry_after: Duration::from_secs(10),
            backoff: Duration::ZERO,
            deadline: Duration::from_secs(10),
        }
    }
}

#[derive(Clone)]
pub struct CachedJWKS<S> {
    jwks_url: Url,
    pkeys: bool,
    update_period: Duration,
    timeout_spec: TimeoutSpec,
    cache_state: Arc<RwLock<JWKSCache>>,
    source: S,
}

impl CachedJWKS<reqwest::Client> {
    pub fn new(
        jwks_url: Url,
        // Period when to refresh in the background before expiration period
        update_period: Duration,
        timeout_spec: TimeoutSpec,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self::from_source(
            jwks_url,
            false,
            update_period,
            timeout_spec,
            reqwest::Client::builder().build()?,
        ))
    }

    /// Load keys as a map of RSA pub keys
    pub fn new_rsa_pkeys(
        pkeys_url: Url,
        // Period when to refresh in the background before expiration period
        update_period: Duration,
        timeout_spec: TimeoutSpec,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self::from_source(
            pkeys_url,
            true,
            update_period,
            timeout_spec,
            reqwest::Client::builder().build()?,
        ))
    }
}

impl<S: JwksSource> CachedJWKS<S> {
    pub fn from_source(
        jwks_url: Url,
        pkeys: bool,
        update_period: Duration,
        timeout_spec: TimeoutSpec,
        source: S,
    ) -> Self {
        assert!(
            update_period > timeout_spec.deadline,
            "Update period should be greater than timeout deadline"
        );

        Self {
            jwks_url,
            pkeys,
            update_period,
            timeout_spec,
            cache_state: Default::default(),
            source,
        }
    }

    async fn request(
        source: S,
        url: Url,
        as_pkeys: bool,
        now: SystemTime,
        timeout: TimeoutSpec,
    ) -> Result<(JwkSet, SystemTime), RequestError<S::Error>> {
        let perform = async {
            let mut retries = 0u8;
            loop {
                match source
                    .clone()
                    .get_jwks_within_deadline(url.clone(), as_pkeys, now, timeout.retry_after)
                    .await
                {
                    Ok(res) => return Ok(res),
                    Err(err) => {
                        if retries == timeout.retries {
                            return Err(err);
                        } else {
                            retries += 1;
                            tokio::time::sleep(timeout.backoff).await;
                            continue;
                        }
                    }
                }
            }
        };

        tokio::time::timeout(timeout.deadline, perform)
            .await
            .map_err(|_| RequestError::Timeout)?
    }

    async fn update_notify(
        &self,
        now: SystemTime,
    ) -> Result<Option<JwkSet>, RequestError<S::Error>> {
        let notifier = if let Some(mut cached_state) = self.cache_state.try_write() {
            let notifier = Arc::new(Notify::new());

            *cached_state = JWKSCache::Fetching(notifier.clone());

            notifier
        } else {
            return Ok(None);
        };

        let result = Self::request(
            self.source.clone(),
            self.jwks_url.clone(),
            self.pkeys,
            now,
            self.timeout_spec,
        )
        .await;

        let result = {
            let mut cached_state = self.cache_state.write();

            match result {
                Ok((jwks, expires)) => {
                    *cached_state = JWKSCache::Fetched {
                        expires,
                        jwks: jwks.clone(),
                    };

                    Ok(Some(jwks))
                }
                // Could not fetch in time, let follow up request try again later
                Err(err) => {
                    *cached_state = JWKSCache::Empty;

                    Err(err)
                }
            }
        };

        notifier.notify_waiters();

        result
    }

    /// Trigger refresh of JWKS in the background when cached JWKS is stil valid but about to expire,
    /// if process dies then we do not care if this completes
    fn update_in_background(&self, now: SystemTime, old_jwks: JwkSet, old_expires: SystemTime) {
        {
            let mut cache_state = self.cache_state.write();

            *cache_state = JWKSCache::Refreshing {
                expires: old_expires,
                jwks: old_jwks,
            };
        }

        let cache_state = self.cache_state.clone();
        let jwks_url = self.jwks_url.clone();
        let timeout_spec = self.timeout_spec;
        let source = self.source.clone();
        let as_pkeys = self.pkeys;

        tokio::spawn(async move {
            let result = Self::request(source, jwks_url, as_pkeys, now, timeout_spec).await;

            if let Err(err) = &result {
                log::error!("Error while refreshing JWKS in the background: {err:?}");
            }

            let mut cache_state = cache_state.write();

            let new_state = match cache_state.to_owned() {
                JWKSCache::Empty => match result {
                    Ok((jwks, expires)) => JWKSCache::Fetched { expires, jwks },
                    Err(_) => JWKSCache::Empty,
                },
                JWKSCache::Fetching(notify) => {
                    if let Ok((jwks, expires)) = result {
                        notify.notify_waiters();
                        JWKSCache::Fetched { expires, jwks }
                    } else {
                        JWKSCache::Fetching(notify)
                    }
                }
                JWKSCache::Refreshing { expires, jwks } => {
                    if let Ok((jwks, expires)) = result {
                        JWKSCache::Fetched { expires, jwks }
                    } else {
                        JWKSCache::Refreshing { expires, jwks }
                    }
                }
                JWKSCache::Fetched { expires, jwks } => {
                    if let Ok((jwks, expires)) = result {
                        JWKSCache::Fetched { expires, jwks }
                    } else {
                        JWKSCache::Refreshing { expires, jwks }
                    }
                }
            };

            *cache_state = new_state;
        });
    }

    pub async fn get(&self) -> Result<JwkSet, RequestError<S::Error>> {
        let now = SystemTime::now();
        loop {
            let cached_state = self.cache_state.read().clone();

            match cached_state {
                JWKSCache::Empty => {
                    if let Some(jwks) = self.update_notify(now).await? {
                        return Ok(jwks);
                    } else {
                        // state changed since reading it, reload
                        continue;
                    }
                }
                JWKSCache::Fetching(notifier) => {
                    notifier.notified().await;

                    // we got notified about change in state, reload
                    continue;
                }
                JWKSCache::Refreshing { expires: _, jwks } => {
                    // Refresh mechanism should guarantee it will change the state before cache is no longer valid
                    return Ok(jwks);
                }
                JWKSCache::Fetched { expires, jwks } => {
                    if now >= expires {
                        if let Some(jwks) = self.update_notify(now).await? {
                            return Ok(jwks);
                        } else {
                            // state changed since reading it, reload
                            continue;
                        }
                    }

                    if now + self.update_period >= expires {
                        self.update_in_background(now, jwks.clone(), expires);
                    }

                    return Ok(jwks);
                }
            }
        }
    }
}
