# rs-jsonwebtoken-jwks-cache
Resilient async JWK Set cache

## Example

```rust
let cache = CachedJWKS::new(
    // strictly follow caching semantics provided by the JWKS URL host
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
        .parse()
        .unwrap(),
    // if requested 1hr before token cache gets expired, refresh the cache in the background
    Duration::from_secs(60 * 60),
    // simple timeout strategy
    TimeoutSpec {
        // if encountered network/http error or single try timeout, how many times more to retry
        retries: 3,
        // single try timeout period
        retry_after: Duration::from_seconds(10),
        // how long to wait between retries
        backoff: Duration::from_seconds(1),
        // total timeout deadline
        deadline: Duration::from_seconds(30),
    },
)
.unwrap();

let jwks = cache.get().await.unwrap();

// perform JWT validation here using `jsonwebtoken` crate
```