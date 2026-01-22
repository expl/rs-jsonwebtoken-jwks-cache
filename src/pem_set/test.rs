use super::PemMap;
use serde_json::from_str;

const PKEYS: &str = include_str!("../../publicKeys-sample.json");

#[test]
fn test_pem_map() {
    let pem_map: PemMap = from_str(PKEYS).unwrap();

    assert_eq!(pem_map.0.len(), 3);

    let jwks = pem_map.into_rsa_jwk_set();

    assert_eq!(jwks.keys.len(), 3);
}
