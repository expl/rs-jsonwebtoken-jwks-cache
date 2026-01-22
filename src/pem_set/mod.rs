#[cfg(test)]
mod test;

// use rsa::{pkcs1::DecodeRsaPublicKey, traits::PublicKeyParts};
use base64::prelude::*;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse,
    RSAKeyParameters,
};
use rustls_pki_types::{CertificateDer, pem::PemObject};
use serde::{
    Deserialize,
    de::{self, Deserializer, Visitor},
};
use std::collections::HashMap;
use x509_parser::{
    certificate::X509CertificateParser,
    nom::{AsBytes, Parser},
    public_key::PublicKey,
};

const RS256_OID: &str = "1.2.840.113549.1.1.11";
const RS384_OID: &str = "1.2.840.113549.1.1.12";
const RS512_OID: &str = "1.2.840.113549.1.1.13";

struct PemCertVisitor;

impl Visitor<'_> for PemCertVisitor {
    type Value = PemCert;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a string containing PEM certificate")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        CertificateDer::from_pem_slice(v.as_bytes())
            .map_err(E::custom)
            .map(PemCert)
    }
}

pub struct PemCert(pub CertificateDer<'static>);

impl<'de> Deserialize<'de> for PemCert {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<PemCert, D::Error> {
        deserializer.deserialize_str(PemCertVisitor)
    }
}

#[derive(Deserialize)]
pub struct PemMap(pub HashMap<String, PemCert>);

impl PemMap {
    pub fn into_rsa_jwk_set(self) -> JwkSet {
        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(false);

        let jwks: Vec<Jwk> = self
            .0
            .into_iter()
            .filter_map(|(k, v)| {
                let Ok((_, cert)) = parser.parse(v.0.as_bytes()) else {
                    return None;
                };

                let pkey = cert.public_key();

                let algo = match cert.signature.oid().to_id_string().as_str() {
                    RS256_OID => KeyAlgorithm::RS256,
                    RS384_OID => KeyAlgorithm::RS384,
                    RS512_OID => KeyAlgorithm::RS512,
                    _ => return None,
                };

                let Ok(pkey) = pkey.parsed() else { return None };
                let PublicKey::RSA(rsa_key) = pkey else {
                    return None;
                };

                Some(Jwk {
                    common: CommonParameters {
                        key_id: Some(k),
                        key_algorithm: Some(algo),
                        public_key_use: Some(PublicKeyUse::Signature),
                        ..Default::default()
                    },
                    algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                        e: BASE64_URL_SAFE_NO_PAD.encode(rsa_key.exponent),
                        n: BASE64_URL_SAFE_NO_PAD.encode(rsa_key.modulus),
                        ..Default::default()
                    }),
                })
            })
            .collect();

        JwkSet { keys: jwks }
    }
}
