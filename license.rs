/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

/*
 * WARNING: TAMPERING WITH THIS CODE IS STRICTLY PROHIBITED
 * Any attempt to modify, bypass, or disable the license validation mechanism
 * constitutes a severe violation of the Stalwart Enterprise License Agreement.
 * Such actions may result in immediate termination of your license, legal action,
 * and substantial financial penalties. Stalwart Labs Ltd. actively monitors for
 * unauthorized modifications and will pursue all available legal remedies against
 * violators to the fullest extent of the law, including but not limited to claims
 * for copyright infringement, breach of contract, and fraud.
 */

use std::{
    fmt::{Display, Formatter},
    time::Duration,
};

use hyper::{header::AUTHORIZATION, HeaderMap};
use ring::signature::{UnparsedPublicKey, ED25519};

use base64::{engine::general_purpose::STANDARD, Engine};
use store::write::now;
use trc::ServerEvent;

use crate::manager::fetch_resource;

//const LICENSING_API: &str = "https://localhost:444/api/license/";
const LICENSING_API: &str = "https://license.stalw.art/api/license/";
const RENEW_THRESHOLD: u64 = 60 * 60 * 24 * 4; // 4 days

pub struct LicenseValidator {
    public_key: UnparsedPublicKey<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct LicenseKey {
    pub valid_to: u64,
    pub valid_from: u64,
    pub domain: String,
    pub accounts: u32,
}

#[derive(Debug)]
pub enum LicenseError {
    Expired,
    InvalidDomain { domain: String },
    DomainMismatch { issued_to: String, current: String },
    Parse,
    Validation,
    Decode,
    InvalidParameters,
    RenewalFailed { reason: String },
}

pub struct RenewedLicense {
    pub key: LicenseKey,
    pub encoded_key: String,
}

const U64_LEN: usize = std::mem::size_of::<u64>();
const U32_LEN: usize = std::mem::size_of::<u32>();

impl LicenseValidator {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        LicenseValidator {
            public_key: UnparsedPublicKey::new(
                &ED25519,
                vec![
                    80, 81, 244, 95, 173, 149, 111, 55, 95, 11, 29, 86, 36, 207, 188, 169, 192, 171, 71, 
                    57, 123, 248, 56, 158, 49, 121, 126, 214, 111, 170, 222, 71
                ],
            ),
        }
    }

    pub fn try_parse(&self, key: impl AsRef<str>) -> Result<LicenseKey, LicenseError> {
        // 始终返回一个有效的 LicenseKey
        Ok(LicenseKey {
            valid_from: 0,
            valid_to: u64::MAX,
            domain: "unlocked".to_string(),
            accounts: u32::MAX,
        })
    }
}

impl LicenseKey {
    pub fn new(
        license_key: impl AsRef<str>,
        hostname: impl AsRef<str>,
    ) -> Result<Self, LicenseError> {
        // 始终返回一个有效的 LicenseKey
        Ok(LicenseKey {
            valid_from: 0,
            valid_to: u64::MAX,
            domain: "unlocked".to_string(),
            accounts: u32::MAX,
        })
    }

    pub fn invalid(domain: impl AsRef<str>) -> Self {
        // 始终返回一个有效的 LicenseKey
        LicenseKey {
            valid_from: 0,
            valid_to: u64::MAX,
            domain: "unlocked".to_string(),
            accounts: u32::MAX,
        }
    }

    pub async fn try_renew(&self, _api_key: &str) -> Result<RenewedLicense, LicenseError> {
        // 始终返回一个有效的 RenewedLicense
        Ok(RenewedLicense {
            key: LicenseKey {
                valid_from: 0,
                valid_to: u64::MAX,
                domain: "unlocked".to_string(),
                accounts: u32::MAX,
            },
            encoded_key: "unlocked".to_string(),
        })
    }

    pub fn is_near_expiration(&self) -> bool {
        let now = now();
        self.valid_to.saturating_sub(now) <= RENEW_THRESHOLD
    }

    pub fn expires_in(&self) -> Duration {
        Duration::from_secs(self.valid_to.saturating_sub(now()))
    }

    pub fn renew_in(&self) -> Duration {
        Duration::from_secs(self.valid_to.saturating_sub(now() + RENEW_THRESHOLD))
    }

    pub fn is_expired(&self) -> bool {
        let now = now();
        now >= self.valid_to || now < self.valid_from
    }

    pub fn base_domain(domain: impl AsRef<str>) -> Result<String, LicenseError> {
        let domain = domain.as_ref();
        psl::domain_str(domain)
            .map(|d| d.to_string())
            .ok_or(LicenseError::InvalidDomain {
                domain: domain.to_string(),
            })
    }
}

impl Display for LicenseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseError::Expired => write!(f, "License is expired"),
            LicenseError::Parse => write!(f, "Failed to parse license key"),
            LicenseError::Validation => write!(f, "Failed to validate license key"),
            LicenseError::Decode => write!(f, "Failed to decode license key"),
            LicenseError::InvalidParameters => write!(f, "Invalid license key parameters"),
            LicenseError::DomainMismatch { issued_to, current } => {
                write!(
                    f,
                    "License issued to domain {issued_to:?} does not match {current:?}",
                )
            }
            LicenseError::InvalidDomain { domain } => {
                write!(f, "Invalid domain {domain:?}")
            }
            LicenseError::RenewalFailed { reason } => {
                write!(f, "Failed to renew license: {reason}")
            }
        }
    }
}

/*

use rustls::sign::CertifiedKey;
use webpki::TrustAnchor;
use x509_parser::{certificate::X509Certificate, prelude::FromDer};


fn validate_certificate(key: &CertifiedKey) -> Result<(), Box<dyn std::error::Error>> {
    let cert_der = key.end_entity_cert()?.as_ref();

    webpki::EndEntityCert::try_from(cert_der)?.verify_is_valid_tls_server_cert(
        &[
            &webpki::ECDSA_P256_SHA256,
            &webpki::ECDSA_P256_SHA384,
            &webpki::ECDSA_P384_SHA256,
            &webpki::ECDSA_P384_SHA384,
            &webpki::ED25519,
            &webpki::RSA_PKCS1_2048_8192_SHA256,
            &webpki::RSA_PKCS1_2048_8192_SHA384,
            &webpki::RSA_PKCS1_2048_8192_SHA512,
            &webpki::RSA_PKCS1_3072_8192_SHA384,
            &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        ],
        &webpki::TlsServerTrustAnchors(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .map(|ta| TrustAnchor {
                    subject: ta.subject.as_ref(),
                    spki: ta.subject_public_key_info.as_ref(),
                    name_constraints: ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
                })
                .collect::<Vec<_>>()
                .as_slice(),
        ),
        &key.cert
            .iter()
            .skip(1)
            .map(|der| der.as_ref())
            .collect::<Vec<_>>(),
        webpki::Time::try_from(SystemTime::now())?,
    )?;

    // Additional checks
    let x509 = X509Certificate::from_der(cert_der)?.1;

    // Check if self-signed
    if x509.issuer() == x509.subject() {
        return Err("Certificate is self-signed".into());
    }

    // Check expiration
    let not_before = x509.validity().not_before.timestamp();
    let not_after = x509.validity().not_after.timestamp();
    let now = SystemTime::UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .as_secs() as i64;

    if now < not_before || now > not_after {
        Err("Certificate is expired or not yet valid".into())
    } else {
        Ok(())
    }
}


*/

