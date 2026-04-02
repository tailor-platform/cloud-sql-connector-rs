use crate::api;
use crate::config::{CloudSqlConfig, IpType};
use crate::error::Error;
use crate::instance::InstanceConnectionName;
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const RSA_KEY_SIZE: usize = 2048;
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct CachedCertificate {
    pub server_ca_certs: Vec<CertificateDer<'static>>,
    pub client_certs: Vec<CertificateDer<'static>>,
    pub client_key: PrivateKeyDer<'static>,
    pub ip_address: IpAddr,
    pub expires_at: DateTime<Utc>,
    /// Instance identifier in format "project:instance" for server certificate verification.
    /// Cloud SQL certificates include this in the Subject.CN or SAN field.
    pub instance_id: String,
}

pub struct CertificateManager {
    cache: Arc<ArcSwap<CachedCertificate>>,
    refresh_handle: Option<JoinHandle<()>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl std::fmt::Debug for CertificateManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateManager")
            .field("cache", &"<cached>")
            .field("refresh_handle", &self.refresh_handle.is_some())
            .finish()
    }
}

impl CertificateManager {
    pub async fn new(config: &CloudSqlConfig) -> Result<Self, Error> {
        let instance = InstanceConnectionName::parse(&config.instance_connection_name)?;
        let (private_key, public_key_pem) = generate_key_pair()?;

        let connection_info = api::fetch_connection_info(
            &config.api_endpoint,
            &instance,
            &config.ip_type,
            &public_key_pem,
        )
        .await?;

        let cached = build_cached_certificate(&connection_info, &private_key, &instance)?;
        let cache = Arc::new(ArcSwap::from_pointee(cached));

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let refresh_handle = {
            let cache = Arc::clone(&cache);
            let instance = instance.clone();
            let ip_type = config.ip_type.clone();
            let refresh_buffer = config.refresh_buffer;
            let api_endpoint = config.api_endpoint.clone();

            tokio::spawn(async move {
                refresh_loop(
                    cache,
                    api_endpoint,
                    instance,
                    ip_type,
                    refresh_buffer,
                    shutdown_rx,
                )
                .await;
            })
        };

        Ok(Self {
            cache,
            refresh_handle: Some(refresh_handle),
            shutdown_tx: Some(shutdown_tx),
        })
    }

    pub fn get_current(&self) -> Arc<CachedCertificate> {
        self.cache.load_full()
    }

    pub fn get_cache(&self) -> Arc<ArcSwap<CachedCertificate>> {
        Arc::clone(&self.cache)
    }

    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.refresh_handle.take() {
            let _ = handle.await;
        }
    }
}

fn generate_key_pair() -> Result<(RsaPrivateKey, String), Error> {
    let mut rng = rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE)
        .map_err(|e| Error::CertificateError(format!("failed to generate RSA key: {e}")))?;

    let public_key = RsaPublicKey::from(&private_key);
    let public_key_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| Error::CertificateError(format!("failed to encode public key: {e}")))?;

    Ok((private_key, public_key_pem))
}

fn build_cached_certificate(
    info: &api::ConnectionInfo,
    private_key: &RsaPrivateKey,
    instance: &InstanceConnectionName,
) -> Result<CachedCertificate, Error> {
    let server_ca_certs = parse_pem_certificates(&info.server_ca_cert)?;
    let client_certs = parse_pem_certificates(&info.client_cert)?;

    let private_key_der = private_key
        .to_pkcs8_der()
        .map_err(|e| Error::CertificateError(format!("failed to encode private key: {e}")))?;

    let client_key = PrivateKeyDer::Pkcs8(private_key_der.as_bytes().to_vec().into());

    // Instance identifier for server certificate verification (format: "project:instance")
    // Cloud SQL certificates include this in the Subject.CN or SAN field
    let instance_id = format!("{}:{}", instance.project, instance.instance);

    Ok(CachedCertificate {
        server_ca_certs,
        client_certs,
        client_key,
        ip_address: info.ip_address,
        expires_at: info.expires_at,
        instance_id,
    })
}

fn parse_pem_certificates(pem_data: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    let mut reader = std::io::BufReader::new(pem_data.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Error::CertificateError(format!("failed to parse certificates: {e}")))?;

    if certs.is_empty() {
        return Err(Error::CertificateError(
            "no certificates found in PEM data".to_string(),
        ));
    }

    Ok(certs)
}

async fn refresh_loop(
    cache: Arc<ArcSwap<CachedCertificate>>,
    api_endpoint: Option<String>,
    instance: InstanceConnectionName,
    ip_type: IpType,
    refresh_buffer: Duration,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        let current = cache.load();
        let now = Utc::now();
        let expires_at = current.expires_at;

        // Calculate next refresh time based on certificate expiration
        let refresh_at =
            expires_at - chrono::Duration::from_std(refresh_buffer).unwrap_or_default();
        let sleep_duration = if refresh_at > now {
            (refresh_at - now).to_std().unwrap_or(MIN_REFRESH_INTERVAL)
        } else {
            MIN_REFRESH_INTERVAL
        };

        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {
                // API calls have built-in retry with exponential backoff for 429/5xx errors.
                // If all retries fail, we wait MIN_REFRESH_INTERVAL before trying again.
                match refresh_certificate(&api_endpoint, &instance, &ip_type).await {
                    Ok(new_cert) => {
                        cache.store(Arc::new(new_cert));
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            retry_secs = MIN_REFRESH_INTERVAL.as_secs(),
                            "certificate refresh failed after retries, will retry later"
                        );
                    }
                }
            }
            _ = &mut shutdown_rx => {
                break;
            }
        }
    }
}

async fn refresh_certificate(
    api_endpoint: &Option<String>,
    instance: &InstanceConnectionName,
    ip_type: &IpType,
) -> Result<CachedCertificate, Error> {
    let (private_key, public_key_pem) = generate_key_pair()?;

    let connection_info =
        api::fetch_connection_info(api_endpoint, instance, ip_type, &public_key_pem).await?;

    build_cached_certificate(&connection_info, &private_key, instance)
}
