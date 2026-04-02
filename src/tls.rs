use crate::cert::CachedCertificate;
use crate::error::Error;
use arc_swap::ArcSwap;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use x509_parser::prelude::*;

#[derive(Clone)]
pub struct CloudSqlTlsConnector {
    cache: Arc<ArcSwap<CachedCertificate>>,
}

impl CloudSqlTlsConnector {
    pub(crate) fn from_cache(cache: Arc<ArcSwap<CachedCertificate>>) -> Self {
        Self { cache }
    }

    fn build_tls_config(&self) -> Result<ClientConfig, Error> {
        let cert = self.cache.load();
        build_tls_config_from_cert(&cert)
    }
}

pub(crate) fn build_tls_config_from_cert(cert: &CachedCertificate) -> Result<ClientConfig, Error> {
    let mut root_store = RootCertStore::empty();
    for ca_cert in &cert.server_ca_certs {
        root_store
            .add(ca_cert.clone())
            .map_err(|e| Error::TlsConfigurationFailed(format!("failed to add CA cert: {e}")))?;
    }

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CloudSqlCertVerifier::new(
            root_store,
            cert.instance_id.clone(),
        )))
        .with_client_auth_cert(cert.client_certs.clone(), cert.client_key.clone_key())
        .map_err(|e| Error::TlsConfigurationFailed(format!("failed to set client cert: {e}")))?;

    Ok(config)
}

impl<S> MakeTlsConnect<S> for CloudSqlTlsConnector
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = CloudSqlTlsStream<S>;
    type TlsConnect = CloudSqlTlsConnect;
    type Error = Error;

    fn make_tls_connect(&mut self, _host: &str) -> Result<Self::TlsConnect, Self::Error> {
        let config = self.build_tls_config()?;
        Ok(CloudSqlTlsConnect {
            connector: TlsConnector::from(Arc::new(config)),
        })
    }
}

pub struct CloudSqlTlsConnect {
    connector: TlsConnector,
}

impl<S> TlsConnect<S> for CloudSqlTlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = CloudSqlTlsStream<S>;
    type Error = Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Stream, Self::Error>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move {
            let server_name = ServerName::try_from("localhost")
                .map_err(|e| Error::TlsConfigurationFailed(format!("invalid server name: {e}")))?;

            let tls_stream = self
                .connector
                .connect(server_name, stream)
                .await
                .map_err(|e| Error::ConnectionFailed(format!("TLS handshake failed: {e}")))?;

            Ok(CloudSqlTlsStream { inner: tls_stream })
        })
    }
}

pub struct CloudSqlTlsStream<S> {
    inner: TlsStream<S>,
}

impl<S> AsyncRead for CloudSqlTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for CloudSqlTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> tokio_postgres::tls::TlsStream for CloudSqlTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}

/// Custom certificate verifier for Cloud SQL server certificates.
///
/// Cloud SQL certificates use instance identifiers in "project:instance" format
/// in the Common Name (CN) or Subject Alternative Name (SAN) fields. This format
/// contains colons which are not valid hostname characters, so standard TLS
/// hostname verification fails.
///
/// This verifier performs:
/// 1. Standard certificate chain validation against the CA
/// 2. Custom identity verification checking CN/SAN against the expected instance ID
///
/// See: https://github.com/GoogleCloudPlatform/cloud-sql-proxy/issues/194
#[derive(Debug)]
pub(crate) struct CloudSqlCertVerifier {
    root_store: RootCertStore,
    expected_instance_id: String,
}

impl CloudSqlCertVerifier {
    pub(crate) fn new(root_store: RootCertStore, expected_instance_id: String) -> Self {
        Self {
            root_store,
            expected_instance_id,
        }
    }

    /// Verify that the server certificate's CN or SANs contain the expected instance identifier.
    /// Cloud SQL certificates store the instance identifier as "project:instance" in the
    /// Subject.CN field (legacy) or in the SAN field (newer certificates).
    fn verify_instance_identity(&self, cert_der: &[u8]) -> Result<(), rustls::Error> {
        let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
            rustls::Error::General(format!("failed to parse server certificate: {e}"))
        })?;

        // Check Common Name first (legacy Cloud SQL certificates)
        if let Some(cn) = cert.subject().iter_common_name().next()
            && let Ok(cn_str) = cn.as_str()
            && cn_str == self.expected_instance_id
        {
            return Ok(());
        }

        // Check Subject Alternative Names (newer certificates)
        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                match name {
                    GeneralName::DNSName(dns) if *dns == self.expected_instance_id => {
                        return Ok(());
                    }
                    GeneralName::RFC822Name(name) if *name == self.expected_instance_id => {
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }

        Err(rustls::Error::General(format!(
            "server certificate identity mismatch: expected '{}', certificate CN/SAN did not match",
            self.expected_instance_id
        )))
    }
}

impl ServerCertVerifier for CloudSqlCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Step 1: Verify certificate chain is signed by our trusted CA
        let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;

        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.root_store,
            intermediates,
            now,
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .all,
        )?;

        // Step 2: Verify the certificate belongs to the expected Cloud SQL instance
        // This matches the Go connector's verifyPeerCertificateFunc behavior
        self.verify_instance_identity(end_entity.as_ref())?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pemfile::certs;
    use std::io::BufReader;

    // Test certificate with CN=my-project:my-instance
    // Generated with: openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out /dev/stdout -days 365 -nodes -subj "/CN=my-project:my-instance"
    const TEST_CERT_WITH_INSTANCE_CN: &str = r#"-----BEGIN CERTIFICATE-----
MIIDIzCCAgugAwIBAgIUE3dRFv+nfkY/vbAXwrT53ukr4kIwDQYJKoZIhvcNAQEL
BQAwITEfMB0GA1UEAwwWbXktcHJvamVjdDpteS1pbnN0YW5jZTAeFw0yNjAxMTIw
MTM2MDVaFw0yNzAxMTIwMTM2MDVaMCExHzAdBgNVBAMMFm15LXByb2plY3Q6bXkt
aW5zdGFuY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCgjFOygckL
VL+6KB6pXOnXEa4f5XSMnY/R4S9TBTIK3H3Wig7rKkBCW+Yl66NLecmvD+Zzqf8f
j5DPs7BxkSX0t5p1SW65Zi0CcJqgxlPzsYqSHXPhi0TKoBctEqeGaAJ9O0mGv8eL
lKh43nViLfxt1Hb5aWLwOUwHhfJaXtt4dph+q0OnXD7LFlkkxWTtKZ+bvdLqaLIh
zAayZe/Wa0QAciG5xxgSLouAz80IFUpLuxbxhiVhrf1b/J8+iIdcFiVe0sqxrTQ8
OhR9ePhwoHpvZVKqEacqrJSVlD589LTwukSzyPp+Aat7DREhkFTUfQsX33B5DC23
5rwTRsrr2UXxAgMBAAGjUzBRMB0GA1UdDgQWBBTZPriweu050mBj5ANWjuX7Ll/I
CzAfBgNVHSMEGDAWgBTZPriweu050mBj5ANWjuX7Ll/ICzAPBgNVHRMBAf8EBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBo8Q8lGJzsyVZe4YFN3lP5tYzXvnTssEe5
wOuhXkaPI+530HrP44a7BM5S/dAUDrUseRVNxCE4MmR8SNXUuf4pjppZp4ZDdocl
f5sVY0RnIAHk6Dp+kJIPUdKlJg1ThFurDUG+jttLHJzQHXOLVRyarABqB0zNAFc0
zazL40kGSa+s1+lck5CaGcVoUOkjlI4wAQ/7V9g/S5xPQsdmmEYIIv1UPVjmNpUX
yz1RuJjc2LhZ70W/fdyL23/S/MR8QkFPzhdfw+RbZZDqzFrpKQlhlXdCDIHQtYVX
INvqYjU55MMHDyZkbFYBPQNFgXrheiQM/NDUTbYdjX60Mg6IdWcr
-----END CERTIFICATE-----"#;

    fn parse_cert_der(pem: &str) -> Vec<u8> {
        let mut reader = BufReader::new(pem.as_bytes());
        let certs: Vec<_> = certs(&mut reader).collect::<Result<Vec<_>, _>>().unwrap();
        certs[0].to_vec()
    }

    #[test]
    fn test_verify_instance_identity_cn_match() {
        let cert_der = parse_cert_der(TEST_CERT_WITH_INSTANCE_CN);
        let verifier =
            CloudSqlCertVerifier::new(RootCertStore::empty(), "my-project:my-instance".to_string());

        let result = verifier.verify_instance_identity(&cert_der);
        assert!(result.is_ok(), "should match CN");
    }

    #[test]
    fn test_verify_instance_identity_cn_mismatch() {
        let cert_der = parse_cert_der(TEST_CERT_WITH_INSTANCE_CN);
        let verifier = CloudSqlCertVerifier::new(
            RootCertStore::empty(),
            "wrong-project:wrong-instance".to_string(),
        );

        let result = verifier.verify_instance_identity(&cert_der);
        assert!(result.is_err(), "should not match wrong instance id");

        let err = result.unwrap_err();
        assert!(
            format!("{err:?}").contains("identity mismatch"),
            "error should mention identity mismatch"
        );
    }

    #[test]
    fn test_verify_instance_identity_invalid_cert() {
        let verifier =
            CloudSqlCertVerifier::new(RootCertStore::empty(), "my-project:my-instance".to_string());

        let result = verifier.verify_instance_identity(b"not a valid certificate");
        assert!(result.is_err(), "should fail on invalid certificate data");
    }
}
