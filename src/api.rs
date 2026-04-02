use crate::config::IpType;
use crate::error::Error;
use crate::instance::InstanceConnectionName;
use crate::retry::{log_retry, should_retry_response};
use chrono::{DateTime, TimeZone, Utc};
use gcp_auth::TokenProvider;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use x509_parser::pem::parse_x509_pem;

const DEFAULT_API_ENDPOINT: &str = "https://sqladmin.googleapis.com";
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectSettings {
    pub server_ca_cert: Option<SslCert>,
    pub ip_addresses: Vec<IpAddress>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SslCert {
    pub cert: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpAddress {
    pub ip_address: String,
    #[serde(rename = "type")]
    pub ip_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GenerateEphemeralCertRequest {
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_duration: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateEphemeralCertResponse {
    pub ephemeral_cert: SslCert,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub server_ca_cert: String,
    pub client_cert: String,
    pub ip_address: IpAddr,
    pub expires_at: DateTime<Utc>,
}

pub struct CloudSqlApiClient {
    http_client: Client,
    provider: Arc<dyn TokenProvider>,
    api_endpoint: String,
}

impl CloudSqlApiClient {
    pub async fn new(api_endpoint: Option<String>) -> Result<Self, Error> {
        let provider = gcp_auth::provider()
            .await
            .map_err(|e| Error::AuthenticationFailed(e.to_string()))?;

        let http_client = Client::builder()
            .build()
            .map_err(|e| Error::ApiRequestFailed(e.to_string()))?;

        Ok(Self {
            http_client,
            provider,
            api_endpoint: api_endpoint.unwrap_or_else(|| DEFAULT_API_ENDPOINT.to_string()),
        })
    }

    async fn get_auth_header(&self) -> Result<String, Error> {
        let token = self
            .provider
            .token(&[CLOUD_PLATFORM_SCOPE])
            .await
            .map_err(|e| Error::AuthenticationFailed(e.to_string()))?;

        Ok(format!("Bearer {}", token.as_str()))
    }

    pub async fn get_connect_settings(
        &self,
        instance: &InstanceConnectionName,
    ) -> Result<ConnectSettings, Error> {
        let url = format!(
            "{}/v1/{}/connectSettings",
            self.api_endpoint,
            instance.api_path()
        );

        let mut attempt = 0u32;
        loop {
            let auth_header = self.get_auth_header().await?;

            let response = self
                .http_client
                .get(&url)
                .header("Authorization", auth_header.clone())
                .send()
                .await?;

            if response.status().is_success() {
                return response
                    .json::<ConnectSettings>()
                    .await
                    .map_err(|e| Error::ApiRequestFailed(e.to_string()));
            }

            let status = response.status();
            let retry_result = should_retry_response(&response, attempt);

            if let Some(wait) = retry_result.wait_duration {
                log_retry(attempt, status, wait, retry_result.is_rate_limit);
                tokio::time::sleep(wait).await;
                attempt += 1;
                continue;
            }

            let body = response.text().await.unwrap_or_default();
            return Err(Error::ApiRequestFailed(format!(
                "GET {url} failed with status {status}: {body}"
            )));
        }
    }

    pub async fn generate_ephemeral_cert(
        &self,
        instance: &InstanceConnectionName,
        public_key_pem: &str,
    ) -> Result<GenerateEphemeralCertResponse, Error> {
        let url = format!(
            "{}/v1/{}:generateEphemeralCert",
            self.api_endpoint,
            instance.api_path()
        );

        let request_body = GenerateEphemeralCertRequest {
            public_key: public_key_pem.to_string(),
            valid_duration: Some("3600s".to_string()),
        };

        let mut attempt = 0u32;
        loop {
            let auth_header = self.get_auth_header().await?;

            let response = self
                .http_client
                .post(&url)
                .header("Authorization", auth_header.clone())
                .json(&request_body)
                .send()
                .await?;

            if response.status().is_success() {
                return response
                    .json::<GenerateEphemeralCertResponse>()
                    .await
                    .map_err(|e| Error::ApiRequestFailed(e.to_string()));
            }

            let status = response.status();
            let retry_result = should_retry_response(&response, attempt);

            if let Some(wait) = retry_result.wait_duration {
                log_retry(attempt, status, wait, retry_result.is_rate_limit);
                tokio::time::sleep(wait).await;
                attempt += 1;
                continue;
            }

            let body = response.text().await.unwrap_or_default();
            return Err(Error::ApiRequestFailed(format!(
                "POST {url} failed with status {status}: {body}"
            )));
        }
    }

    pub async fn fetch_connection_info(
        &self,
        instance: &InstanceConnectionName,
        ip_type: &IpType,
        public_key_pem: &str,
    ) -> Result<ConnectionInfo, Error> {
        let settings = self.get_connect_settings(instance).await?;
        let cert_response = self
            .generate_ephemeral_cert(instance, public_key_pem)
            .await?;

        let server_ca_cert = settings
            .server_ca_cert
            .ok_or_else(|| Error::CertificateError("no server CA cert in response".to_string()))?
            .cert;

        let client_cert = cert_response.ephemeral_cert.cert.clone();

        // Parse the certificate to extract expiration from the X.509 NotAfter field
        // This matches the Go connector's approach of reading from the cert itself
        let expires_at = parse_cert_expiration(&client_cert)?;

        let target_ip_type = match ip_type {
            IpType::Private => "PRIVATE",
            IpType::Public => "PRIMARY",
        };

        let ip_address = settings
            .ip_addresses
            .iter()
            .find(|addr| addr.ip_type == target_ip_type)
            .or_else(|| settings.ip_addresses.first())
            .ok_or_else(|| Error::ConnectionFailed("no IP address available".to_string()))?;

        let ip_addr: IpAddr = ip_address
            .ip_address
            .parse()
            .map_err(|e| Error::ConnectionFailed(format!("invalid IP address: {e}")))?;

        Ok(ConnectionInfo {
            server_ca_cert,
            client_cert,
            ip_address: ip_addr,
            expires_at,
        })
    }
}

/// Parse a PEM-encoded X.509 certificate and extract the NotAfter expiration time.
fn parse_cert_expiration(pem_cert: &str) -> Result<DateTime<Utc>, Error> {
    let (_, pem) = parse_x509_pem(pem_cert.as_bytes())
        .map_err(|e| Error::CertificateError(format!("failed to parse PEM: {e}")))?;

    let cert = pem
        .parse_x509()
        .map_err(|e| Error::CertificateError(format!("failed to parse X.509 certificate: {e}")))?;

    let not_after = cert.validity().not_after;
    let timestamp = not_after.timestamp();

    Utc.timestamp_opt(timestamp, 0)
        .single()
        .ok_or_else(|| Error::CertificateError("invalid certificate expiration timestamp".into()))
}

pub async fn fetch_connection_info(
    api_endpoint: &Option<String>,
    instance: &InstanceConnectionName,
    ip_type: &IpType,
    public_key_pem: &str,
) -> Result<ConnectionInfo, Error> {
    let api_client = CloudSqlApiClient::new(api_endpoint.clone()).await?;
    api_client
        .fetch_connection_info(instance, ip_type, public_key_pem)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test certificate generated with:
    // openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out /dev/stdout -days 365 -nodes -subj "/CN=test"
    // Expires: Jan 12 2027
    const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUMwFTEMgvtcN2YhIFDB4+FYAqMuowDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjAxMTIwMTMwNDVaFw0yNzAxMTIwMTMw
NDVaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC4eRxMjczvdZlCDntwB1yfbArym81GLwsI4GlS2pWPNEk9YOYq3KxlPfD2
kokxLaDItPtv5jVctqcLbvIP57ZrlRi1rWRNmYJYRmPmcYFDAgnKiAP7fTgIAt0F
y+XQMN5a6N/NvFrcAA+weikcZUEzamk3vunBd0v5z7SMkhZ1+TXIQsP31j2HGpBb
ceqV2uRo9Y1aNJmwmlNNCPJ+r6/cFnJQOkPKzfc3ddQXjw1OSL5DUc4cWH7ViUCy
CapG/WP3iN34CC13zKd5/UFDkPnX4z6yL2vzLpB9j06+NFmc004As5HAZiTIJ3QC
Cq0ekwQ1+qAzNQARgbQlEoHJnHi1AgMBAAGjUzBRMB0GA1UdDgQWBBR+fn/Lzszg
uED9llsd1QNxbId8GTAfBgNVHSMEGDAWgBR+fn/LzszguED9llsd1QNxbId8GTAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAA32Oai+cJO1k1dtNw
TgEldVaj4LrJ+WDrdtriCOGlmC7yOVcY9n9EoyTGqEzxPt2MZCD+bLF9jamvpnTA
Je4i+9boVkoAmYcjD1TAtDzxnmWbdwh/L4XncLaVp9WtpDoA+GGOdFM8m0PJjK0W
3Jr2wzwE7vuQhmMF1M0JFZXSaSmSgBHbHNvTDPym/vguHqHdtkxJXLoGzXz43NU+
GjWOWr//DUPmErqvfyn6r0MmaEeCc/m4kzOZ3jQZs/fPAdO9e00mx3q9aBW/+FYG
4wNkCkHF4CPuSGUDkmEG0UyFq9MIPbH1qIHjmpgGeOJMbQGFkiL67D4guJKSb3bC
96sr
-----END CERTIFICATE-----"#;

    #[test]
    fn test_parse_cert_expiration_valid() {
        let result = parse_cert_expiration(TEST_CERT_PEM);
        assert!(result.is_ok(), "should parse valid certificate");
        let expires_at = result.unwrap();
        // Verify the year is 2027 (the NotAfter year in the test cert)
        assert_eq!(expires_at.format("%Y").to_string(), "2027");
    }

    #[test]
    fn test_parse_cert_expiration_invalid_pem() {
        let result = parse_cert_expiration("not a valid PEM");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::CertificateError(_)));
    }

    #[test]
    fn test_parse_cert_expiration_empty() {
        let result = parse_cert_expiration("");
        assert!(result.is_err());
    }

    #[test]
    fn test_connect_settings_deserialization() {
        let json = r#"{
            "serverCaCert": {"cert": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"},
            "ipAddresses": [
                {"ipAddress": "10.0.0.1", "type": "PRIVATE"},
                {"ipAddress": "35.1.2.3", "type": "PRIMARY"}
            ]
        }"#;

        let settings: ConnectSettings = serde_json::from_str(json).unwrap();
        assert!(settings.server_ca_cert.is_some());
        assert_eq!(settings.ip_addresses.len(), 2);
        assert_eq!(settings.ip_addresses[0].ip_address, "10.0.0.1");
        assert_eq!(settings.ip_addresses[0].ip_type, "PRIVATE");
        assert_eq!(settings.ip_addresses[1].ip_type, "PRIMARY");
    }

    #[test]
    fn test_connect_settings_deserialization_no_ca_cert() {
        let json = r#"{
            "ipAddresses": [{"ipAddress": "10.0.0.1", "type": "PRIVATE"}]
        }"#;

        let settings: ConnectSettings = serde_json::from_str(json).unwrap();
        assert!(settings.server_ca_cert.is_none());
    }

    #[test]
    fn test_ephemeral_cert_response_deserialization() {
        let json = r#"{
            "ephemeralCert": {"cert": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"}
        }"#;

        let response: GenerateEphemeralCertResponse = serde_json::from_str(json).unwrap();
        assert!(response.ephemeral_cert.cert.contains("BEGIN CERTIFICATE"));
    }
}
