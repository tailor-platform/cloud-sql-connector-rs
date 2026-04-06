//! Cloud SQL Connector for Rust
//!
//! This crate provides a native Rust connector for Google Cloud SQL,
//! enabling direct mTLS connections without requiring the Cloud SQL Auth Proxy sidecar.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use cloudsqlconn::{CloudSqlConnector, CloudSqlConfig, IpType};
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Basic usage with static credentials
//!     let config = CloudSqlConfig::new("my-project:us-central1:my-instance")?
//!         .with_ip_type(IpType::Private);
//!
//!     let connector = Arc::new(CloudSqlConnector::new(config).await?);
//!
//!     // Create a connection pool
//!     let pool = connector.clone().create_pool(
//!         "mydb".to_string(),
//!         "user".to_string(),
//!         Some("password".to_string()),  // Some(password) for static auth
//!         10,
//!         Some(Duration::from_secs(300)),  // max connection lifetime
//!     )?;
//!
//!     // For IAM database authentication
//!     // Note: For service accounts, use the truncated username without ".gserviceaccount.com"
//!     // e.g., "sa@project.iam" instead of "sa@project.iam.gserviceaccount.com"
//!     let config_iam = CloudSqlConfig::new("my-project:us-central1:my-instance")?
//!         .with_ip_type(IpType::Private)
//!         .with_iam_auth();
//!
//!     let connector_iam = Arc::new(CloudSqlConnector::new(config_iam).await?);
//!     // For IAM auth, max_lifetime is capped at 55 minutes (tokens expire after 60 min)
//!     let pool_iam = connector_iam.clone().create_pool(
//!         "mydb".to_string(),
//!         "sa@my-project.iam".to_string(),  // IAM user (truncated for service accounts)
//!         None,  // None = use IAM token as password
//!         10,
//!         Some(Duration::from_secs(300)),  // will be capped at 55 min for IAM auth
//!     )?;
//!
//!     Ok(())
//! }
//! ```

mod api;
mod cert;
mod config;
mod error;
mod iam;
mod instance;
mod pool;
mod retry;
mod tls;

pub use config::{CloudSqlConfig, IpType};
pub use error::Error;
pub use pool::{CloudSqlPool, CloudSqlPoolManager, PooledConnection};
pub use tls::CloudSqlTlsConnector;

use cert::CertificateManager;
use iam::IamAuthProvider;
use rustls::ClientConfig;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tls::build_tls_config_from_cert;

// Default max lifetime for connections when using IAM auth (less than 60min token expiry)
const DEFAULT_IAM_MAX_LIFETIME: Duration = Duration::from_secs(55 * 60);

#[derive(Debug)]
pub struct CloudSqlConnector {
    cert_manager: CertificateManager,
    iam_provider: IamAuthProvider,
    use_iam_auth: bool,
}

impl CloudSqlConnector {
    pub async fn new(config: CloudSqlConfig) -> Result<Self, Error> {
        let cert_manager = CertificateManager::new(&config).await?;
        let iam_provider = IamAuthProvider::new().await?;

        Ok(Self {
            cert_manager,
            iam_provider,
            use_iam_auth: config.use_iam_auth,
        })
    }

    pub fn make_tls_connector(&self) -> CloudSqlTlsConnector {
        CloudSqlTlsConnector::from_cache(self.cert_manager.get_cache())
    }

    /// Builds a TLS configuration for direct TLS connections.
    /// This is used internally by the connection pool to establish TLS-first connections
    /// (as opposed to PostgreSQL-style SSL negotiation).
    pub(crate) fn build_tls_config(&self) -> Result<ClientConfig, Error> {
        let cert = self.cert_manager.get_current();
        build_tls_config_from_cert(&cert)
    }

    pub fn host(&self) -> IpAddr {
        self.cert_manager.get_current().ip_address
    }

    /// Fetches an IAM access token for database authentication.
    /// Returns None if IAM auth is not enabled.
    pub async fn get_iam_token(&self) -> Result<Option<String>, Error> {
        if self.use_iam_auth {
            let token = self.iam_provider.get_access_token().await?;
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }

    /// Creates a connection pool.
    ///
    /// # Arguments
    /// * `dbname` - Database name
    /// * `user` - Database username (for service accounts, use truncated form without ".gserviceaccount.com")
    /// * `password` - Password for static auth, or None for IAM auth (token fetched automatically)
    /// * `max_size` - Maximum number of connections in the pool
    /// * `max_lifetime` - Maximum connection lifetime. When IAM auth is enabled, this is capped
    ///   at 55 minutes (IAM tokens expire after 60 minutes).
    pub fn create_pool(
        self: Arc<Self>,
        dbname: String,
        user: String,
        password: Option<String>,
        max_size: usize,
        max_lifetime: Option<Duration>,
    ) -> Result<CloudSqlPool, Error> {
        if max_size == 0 {
            return Err(Error::ConnectionFailed(
                "max_size must be greater than 0".to_string(),
            ));
        }

        let use_iam_auth = self.use_iam_auth;
        // When using IAM auth, cap the max lifetime to ensure connections are refreshed
        // before the access token expires (tokens are valid for 60 minutes)
        let max_lifetime = if use_iam_auth {
            Some(match max_lifetime {
                Some(configured) => configured.min(DEFAULT_IAM_MAX_LIFETIME),
                None => DEFAULT_IAM_MAX_LIFETIME,
            })
        } else {
            max_lifetime
        };
        let manager =
            CloudSqlPoolManager::new(self, dbname, user, password, use_iam_auth, max_lifetime);
        Ok(CloudSqlPool::builder(manager)
            .max_size(max_size)
            .build()
            .expect("pool build should not fail with valid max_size"))
    }

    pub async fn shutdown(&mut self) {
        self.cert_manager.shutdown().await;
    }
}
