use crate::CloudSqlConnector;
use crate::error::Error;
use deadpool::managed::{Manager, Metrics, RecycleError, RecycleResult};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_postgres::Client;
use tokio_rustls::TlsConnector;

/// The port that Cloud SQL's server-side proxy receives connections on.
/// This is fixed and not configurable - all Cloud SQL instances accept
/// mTLS connections on this port.
const SERVER_PROXY_PORT: u16 = 3307;

pub type CloudSqlPool = deadpool::managed::Pool<CloudSqlPoolManager>;

pub struct PooledConnection {
    pub client: Client,
    created_at: Instant,
}

impl PooledConnection {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            created_at: Instant::now(),
        }
    }

    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

impl std::ops::Deref for PooledConnection {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}

pub struct CloudSqlPoolManager {
    connector: Arc<CloudSqlConnector>,
    dbname: String,
    user: String,
    password: Option<String>,
    use_iam_auth: bool,
    max_lifetime: Option<Duration>,
}

impl CloudSqlPoolManager {
    pub fn new(
        connector: Arc<CloudSqlConnector>,
        dbname: String,
        user: String,
        password: Option<String>,
        use_iam_auth: bool,
        max_lifetime: Option<Duration>,
    ) -> Self {
        Self {
            connector,
            dbname,
            user,
            password,
            use_iam_auth,
            max_lifetime,
        }
    }
}

impl Manager for CloudSqlPoolManager {
    type Type = PooledConnection;
    type Error = Error;

    async fn create(&self) -> Result<PooledConnection, Error> {
        let password = if self.use_iam_auth {
            // IAM auth: fetch fresh token for each new connection
            self.connector.get_iam_token().await?.ok_or_else(|| {
                Error::ConnectionFailed("IAM auth enabled but token fetch failed".to_string())
            })?
        } else {
            // Static auth: use configured password
            self.password
                .clone()
                .ok_or_else(|| Error::ConnectionFailed("no password configured".to_string()))?
        };

        let host = self.connector.host();

        // Step 1: Establish TCP connection
        let addr = format!("{host}:{SERVER_PROXY_PORT}");
        let tcp_stream = TcpStream::connect(&addr).await.map_err(|e| {
            Error::ConnectionFailed(format!("TCP connection to {addr} failed: {e}"))
        })?;

        // Step 2: Perform TLS handshake directly (not PostgreSQL SSL negotiation)
        // Cloud SQL's server-side proxy expects TLS-first, not PostgreSQL-style SSL upgrade
        let tls_config = self.connector.build_tls_config()?;
        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        // ServerName is required by TLS but our custom verifier handles actual identity
        // verification via CN/SAN matching, so we use a placeholder here
        let server_name = ServerName::try_from("localhost").unwrap();

        let tls_stream = tls_connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("TLS handshake failed: {e}")))?;

        // Step 3: Connect PostgreSQL over the already-TLS stream (no SSL negotiation)
        let mut pg_config = tokio_postgres::Config::new();
        pg_config
            .user(&self.user)
            .password(&password)
            .dbname(&self.dbname);

        // Use NoTls since the stream is already TLS-encrypted
        let (client, connection) = pg_config
            .connect_raw(tls_stream, tokio_postgres::NoTls)
            .await
            .map_err(|e| {
                let mut msg = format!("PostgreSQL connection failed: {e}");
                if let Some(code) = e.code() {
                    msg.push_str(&format!(" [SQLSTATE: {}]", code.code()));
                }
                if let Some(source) = e.into_source() {
                    msg.push_str(&format!(" (source: {source})"));
                }
                Error::ConnectionFailed(msg)
            })?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!(error = %e, "PostgreSQL connection task ended with error");
            }
        });

        Ok(PooledConnection::new(client))
    }

    async fn recycle(
        &self,
        conn: &mut PooledConnection,
        _metrics: &Metrics,
    ) -> RecycleResult<Self::Error> {
        // Check max lifetime - reject connections that are too old
        if let Some(max_lifetime) = self.max_lifetime
            && conn.age() > max_lifetime
        {
            return Err(RecycleError::message(format!(
                "connection exceeded max lifetime ({:?})",
                max_lifetime
            )));
        }

        if conn.client.is_closed() {
            return Err(RecycleError::message("connection is closed"));
        }

        conn.client
            .simple_query("")
            .await
            .map_err(|e| RecycleError::message(format!("connection health check failed: {e}")))?;

        Ok(())
    }
}
