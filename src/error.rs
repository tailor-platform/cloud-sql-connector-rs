use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid instance connection name: {0}")]
    InvalidInstanceName(String),

    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("API request failed: {0}")]
    ApiRequestFailed(String),

    #[error("certificate error: {0}")]
    CertificateError(String),

    #[error("TLS configuration failed: {0}")]
    TlsConfigurationFailed(String),

    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("pool configuration failed: {0}")]
    PoolConfigurationFailed(String),
}

impl From<deadpool::managed::BuildError> for Error {
    fn from(err: deadpool::managed::BuildError) -> Self {
        Error::PoolConfigurationFailed(err.to_string())
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::ApiRequestFailed(err.to_string())
    }
}
