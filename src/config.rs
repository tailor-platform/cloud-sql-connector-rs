use std::str::FromStr;
use std::time::Duration;

use crate::error::Error;
use crate::instance::InstanceConnectionName;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum IpType {
    #[default]
    Private,
    Public,
}

impl FromStr for IpType {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "public" => IpType::Public,
            _ => IpType::Private,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CloudSqlConfig {
    pub instance_connection_name: String,
    pub ip_type: IpType,
    pub refresh_buffer: Duration,
    pub api_endpoint: Option<String>,
    pub use_iam_auth: bool,
}

impl CloudSqlConfig {
    pub fn new(instance_connection_name: impl Into<String>) -> Result<Self, Error> {
        let instance_connection_name = instance_connection_name.into();
        InstanceConnectionName::parse(&instance_connection_name)?;
        Ok(Self {
            instance_connection_name,
            ip_type: IpType::default(),
            refresh_buffer: Duration::from_secs(4 * 60),
            api_endpoint: None,
            use_iam_auth: false,
        })
    }

    pub fn with_ip_type(mut self, ip_type: IpType) -> Self {
        self.ip_type = ip_type;
        self
    }

    pub fn with_refresh_buffer(mut self, refresh_buffer: Duration) -> Self {
        self.refresh_buffer = refresh_buffer;
        self
    }

    pub fn with_api_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.api_endpoint = Some(endpoint.into());
        self
    }

    pub fn with_iam_auth(mut self) -> Self {
        self.use_iam_auth = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_type_from_str() {
        assert_eq!("public".parse::<IpType>().unwrap(), IpType::Public);
        assert_eq!("PUBLIC".parse::<IpType>().unwrap(), IpType::Public);
        assert_eq!("private".parse::<IpType>().unwrap(), IpType::Private);
        assert_eq!("anything".parse::<IpType>().unwrap(), IpType::Private);
    }

    #[test]
    fn test_config_builder() {
        let config = CloudSqlConfig::new("project:region:instance")
            .expect("valid instance connection name")
            .with_ip_type(IpType::Public)
            .with_refresh_buffer(Duration::from_secs(300));

        assert_eq!(config.instance_connection_name, "project:region:instance");
        assert_eq!(config.ip_type, IpType::Public);
        assert_eq!(config.refresh_buffer, Duration::from_secs(300));
    }

    #[test]
    fn test_config_with_api_endpoint() {
        let config = CloudSqlConfig::new("project:region:instance")
            .expect("valid instance connection name")
            .with_api_endpoint("https://custom.api");

        assert_eq!(config.api_endpoint, Some("https://custom.api".to_string()));
    }

    #[test]
    fn test_config_with_iam_auth() {
        let config = CloudSqlConfig::new("project:region:instance")
            .expect("valid instance connection name")
            .with_iam_auth();

        assert!(config.use_iam_auth);
    }

    #[test]
    fn test_config_invalid_instance_connection_name() {
        assert!(CloudSqlConfig::new("invalid").is_err());
        assert!(CloudSqlConfig::new("").is_err());
        assert!(CloudSqlConfig::new("a:b").is_err());
        assert!(CloudSqlConfig::new("a:b:c:d").is_err());
    }
}
