// Integration tests for cloud-sql-connector
//
// These tests require a real Cloud SQL instance and are automatically skipped
// if the required environment variables are not set.
//
// Use `--show-output` to see skip messages:
//   cargo test --package cloud-sql-connector --test integration_test -- --show-output
//
// Environment variables:
//   TEST_CLOUD_SQL_INSTANCE       - Instance connection name (project:region:instance)
//   TEST_CLOUD_SQL_DATABASE       - Database name
//   TEST_CLOUD_SQL_USER           - Database user
//                                   For IAM auth with service accounts, use truncated form:
//                                   sa@project.iam (not sa@project.iam.gserviceaccount.com)
//   TEST_CLOUD_SQL_PASSWORD       - Database password (required for static auth, ignored for IAM auth)
//   TEST_CLOUD_SQL_USE_IAM_AUTH   - Set to "true" to enable IAM authentication
//   TEST_CLOUD_SQL_IP_TYPE        - IP type: "private" (default) or "public"
//
// Example (static auth):
//   TEST_CLOUD_SQL_INSTANCE=my-project:us-central1:my-instance \
//   TEST_CLOUD_SQL_DATABASE=postgres \
//   TEST_CLOUD_SQL_USER=postgres \
//   TEST_CLOUD_SQL_PASSWORD=secret \
//   TEST_CLOUD_SQL_IP_TYPE=public \
//   cargo test --package cloud-sql-connector --test integration_test
//
// Example (IAM auth):
//   TEST_CLOUD_SQL_INSTANCE=my-project:us-central1:my-instance \
//   TEST_CLOUD_SQL_DATABASE=postgres \
//   TEST_CLOUD_SQL_USER=sa@my-project.iam \
//   TEST_CLOUD_SQL_USE_IAM_AUTH=true \
//   TEST_CLOUD_SQL_IP_TYPE=public \
//   cargo test --package cloud-sql-connector --test integration_test

use cloud_sql_connector::{CloudSqlConfig, CloudSqlConnector, IpType};
use std::env;
use std::sync::{Arc, Once};

static INIT: Once = Once::new();

fn init_crypto_provider() {
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("failed to install rustls crypto provider");
    });
}

struct TestConfig {
    instance: String,
    database: String,
    user: String,
    password: Option<String>,
    use_iam_auth: bool,
    ip_type: IpType,
}

impl TestConfig {
    fn from_env() -> Option<Self> {
        let instance = env::var("TEST_CLOUD_SQL_INSTANCE").ok()?;
        let database = env::var("TEST_CLOUD_SQL_DATABASE").ok()?;
        let user = env::var("TEST_CLOUD_SQL_USER").ok()?;
        let password = env::var("TEST_CLOUD_SQL_PASSWORD").ok();
        let use_iam_auth = env::var("TEST_CLOUD_SQL_USE_IAM_AUTH")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        let ip_type = env::var("TEST_CLOUD_SQL_IP_TYPE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(IpType::Private);

        // For static auth, password is required
        if !use_iam_auth && password.is_none() {
            return None;
        }

        Some(Self {
            instance,
            database,
            user,
            password: if use_iam_auth { None } else { password },
            use_iam_auth,
            ip_type,
        })
    }
}

#[tokio::test]
async fn test_connect_and_query() {
    init_crypto_provider();

    let Some(config) = TestConfig::from_env() else {
        println!("SKIPPED: TEST_CLOUD_SQL_* environment variables not set");
        return;
    };

    let auth_mode = if config.use_iam_auth { "IAM" } else { "static" };
    println!(
        "Testing connect_and_query with {auth_mode} auth (user: {})",
        config.user
    );

    let mut connector_config = CloudSqlConfig::new(&config.instance)
        .expect("valid instance connection name")
        .with_ip_type(config.ip_type.clone());

    if config.use_iam_auth {
        connector_config = connector_config.with_iam_auth();
    }

    let connector = Arc::new(
        CloudSqlConnector::new(connector_config)
            .await
            .expect("failed to create connector"),
    );

    let pool = connector
        .clone()
        .create_pool(
            config.database.clone(),
            config.user.clone(),
            config.password.clone(),
            5,
            None,
        )
        .expect("failed to create pool");

    let client = pool
        .get()
        .await
        .expect("failed to get connection from pool");

    let row = client
        .query_one("SELECT 1 as value", &[])
        .await
        .expect("failed to execute query");

    let value: i32 = row.get("value");
    assert_eq!(value, 1);
}

#[tokio::test]
async fn test_connection_pool_multiple_queries() {
    init_crypto_provider();

    let Some(config) = TestConfig::from_env() else {
        println!("SKIPPED: TEST_CLOUD_SQL_* environment variables not set");
        return;
    };

    let auth_mode = if config.use_iam_auth { "IAM" } else { "static" };
    println!(
        "Testing connection_pool_multiple_queries with {auth_mode} auth (user: {})",
        config.user
    );

    let mut connector_config = CloudSqlConfig::new(&config.instance)
        .expect("valid instance connection name")
        .with_ip_type(config.ip_type.clone());

    if config.use_iam_auth {
        connector_config = connector_config.with_iam_auth();
    }

    let connector = Arc::new(
        CloudSqlConnector::new(connector_config)
            .await
            .expect("failed to create connector"),
    );

    let pool = connector
        .clone()
        .create_pool(
            config.database.clone(),
            config.user.clone(),
            config.password.clone(),
            5,
            None,
        )
        .expect("failed to create pool");

    for i in 0..10 {
        let client = pool
            .get()
            .await
            .expect("failed to get connection from pool");

        let row = client
            .query_one("SELECT $1::int as value", &[&i])
            .await
            .expect("failed to execute query");

        let value: i32 = row.get("value");
        assert_eq!(value, i);
    }
}

#[tokio::test]
async fn test_connector_iam_token() {
    init_crypto_provider();

    let Some(config) = TestConfig::from_env() else {
        println!("SKIPPED: TEST_CLOUD_SQL_* environment variables not set");
        return;
    };

    let auth_mode = if config.use_iam_auth { "IAM" } else { "static" };
    println!("Testing connector_iam_token with {auth_mode} auth");

    let mut connector_config = CloudSqlConfig::new(&config.instance)
        .expect("valid instance connection name")
        .with_ip_type(config.ip_type.clone());

    if config.use_iam_auth {
        connector_config = connector_config.with_iam_auth();
    }

    let connector = CloudSqlConnector::new(connector_config)
        .await
        .expect("failed to create connector");

    let token = connector
        .get_iam_token()
        .await
        .expect("failed to get IAM token");

    if config.use_iam_auth {
        let token = token.expect("expected IAM token when IAM auth is enabled");
        assert!(!token.is_empty(), "IAM token should not be empty");
        println!(
            "IAM token fetched successfully (length: {} chars)",
            token.len()
        );
    } else {
        assert!(token.is_none(), "expected no token for static auth");
        println!("No token returned (expected for static auth)");
    }
}
