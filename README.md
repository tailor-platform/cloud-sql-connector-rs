# cloud-sql-connector

A Rust connector for [Google Cloud SQL](https://cloud.google.com/sql). Provides secure, authenticated connections to Cloud SQL instances using IAM authentication and automatic certificate management.

## Features

- Automatic TLS certificate management with background refresh
- IAM-based authentication
- Connection pooling via [deadpool](https://crates.io/crates/deadpool)
- Support for both public and private IP connections

## Usage

```rust
use cloud_sql_connector::{CloudSqlConfig, CloudSqlConnector};

let config = CloudSqlConfig::new("my-project:us-central1:my-instance")
    .with_iam_auth(true);

let connector = CloudSqlConnector::new(config).await?;
let pool = connector.create_pool("my_database", "my_user", None)?;
let conn = pool.get().await?;
```

## License

MIT
