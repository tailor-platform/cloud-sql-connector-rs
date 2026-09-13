# cloudsqlconn

A Rust connector for [Google Cloud SQL](https://cloud.google.com/sql). Provides secure, authenticated connections to Cloud SQL instances using IAM authentication and automatic certificate management.

## Features

- Automatic TLS certificate management with background refresh
- IAM-based authentication
- Connection pooling via [deadpool](https://crates.io/crates/deadpool)
- Support for both public and private IP connections

## Usage

```rust
use cloudsqlconn::{CloudSqlConfig, CloudSqlConnector, Timeouts};
use std::sync::Arc;
use std::time::Duration;

let config = CloudSqlConfig::new("my-project:us-central1:my-instance")?
    .with_iam_auth();

let connector = Arc::new(CloudSqlConnector::new(config).await?);
let pool = connector.clone().create_pool(
    "my_database".to_string(),
    "my_user".to_string(),
    None, // IAM auth
    10,   // max pool size
    None, // max connection lifetime (capped at 55 min for IAM auth)
)?;
let conn = pool.get().await?;
```

### Pool timeouts

`create_pool_with_timeouts` accepts deadpool's `Timeouts` to bound waiting for
a free connection, creating a new connection, and recycling an existing one.
Without timeouts, `pool.get()` waits indefinitely.

```rust
let pool = connector.clone().create_pool_with_timeouts(
    "my_database".to_string(),
    "my_user".to_string(),
    None,
    10,
    None,
    Timeouts {
        wait: Some(Duration::from_secs(5)),
        create: Some(Duration::from_secs(10)),
        ..Timeouts::default()
    },
)?;

match pool.get().await {
    Ok(conn) => { /* use conn */ }
    Err(cloudsqlconn::PoolError::Timeout(kind)) => { /* kind is Wait, Create or Recycle */ }
    Err(err) => return Err(err.into()),
}
```

## License

MIT
