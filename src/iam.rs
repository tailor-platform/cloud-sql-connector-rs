// We use gcp_auth instead of google-cloud-auth (Google's official crate) because
// gcp_auth provides direct access to tokens via `provider.token(scopes)`, while
// google-cloud-auth only exposes tokens through HTTP headers, requiring us to
// parse "Bearer <token>" from the Authorization header.
use crate::error::Error;
use gcp_auth::TokenProvider;
use std::sync::Arc;

const CLOUD_SQL_LOGIN_SCOPE: &str = "https://www.googleapis.com/auth/sqlservice.login";

pub struct IamAuthProvider {
    provider: Arc<dyn TokenProvider>,
}

impl std::fmt::Debug for IamAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IamAuthProvider").finish_non_exhaustive()
    }
}

impl IamAuthProvider {
    pub async fn new() -> Result<Self, Error> {
        let provider = gcp_auth::provider()
            .await
            .map_err(|e| Error::AuthenticationFailed(e.to_string()))?;

        Ok(Self { provider })
    }

    pub async fn get_access_token(&self) -> Result<String, Error> {
        let token = self
            .provider
            .token(&[CLOUD_SQL_LOGIN_SCOPE])
            .await
            .map_err(|e| Error::AuthenticationFailed(e.to_string()))?;

        Ok(token.as_str().to_string())
    }
}
