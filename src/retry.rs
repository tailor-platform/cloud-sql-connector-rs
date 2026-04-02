use reqwest::{Response, StatusCode};
use std::time::Duration;

/// Maximum number of retry attempts for API calls.
const MAX_RETRIES: u32 = 5;

/// Base delay for exponential backoff (200ms, matching Go connector).
const BACKOFF_BASE: Duration = Duration::from_millis(200);

/// Multiplier for exponential backoff (1.618, golden ratio, matching Go connector).
const BACKOFF_MULTIPLIER: f64 = 1.618;

/// Maximum wait duration to prevent unreasonably long waits from Retry-After headers.
/// Capped at 30s to ensure certificate refresh (with 4-minute buffer) completes before expiry
/// even in worst case (5 retries × 30s = 2.5 min < 4 min buffer).
const MAX_WAIT_DURATION: Duration = Duration::from_secs(30);

/// Retry configuration and result tracking.
#[derive(Debug)]
pub struct RetryResult {
    pub wait_duration: Option<Duration>,
    pub is_rate_limit: bool,
}

/// Determines if a response should be retried and calculates the wait duration.
///
/// Returns retry information based on the response status:
/// - 429 (Too Many Requests): Retry with Retry-After header or exponential backoff
/// - 5xx (Server Error): Retry with exponential backoff
/// - Other errors: Do not retry
pub fn should_retry_response(response: &Response, attempt: u32) -> RetryResult {
    if attempt >= MAX_RETRIES {
        return RetryResult {
            wait_duration: None,
            is_rate_limit: false,
        };
    }

    let status = response.status();

    // Handle 429 Too Many Requests (rate limiting)
    if status == StatusCode::TOO_MANY_REQUESTS {
        let wait_duration = parse_retry_after(response)
            .unwrap_or_else(|| backoff_duration(attempt))
            .min(MAX_WAIT_DURATION);
        return RetryResult {
            wait_duration: Some(wait_duration),
            is_rate_limit: true,
        };
    }

    // Handle 5xx Server Errors
    if status.is_server_error() {
        return RetryResult {
            wait_duration: Some(backoff_duration(attempt)),
            is_rate_limit: false,
        };
    }

    // Don't retry other errors (4xx client errors, etc.)
    RetryResult {
        wait_duration: None,
        is_rate_limit: false,
    }
}

/// Parse the Retry-After header from a response.
fn parse_retry_after(response: &Response) -> Option<Duration> {
    let header = response.headers().get("retry-after")?;
    let value = header.to_str().ok()?;
    parse_retry_after_value(value)
}

/// Parse a Retry-After header value string into a Duration.
///
/// Supports:
/// - Seconds format: "120" -> 120 seconds
/// - HTTP-date format: Not implemented, returns None (falls back to exponential backoff)
fn parse_retry_after_value(value: &str) -> Option<Duration> {
    // Try parsing as seconds
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    // HTTP-date format not implemented, return None to use default backoff
    None
}

/// Calculate exponential backoff duration for a given attempt.
///
/// Uses the formula: base * multiplier^(attempt + random)
/// This matches the Go connector's approach with jitter to avoid thundering herd.
fn backoff_duration(attempt: u32) -> Duration {
    // Add jitter (0.0 to 1.0) to spread out retries
    let jitter: f64 = rand::random::<f64>();
    let exponent = attempt as f64 + 1.0 + jitter;
    let multiplied = BACKOFF_BASE.as_secs_f64() * BACKOFF_MULTIPLIER.powf(exponent);

    Duration::from_secs_f64(multiplied)
}

/// Log a retry attempt with appropriate context.
pub fn log_retry(attempt: u32, status: StatusCode, wait: Duration, is_rate_limit: bool) {
    if is_rate_limit {
        tracing::warn!(
            attempt = attempt,
            status = %status,
            wait_secs = wait.as_secs_f64(),
            "API rate limit hit (429), retrying after backoff. Consider requesting quota increase."
        );
    } else {
        tracing::warn!(
            attempt = attempt,
            status = %status,
            wait_secs = wait.as_secs_f64(),
            "API server error (5xx), retrying with exponential backoff"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_duration_increases() {
        // Backoff should generally increase with attempts (allowing for jitter variation)
        let d0 = backoff_duration(0);
        let d4 = backoff_duration(4);

        // With base=200ms and multiplier=1.618:
        // attempt 0: ~324-524ms
        // attempt 4: ~2218-3588ms
        assert!(d0 < Duration::from_secs(1), "first backoff should be < 1s");
        assert!(d4 > Duration::from_secs(1), "fifth backoff should be > 1s");
    }

    #[test]
    fn test_backoff_duration_bounds() {
        // Test multiple samples to verify bounds with jitter
        for _ in 0..10 {
            let d0 = backoff_duration(0);
            // attempt 0: base * 1.618^(1 to 2) = 200ms * (1.618 to 2.618) = 324ms to 524ms
            assert!(
                d0 >= Duration::from_millis(300) && d0 <= Duration::from_millis(550),
                "attempt 0 backoff {d0:?} should be ~324-524ms"
            );
        }
    }

    #[test]
    fn test_backoff_never_exceeds_max_wait() {
        // Even at high attempt numbers, backoff itself grows but is reasonable
        // (the cap is applied in should_retry_response for 429, not here)
        let d10 = backoff_duration(10);
        // This tests that the function doesn't overflow or return unreasonable values
        assert!(d10 < Duration::from_secs(300), "backoff should be bounded");
    }

    #[test]
    fn test_max_retries_constant() {
        assert_eq!(MAX_RETRIES, 5, "max retries should be 5");
    }

    #[test]
    fn test_max_wait_duration_constant() {
        assert_eq!(
            MAX_WAIT_DURATION,
            Duration::from_secs(30),
            "max wait should be 30s to fit within 4-min refresh buffer"
        );
    }

    #[test]
    fn test_parse_retry_after_value_seconds() {
        assert_eq!(
            parse_retry_after_value("120"),
            Some(Duration::from_secs(120))
        );
        assert_eq!(parse_retry_after_value("0"), Some(Duration::from_secs(0)));
        assert_eq!(parse_retry_after_value("1"), Some(Duration::from_secs(1)));
    }

    #[test]
    fn test_parse_retry_after_value_invalid() {
        // HTTP-date format not supported, returns None
        assert_eq!(
            parse_retry_after_value("Wed, 21 Oct 2015 07:28:00 GMT"),
            None
        );
        // Invalid strings
        assert_eq!(parse_retry_after_value(""), None);
        assert_eq!(parse_retry_after_value("abc"), None);
        assert_eq!(parse_retry_after_value("-1"), None); // negative not supported by u64
    }

    #[test]
    fn test_worst_case_retry_fits_refresh_buffer() {
        // Verify that worst-case retry time fits within the 4-minute refresh buffer
        let worst_case_total = MAX_WAIT_DURATION.as_secs() * MAX_RETRIES as u64;
        let refresh_buffer_secs = 4 * 60; // 4 minutes
        assert!(
            worst_case_total < refresh_buffer_secs,
            "worst case retry ({worst_case_total}s) should be less than refresh buffer ({refresh_buffer_secs}s)"
        );
    }
}
