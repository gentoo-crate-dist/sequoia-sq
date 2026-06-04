//! Network-related functionality.

use std::time::Duration;

use sequoia_net as net;

use crate::Result;

/// User agent for http communications.
pub const USER_AGENT: &'static str = concat!("sq/", env!("CARGO_PKG_VERSION"));

/// How long to wait for the initial http connection.
pub const CONNECT_TIMEOUT: Duration = Duration::new(5, 0);

/// How long to wait for each individual http request.
pub const REQUEST_TIMEOUT: Duration = Duration::new(5, 0);

/// Makes a http client.
pub fn http_client() -> Result<net::reqwest::Client> {
    Ok(net::reqwest::Client::builder()
       .user_agent(USER_AGENT)
       .connect_timeout(CONNECT_TIMEOUT)
       .timeout(REQUEST_TIMEOUT)
       .build()?)
}
