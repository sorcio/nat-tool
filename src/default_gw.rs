use std::net::{Ipv4Addr, Ipv6Addr};

use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
pub(crate) enum DefaultGatewayError {
    #[error("{0}")]
    CannotFindDefaultGateway(String),
    #[error("gateway has an IPv6 address [{0}] which is not supported")]
    Ipv6Unsupported(Ipv6Addr),
}

pub(crate) fn get_default_gateway() -> Result<Ipv4Addr, DefaultGatewayError> {
    let dev =
        netdev::get_default_gateway().map_err(DefaultGatewayError::CannotFindDefaultGateway)?;
    if let [ipv4, ..] = dev.ipv4[..] {
        Ok(ipv4)
    } else if let [ipv6, ..] = dev.ipv6[..] {
        Err(DefaultGatewayError::Ipv6Unsupported(ipv6))
    } else {
        Err(DefaultGatewayError::CannotFindDefaultGateway(
            "no valid address".to_string(),
        ))
    }
}
