use std::net::Ipv4Addr;

use nat_pmp_client::{Lifetime, PortMapping, Protocol};

use crate::OutputFormat;

struct ProtocolDisplay(Protocol);

impl std::fmt::Display for ProtocolDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

pub(crate) struct NatPmpNotification {
    pub(crate) internal_port: u16,
    pub(crate) external_port: u16,
    pub(crate) protocol: Protocol,
    pub(crate) lifetime: Lifetime,
    pub(crate) external_address: Option<Ipv4Addr>,
}

impl NatPmpNotification {
    pub(crate) fn from_response(
        protocol: Protocol,
        response: PortMapping,
        external_address: Option<Ipv4Addr>,
    ) -> Self {
        NatPmpNotification {
            internal_port: response.internal_port,
            external_port: response.external_port,
            lifetime: response.lifetime,
            protocol,
            external_address,
        }
    }

    pub(crate) fn format(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Json => self.to_json(),
            OutputFormat::Text => self.to_text(),
        }
    }

    pub(crate) fn to_json(&self) -> String {
        // we can safely use string interpolation instead of a crate like serde_json
        // because we know the data is safe
        let formatted_external_address = match self.external_address {
            Some(addr) => format!("\"external_address\":\"{addr}\","),
            None => String::new(),
        };
        format!(
            "{{\
            {formatted_external_address}\
            \"internal_port\":{internal_port},\
            \"external_port\":{external_port},\
            \"protocol\":\"{protocol}\",\
            \"lifetime\":{lifetime}\
            }}",
            internal_port = self.internal_port,
            external_port = self.external_port,
            protocol = ProtocolDisplay(self.protocol),
            lifetime = self.lifetime.duration().as_secs(),
        )
    }

    pub(crate) fn to_text(&self) -> String {
        let formatted_external_address = match self.external_address {
            Some(addr) => format!("{addr}:"),
            None => String::new(),
        };
        format!(
            "{protocol} external port {formatted_external_address}{external_port} -> internal port {internal_port} ({lifetime})",
            internal_port = self.internal_port,
            external_port = self.external_port,
            protocol = ProtocolDisplay(self.protocol),
            lifetime = self.lifetime,
        )
    }
}
