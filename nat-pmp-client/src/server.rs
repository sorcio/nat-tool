//! Fake NAT-PMP server for testing purposes.

use std::{
    mem::size_of,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    time::Instant,
};

use derive_builder::Builder;
use parking_lot::Mutex;
use zerocopy::{AsBytes, FromBytes, FromZeroes};
use zerocopy_derive::{FromBytes, FromZeroes};

use crate::{
    packets::{
        ExternalAddressResponse, MapPortResponse, Opcode, ResponseHeader, ResponsePacket, Version,
    },
    Lifetime, Protocol, ResultCode,
};

#[repr(C, packed)]
#[derive(Debug, FromZeroes, FromBytes)]
struct RawRequestHeader {
    version: u8,
    opcode: u8,
    _reserved: u16,
}

#[repr(C, packed)]
#[derive(Debug, FromZeroes, FromBytes)]
pub(crate) struct RawMapPortRequest {
    internal_port_be: [u8; 2],
    external_port_be: [u8; 2],
    lifetime_be: [u8; 4],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolOptions {
    Udp,
    Tcp,
    Both,
}

impl ProtocolOptions {
    fn contains(self, protocol: Protocol) -> bool {
        match self {
            Self::Udp => protocol == Protocol::Udp,
            Self::Tcp => protocol == Protocol::Tcp,
            Self::Both => true,
        }
    }
}

/// A range of ports between `start` and `end` (inclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortRange {
    start: u16,
    length: u16,
}

impl PortRange {
    pub const ALL_PORTS: Self = Self::new(1, u16::MAX);

    /// Create a new port range between `start` and `end` (inclusive).
    /// Returns `None` if `start` is greater than `end`, or if `start` is 0.
    pub const fn checked_new(start: u16, end: u16) -> Option<Self> {
        if start == 0 {
            return None;
        }
        if let Some(length_minus_one) = end.checked_sub(start) {
            Some(Self {
                start,
                length: length_minus_one + 1,
            })
        } else {
            None
        }
    }

    /// Create a new port range between `start` and `end` (inclusive).
    /// # Panics
    /// Panics if `start` is greater than `end`, or if `start` is 0.
    pub const fn new(start: u16, end: u16) -> Self {
        if let Some(range) = Self::checked_new(start, end) {
            range
        } else {
            panic!("invalid port range");
        }
    }

    pub const fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= (self.start - 1) + self.length
    }

    pub const fn len(&self) -> u16 {
        self.length
    }

    pub const fn is_empty(&self) -> bool {
        false
    }

    pub const fn start(&self) -> u16 {
        self.start
    }

    pub const fn end(&self) -> u16 {
        (self.start - 1) + self.length
    }

    pub const fn starting_at(self, start: u16) -> Option<Self> {
        if start == 0 {
            return None;
        }
        if start.checked_add(self.length - 1).is_some() {
            Some(Self {
                start,
                length: self.length,
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMappingOptions {
    internal_port_range: PortRange,
    protocol: ProtocolOptions,
    external_port_range: Option<PortRange>,
}

impl PortMappingOptions {
    pub fn new(
        protocol: ProtocolOptions,
        internal_port_range: PortRange,
        external_port_start: Option<u16>,
    ) -> Option<Self> {
        let external_port_range = if let Some(start) = external_port_start {
            Some(internal_port_range.starting_at(start)?)
        } else {
            None
        };
        Some(Self {
            internal_port_range,
            protocol,
            external_port_range,
        })
    }

    pub fn disable_all(protocol: ProtocolOptions) -> Self {
        Self {
            internal_port_range: PortRange::ALL_PORTS,
            protocol,
            external_port_range: None,
        }
    }

    pub fn internal_port_range(&self) -> PortRange {
        self.internal_port_range
    }

    pub fn protocol(&self) -> ProtocolOptions {
        self.protocol
    }

    pub fn external_port_range(&self) -> Option<PortRange> {
        self.external_port_range
    }

    fn map_internal_port(&self, internal_port: u16) -> Option<u16> {
        debug_assert!(self.internal_port_range().contains(internal_port));
        if let Some(external_port_range) = self.external_port_range {
            let internal_start = self.internal_port_range.start();
            let external_start = external_port_range.start();
            tracing::debug!(
                ?internal_start,
                ?external_start,
                ?internal_port,
                "mapping internal port"
            );
            // What we want is:
            // external_port = internal_port - internal_start + external_start
            // But we need to calculate that with u16 arithmetic.
            let external = if let Some(difference) = internal_port.checked_sub(internal_start) {
                tracing::debug!(?difference, "internal_port >= internal_start");
                external_start + difference
            } else {
                let difference = internal_start - internal_port;
                tracing::debug!(?difference, "internal_port <= internal_start");
                external_start - difference
            };
            Some(external)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Builder)]
pub struct TestServerOptions {
    /// The address to bind to. Defaults to 0.0.0.0:5351.
    #[builder(default = "SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5351)")]
    bind_address: SocketAddrV4,

    /// The address that external address requests should return.
    /// If `None`, the server will not respond to external address requests.
    /// Defaults to 127.0.0.1.
    #[builder(default = "Some(Ipv4Addr::LOCALHOST)")]
    external_address: Option<Ipv4Addr>,

    /// Specific responses for specific port mappings.
    /// Defaults to no port mappings.
    #[builder(default)]
    port_ranges: Vec<PortMappingOptions>,

    /// Allow automatic selection of external port (when external port is 0).
    /// Defaults to `true`.
    #[builder(default = "true")]
    allow_random_external_ports: bool,

    /// Allow automatic selection of internal port (when internal port is 0; not RFC-sanctioned).
    /// Defaults to `false`.
    #[builder(default = "false")]
    allow_random_internal_ports: bool,
}

impl TestServerOptions {
    pub fn build_server(self) -> Result<UdpServer, std::io::Error> {
        UdpServer::new(self)
    }

    pub fn bind_address(&self) -> SocketAddrV4 {
        self.bind_address
    }

    pub fn external_address(&self) -> Option<Ipv4Addr> {
        self.external_address
    }

    pub fn port_ranges(&self) -> &[PortMappingOptions] {
        &self.port_ranges
    }

    pub fn allow_random_external_ports(&self) -> bool {
        self.allow_random_external_ports
    }

    pub fn allow_random_internal_ports(&self) -> bool {
        self.allow_random_internal_ports
    }
}

impl Default for TestServerOptions {
    fn default() -> Self {
        Self {
            bind_address: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5351),
            external_address: Some(Ipv4Addr::LOCALHOST),
            port_ranges: Vec::new(),
            allow_random_external_ports: true,
            allow_random_internal_ports: false,
        }
    }
}

struct ResponseBuilder {
    opcode: u8,
    timestamp: Lifetime,
}

impl ResponseBuilder {
    fn new(opcode: u8, timestamp: Lifetime) -> Self {
        Self { opcode, timestamp }
    }

    fn build<T>(self, result_code: ResultCode, payload: T) -> ResponsePacket<T> {
        ResponsePacket::new(
            ResponseHeader::new(Version::NatPmp, self.opcode, result_code, self.timestamp),
            payload,
        )
    }

    fn success<T>(self, payload: T) -> ResponsePacket<T> {
        self.build(ResultCode::Success, payload)
    }

    fn empty_error(self, result_code: ResultCode) -> ResponsePacket<[u8; 0]> {
        assert!(!result_code.is_success());
        self.build(result_code, [])
    }

    fn default_error<T: FromZeroes>(self, result_code: ResultCode) -> ResponsePacket<T> {
        assert!(!result_code.is_success());
        self.build(result_code, FromZeroes::new_zeroed())
    }
}

struct Server {
    options: TestServerOptions,
    start_time: Instant,
    external_address: Mutex<Option<Ipv4Addr>>,
}

impl Server {
    fn new(options: TestServerOptions) -> Self {
        let start_time = Instant::now();
        let external_address = Mutex::new(options.external_address);
        Self {
            options,
            start_time,
            external_address,
        }
    }

    fn process_packet(&self, data: &[u8], source: SocketAddr, respond: impl Fn(&[u8])) {
        tracing::trace!(packet = ?data);
        let timestamp = Lifetime::try_from(self.start_time.elapsed()).expect("ran too long");
        let (header_data, payload_data) = data.split_at(size_of::<RawRequestHeader>());
        let Some(header) = RawRequestHeader::read_from(header_data) else {
            tracing::warn!(?source, ?data, "invalid message");
            return;
        };
        tracing::trace!(?header);
        let response = ResponseBuilder::new(header.opcode, timestamp);
        match Version::try_from(header.version) {
            Ok(Version::NatPmp) => {}
            _ => {
                tracing::warn!(?source, ?header, "unsupported version");
                respond(
                    response
                        .empty_error(ResultCode::UnsupportedVersion)
                        .as_bytes(),
                );
                return;
            }
        }
        if header.opcode & 0x80 != 0 {
            tracing::info!("received a response packet, not a request; discarding");
            return;
        }
        let opcode = match Opcode::try_from(header.opcode) {
            Ok(opcode) => opcode,
            Err(_) => {
                tracing::warn!(?source, ?header, "unsupported opcode");
                respond(
                    response
                        .empty_error(ResultCode::UnsupportedOpcode)
                        .as_bytes(),
                );
                return;
            }
        };
        match opcode {
            Opcode::GetExternalAddress => {
                tracing::info!("external address request");
                respond(self.process_external_address_request(response).as_bytes());
            }
            Opcode::MapUdpPort | Opcode::MapTcpPort => {
                let Some(request) =
                    RawMapPortRequest::read_from(&payload_data[..size_of::<RawMapPortRequest>()])
                else {
                    tracing::warn!(?source, ?payload_data, "invalid map port request");
                    // RFC does not seem to specify what to do when an invalid request is received.
                    // We send an unsupported version error just to report something back
                    respond(
                        response
                            .empty_error(ResultCode::UnsupportedVersion)
                            .as_bytes(),
                    );
                    return;
                };
                let protocol = match opcode {
                    Opcode::MapUdpPort => Protocol::Udp,
                    Opcode::MapTcpPort => Protocol::Tcp,
                    _ => unreachable!(),
                };
                respond(
                    self.process_map_port_request(request, protocol, response)
                        .as_bytes(),
                );
            }
        }
    }

    fn process_external_address_request(
        &self,
        builder: ResponseBuilder,
    ) -> ResponsePacket<ExternalAddressResponse> {
        if let Some(external_address) = *self.external_address.lock() {
            builder.success(ExternalAddressResponse::new(external_address))
        } else {
            tracing::info!("request rejected because of configuration");
            builder.default_error(ResultCode::NotAuthorized)
        }
    }

    fn process_map_port_request(
        &self,
        request: RawMapPortRequest,
        protocol: Protocol,
        builder: ResponseBuilder,
    ) -> ResponsePacket<MapPortResponse> {
        let internal_port = u16::from_be_bytes(request.internal_port_be);
        let suggested_external_port = u16::from_be_bytes(request.external_port_be);
        let lifetime = Lifetime::from_secs(u32::from_be_bytes(request.lifetime_be));
        tracing::info!(
            ?internal_port,
            ?suggested_external_port,
            ?lifetime,
            "map port request"
        );
        if !self.options.allow_random_internal_ports && internal_port == 0 {
            tracing::info!("internal port is random, rejecting");
            return builder.default_error(ResultCode::NotAuthorized);
        }
        if !self.options.allow_random_external_ports && suggested_external_port == 0 {
            tracing::info!("external port is random, rejecting");
            return builder.build(
                ResultCode::NotAuthorized,
                MapPortResponse::new(internal_port, 0, Lifetime::ZERO),
            );
        }
        let external_port = if let Some(mapping_options) = self
            .options
            .port_ranges
            .iter()
            .inspect(|o| {
                tracing::trace!(?o, "checking port mapping options");
            })
            .filter(|o| {
                o.protocol().contains(protocol) && o.internal_port_range().contains(internal_port)
            })
            .inspect(|_| tracing::trace!("found matching port mapping options"))
            .last()
        {
            if suggested_external_port != 0
                && mapping_options
                    .external_port_range()
                    .is_some_and(|r| r.contains(suggested_external_port))
            {
                tracing::trace!("suggested external port is within allowed range, use it");
                Some(suggested_external_port)
            } else {
                // map 1-1
                tracing::trace!("map internal range to external range");
                mapping_options.map_internal_port(internal_port)
            }
        } else {
            // no specific port mapping options specified
            if suggested_external_port != 0 {
                tracing::trace!("use suggested external port as is");
                Some(suggested_external_port)
            } else {
                tracing::trace!("use internal port as external port");
                Some(internal_port)
            }
        };
        if let Some(external_port) = external_port {
            tracing::info!(?external_port, "port mapped");
            builder.success(MapPortResponse::new(internal_port, external_port, lifetime))
        } else {
            tracing::info!("port not mapped");
            builder.build(
                ResultCode::NotAuthorized,
                MapPortResponse::new(internal_port, 0, Lifetime::ZERO),
            )
        }
    }

    fn set_external_address(&self, external_address: Option<Ipv4Addr>) -> bool {
        let mut guard = self.external_address.lock();
        if *guard != external_address {
            *guard = external_address;
            external_address.is_some()
        } else {
            false
        }
    }

    fn external_address_announcement(&self) -> Option<ResponsePacket<ExternalAddressResponse>> {
        let external_address = (*self.external_address.lock())?;
        let timestamp = Lifetime::try_from(self.start_time.elapsed()).expect("ran too long");
        let response = ResponseBuilder::new(Opcode::get_external_address() as u8, timestamp);
        Some(response.success(ExternalAddressResponse::new(external_address)))
    }
}

pub struct UdpServer {
    inner: Server,
    socket: UdpSocket,
}

impl UdpServer {
    pub fn new(options: TestServerOptions) -> std::io::Result<Self> {
        let inner = Server::new(options);
        let socket = UdpSocket::bind(inner.options.bind_address)?;
        Ok(Self { inner, socket })
    }

    pub fn run(&self) -> std::io::Result<()> {
        loop {
            let mut buf = [0; 256];
            let (amt, source) = self.socket.recv_from(&mut buf)?;
            let packet_span = tracing::info_span!("request", ?source);
            let _enter = packet_span.enter();
            let data = &buf[..amt];
            self.inner.process_packet(data, source, |response| {
                if let Err(err) = self.socket.send_to(response, source) {
                    tracing::error!(?err, "failed to send response");
                }
            });
        }
    }

    pub fn external_address(&self) -> Option<Ipv4Addr> {
        *self.inner.external_address.lock()
    }

    pub fn set_external_address(&self, external_address: Option<Ipv4Addr>) -> std::io::Result<()> {
        if self.inner.set_external_address(external_address) {
            self.announce()
        } else {
            Ok(())
        }
    }

    pub fn announce(&self) -> std::io::Result<()> {
        let Some(packet) = self.inner.external_address_announcement() else {
            tracing::info!("external address not set, skipping announcement");
            return Ok(());
        };
        let multi_addr = Ipv4Addr::new(224, 0, 0, 1);
        let _ = self.socket.send_to(packet.as_bytes(), (multi_addr, 5350))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn valid_port_range() {
        let range = PortRange::checked_new(1000, 2000).unwrap();
        assert_eq!(range.len(), 1001);
        assert!(range.contains(1000));
        assert!(range.contains(2000));
        assert!(!range.contains(999));
        assert!(!range.contains(2001));
    }

    #[test]
    fn invalid_port_ranges() {
        assert!(PortRange::checked_new(2000, 1000).is_none());
        assert!(PortRange::checked_new(0, 1000).is_none());
        assert!(PortRange::checked_new(1000, 999).is_none());
    }
}
