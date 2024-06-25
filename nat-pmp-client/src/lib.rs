#![deny(unsafe_code)]
#![deny(unreachable_pub)]

mod packets;

use std::fmt::Debug;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use packets::{
    ExternalAddressRequest, ExternalAddressResponse, MapPortRequest, MapPortResponse,
    ResponseHeader, ResponsePacket,
};
use parking_lot::Mutex;
use thiserror::Error;

pub use packets::{Protocol, ResultCode};
use zerocopy::{AsBytes, FromBytes};

type Result<T> = std::result::Result<T, NatPmpError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lifetime(u32);

impl Lifetime {
    pub const fn from_secs(secs: u32) -> Self {
        Lifetime(secs)
    }

    pub const fn duration(self) -> Duration {
        Duration::from_secs(self.0 as _)
    }

    pub const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl std::str::FromStr for Lifetime {
    type Err = <u32 as std::str::FromStr>::Err;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let s = s.strip_suffix('s').unwrap_or(s);
        Ok(Self(u32::from_str(s)?))
    }
}

impl std::fmt::Display for Lifetime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}s", self.0)
    }
}

trait NatPmpRequest: AsBytes {
    type Response: NatPmpResponse;
}

trait NatPmpResponse: FromBytes {}

impl NatPmpRequest for ExternalAddressRequest {
    type Response = ExternalAddressResponse;
}

impl NatPmpResponse for ExternalAddressResponse {}

impl NatPmpRequest for MapPortRequest {
    type Response = MapPortResponse;
}

impl NatPmpResponse for MapPortResponse {}

#[derive(Debug, Error)]
pub enum NatPmpError {
    #[error("socket error")]
    SocketError(#[from] std::io::Error),
    #[error("NAT gateway sent an invalid response")]
    BadResponse,
    #[error("no response from gateway within timeout")]
    ResponseTimeout,
    #[error("gateway refused the operation: {0:?}")]
    ProtocolError(ResultCode),
    #[error("gateway responded with an unknown result code: {0}")]
    UnknownResultCode(u16),
}

pub struct NatPmpClient {
    socket: Mutex<UdpSocket>,
}

pub struct PortMapping {
    pub internal_port: u16,
    pub external_port: u16,
    pub protocol: Protocol,
    pub lifetime: Lifetime,
}

impl PortMapping {
    fn from_response(protocol: Protocol, response: &MapPortResponse) -> Self {
        Self {
            internal_port: response.internal_port(),
            external_port: response.external_port(),
            protocol,
            lifetime: response.lifetime(),
        }
    }
}

impl NatPmpClient {
    pub fn new(gateway: Ipv4Addr, port: u16) -> Result<Self> {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
        let gw_addr = SocketAddrV4::new(gateway, port);
        socket.connect(gw_addr)?;
        Ok(Self {
            socket: Mutex::new(socket),
        })
    }

    fn parse_response<Response: NatPmpResponse>(&self, data: &[u8]) -> Result<Response> {
        if data.len() == ResponseHeader::SIZE {
            // Some gateways (likely supporting PCP) can send empty error
            // response packet, with no payload. When that is the case, we can
            // still parse the response header to get the result code.
            let header = ResponseHeader::read_from(data).ok_or(NatPmpError::BadResponse)?;
            let result_code = header.result()?;
            Err(if !result_code.is_success() {
                NatPmpError::ProtocolError(result_code)
            } else {
                // no error code, but no payload either, so we can't make no sense of it
                NatPmpError::BadResponse
            })
        } else {
            let packet = ResponsePacket::read_from(data).ok_or(NatPmpError::BadResponse)?;
            let result_code = packet.header().result()?;
            if !result_code.is_success() {
                return Err(NatPmpError::ProtocolError(result_code));
            }
            // TODO check opcode, ...
            Ok(packet.into_payload())
        }
    }

    fn do_request<Request, Response>(&self, s: &UdpSocket, request: &Request) -> Result<Response>
    where
        Request: NatPmpRequest<Response = Response>,
        Response: NatPmpResponse,
    {
        const MAX_PACKET_SIZE: usize = 1100;

        let mut timeout = Duration::from_millis(250);

        for _ in 0..64 {
            s.send(request.as_bytes())?;

            s.set_read_timeout(Some(timeout))?;

            let mut buf = [0u8; MAX_PACKET_SIZE];
            let recv_result = s.recv(&mut buf);

            match recv_result {
                Ok(size) => {
                    let response = self.parse_response(&buf[..size])?;
                    return Ok(response);
                }
                Err(err) => match err.kind() {
                    ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                        timeout *= 2;
                    }
                    _ => return Err(err.into()),
                },
            }
        }
        Err(NatPmpError::ResponseTimeout)
    }

    pub fn external_address(&self) -> Result<ExternalAddressResponse> {
        let s = self.socket.lock();
        self.do_request(&s, &ExternalAddressRequest::new())
    }

    pub fn map_port(
        &self,
        internal_port: u16,
        external_port: u16,
        protocol: Protocol,
        lifetime: Lifetime,
    ) -> Result<PortMapping> {
        let s = self.socket.lock();
        let map_port = MapPortRequest::new(internal_port, external_port, protocol, lifetime);
        let response = self.do_request(&s, &map_port)?;
        Ok(PortMapping::from_response(protocol, &response))
    }
}
