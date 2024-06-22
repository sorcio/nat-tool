use std::fmt::Debug;
use std::io::ErrorKind;
use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use parking_lot::Mutex;
use thiserror::Error;

type Result<T> = std::result::Result<T, NatPmpError>;


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Lifetime(u32);

impl Lifetime {
    pub(crate) const fn from_secs(secs: u32) -> Self {
        Lifetime(secs)
    }

    pub(crate) const fn duration(self) -> Duration {
        Duration::from_secs(self.0 as _)
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; 4] {
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


#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct ResponseHeader {
    version: u8,
    opcode: u8,
    result_be: [u8; 2],
    ts_be: [u8; 4],
}

impl ResponseHeader {
    #[allow(dead_code)]
    fn timestamp(&self) -> Lifetime {
        let secs = u32::from_be_bytes(self.ts_be);
        Lifetime::from_secs(secs as _)
    }

    fn result(&self) -> Result<ResultCode> {
        let raw_code = u16::from_be_bytes(self.result_be);
        let max = ResultCode::MAX as u16;
        if raw_code < max {
            Ok(unsafe { std::mem::transmute(raw_code) })
        } else {
            Err(NatPmpError::UnknownResultCode(raw_code).into())
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) enum ResultCode {
    /// Success
    Success = 0,
    /// Unsupported Version
    UnsupportedVersion = 1,
    /// Not Authorized/Refused (e.g. box supports mapping, but user has turned feature off)
    NotAuthorized = 2,
    /// Network Failure (e.g. NAT box itself has not obtained a DHCP lease)
    NetworkFailure = 3,
    /// Out of resources (NAT box cannot create any more mappings at this time)
    OutOfResource = 4,
    /// Unsupported opcode
    UnsupportedOpcode = 5,
    /// (this is only a marker, don't use)
    MAX,
}

impl ResultCode {
    fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

trait NatPmpRequest: Sized {
    const SIZE: usize = size_of::<Self>();

    type Response: NatPmpResponse;

    fn as_bytes(&self) -> &[u8] {
        let data = self as *const Self;
        unsafe { std::slice::from_raw_parts(data as _, Self::SIZE) }
    }
}

trait NatPmpResponse: Sized {
    const SIZE: usize = size_of::<Self>();

    unsafe fn from_bytes(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), Self::SIZE);
        let ptr = bytes.as_ptr() as *const Self;
        unsafe { ptr.read() }
    }
}

#[repr(C, packed)]
struct PublicAddressRequest {
    version: u8,
    opcode: u8,
    reserved: u16, // PCP compatibility hack
    reserved2: u32, // PCP compatibility hack
}

impl PublicAddressRequest {
    fn new() -> Self {
        Self {
            version: 0,
            opcode: 0,
            reserved: 0,
            reserved2: 0,
        }
    }
}

impl NatPmpRequest for PublicAddressRequest {
    type Response = PublicAddressResponse;
}

#[repr(C, packed)]
pub(crate) struct PublicAddressResponse {
    ip: [u8; 4],
}

impl NatPmpResponse for PublicAddressResponse {}

impl PublicAddressResponse {
    pub(crate) fn ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.ip)
    }
}

#[repr(C, packed)]
struct MapPortRequest {
    version: u8,
    opcode: u8,
    reserved: u16,
    private_port_be: [u8; 2],
    public_port_be: [u8; 2],
    lifetime_be: [u8; 4],
}

impl NatPmpRequest for MapPortRequest {
    type Response = MapPortResponse;
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum Protocol {
    Udp = 1,
    Tcp = 2,
}

impl MapPortRequest {
    pub(crate) fn new(
        private_port: u16,
        public_port: u16,
        protocol: Protocol,
        lifetime: Lifetime,
    ) -> Self {
        let private_port_be = private_port.to_be_bytes();
        let public_port_be = public_port.to_be_bytes();
        let lifetime_be = lifetime.to_be_bytes();
        let opcode = protocol as _;
        MapPortRequest {
            version: 0,
            opcode,
            reserved: 0,
            private_port_be,
            public_port_be,
            lifetime_be,
        }
    }
}

#[repr(C, packed)]
pub(crate) struct MapPortResponse {
    private_port_be: [u8; 2],
    public_port_be: [u8; 2],
    lifetime_be: [u8; 4],
}

impl NatPmpResponse for MapPortResponse {}

impl MapPortResponse {
    pub(crate) fn private_port(&self) -> u16 {
        u16::from_be_bytes(self.private_port_be)
    }

    pub(crate) fn public_port(&self) -> u16 {
        u16::from_be_bytes(self.public_port_be)
    }

    pub(crate) fn lifetime(&self) -> Lifetime {
        let secs = u32::from_be_bytes(self.lifetime_be);
        Lifetime::from_secs(secs as _)
    }
}

#[derive(Debug, Error)]
pub(crate) enum NatPmpError {
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

pub(crate) struct NatPmpClient {
    socket: Mutex<UdpSocket>,
}

impl NatPmpClient {
    pub(crate) fn new(gateway: Ipv4Addr, port: u16) -> Result<Self> {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
        let gw_addr = SocketAddrV4::new(gateway, port);
        socket.connect(gw_addr)?;
        Ok(Self {
            socket: Mutex::new(socket),
        })
    }

    fn parse_response<Response: NatPmpResponse>(
        &self,
        size: usize,
        data: &[u8],
    ) -> Result<Response> {
        const HEADER_SIZE: usize = size_of::<ResponseHeader>();
        if size < HEADER_SIZE {
            return Err(NatPmpError::BadResponse.into());
        }
        let header = unsafe { (data.as_ptr() as *const ResponseHeader).read() };
        let result_code = header.result()?;
        if !result_code.is_success() {
            return Err(NatPmpError::ProtocolError(result_code).into());
        }
        // TODO check opcode, ...
        let msg = &data[HEADER_SIZE..];
        if msg.len() < Response::SIZE {
            return Err(NatPmpError::BadResponse.into());
        }
        return Ok(unsafe { Response::from_bytes(&msg[..Response::SIZE]) });
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
                    let response = self.parse_response(size, &buf)?;
                    return Ok(response);
                }
                Err(err) => match err.kind() {
                    ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                        timeout *= 2;
                    }
                    _ => {
                        return Err(err.into())
                    }
                },
            }
        }
        Err(NatPmpError::ResponseTimeout.into())
    }

    pub(crate) fn public_address(&self) -> Result<PublicAddressResponse> {
        let s = self.socket.lock();
        self.do_request(&s, &PublicAddressRequest::new())
    }

    pub(crate) fn map_port(
        &self,
        private_port: u16,
        public_port: u16,
        protocol: Protocol,
        lifetime: Lifetime,
    ) -> Result<MapPortResponse> {
        let s = self.socket.lock();
        let map_port = MapPortRequest::new(private_port, public_port, protocol, lifetime);
        self.do_request(&s, &map_port)
    }
}
