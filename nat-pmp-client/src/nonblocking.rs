use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::ops::Deref;
use std::time::{Duration, Instant};

use crate::packets::{
    ExternalAddressRequest, ExternalAddressResponse, MapPortRequest, MapPortResponse, Opcode,
    ResponseHeader, ValidatedResponseHeader, Version,
};
use crate::{Lifetime, NatPmpError, PortMapping, Protocol, RequestError};

use parking_lot::{Mutex, MutexGuard};
use tracing::instrument;
use zerocopy::{AsBytes, FromBytes};

#[derive(Debug)]
pub enum Request {
    ExternalAddress,
    MapPort {
        internal_port: u16,
        external_port: u16,
        protocol: Protocol,
        lifetime: Lifetime,
    },
}

impl Request {
    fn check_compatibility(&self, other: &Request) -> Result<(), NatPmpError> {
        match (self, other) {
            (
                Request::MapPort {
                    protocol,
                    internal_port,
                    external_port,
                    ..
                },
                Request::MapPort {
                    protocol: other_protocol,
                    internal_port: other_internal_port,
                    external_port: other_external_port,
                    ..
                },
            ) if protocol == other_protocol
                && internal_port == other_internal_port
                && external_port != other_external_port =>
            {
                Err(NatPmpError::ConflictingMappingPending {
                    protocol: *protocol,
                    internal_port: *internal_port,
                    external_port: *external_port,
                })
            }
            _ => Ok(()),
        }
    }

    fn key(&self) -> RequestKey {
        match self {
            Request::ExternalAddress => RequestKey::GetExternalAddress,
            Request::MapPort {
                protocol: Protocol::Udp,
                internal_port,
                ..
            } => RequestKey::MapUdpPort(*internal_port),
            Request::MapPort {
                protocol: Protocol::Tcp,
                internal_port,
                ..
            } => RequestKey::MapTcpPort(*internal_port),
        }
    }

    fn as_bytes(&self) -> FixedSizeBuffer {
        match self {
            Request::ExternalAddress => {
                let request = ExternalAddressRequest::new();
                FixedSizeBuffer::from_pod(request)
            }
            Request::MapPort {
                internal_port,
                external_port,
                protocol,
                lifetime,
            } => {
                let request =
                    MapPortRequest::new(*internal_port, *external_port, *protocol, *lifetime);
                FixedSizeBuffer::from_pod(request)
            }
        }
    }
}

#[derive(Debug)]
struct RequestState {
    request: Request,
    time: Instant,
    attempts: u8,
    response: Option<Response>,
    wakers: Vec<std::task::Waker>,
}

enum ShouldSend {
    No,
    Now,
    Later(Instant),
}

impl RequestState {
    fn new(request: Request, time: Instant) -> Self {
        Self {
            request,
            time,
            attempts: 0,
            response: None,
            wakers: Vec::new(),
        }
    }

    fn should_send(&self, now: Instant) -> ShouldSend {
        const MAX_ATTEMPTS: u8 = 10;
        const BASIC_DELAY: Duration = Duration::from_millis(250);
        if self.response.is_some() || self.attempts >= MAX_ATTEMPTS {
            ShouldSend::No
        } else if self.attempts == 0 {
            ShouldSend::Now
        } else {
            // Exponential backoff: start with 250 ms, then double each time
            let next_attempt = self.time + BASIC_DELAY * 2u32.pow(self.attempts as u32);
            if now >= next_attempt {
                ShouldSend::Now
            } else {
                ShouldSend::Later(next_attempt)
            }
        }
    }

    fn increment_attempts(&mut self) {
        self.attempts += 1;
    }

    fn set_response(&mut self, response: Result<ResponseData, NatPmpError>, now: Instant) {
        tracing::trace!(?response, "Setting response");
        debug_assert!(
            self.response.is_none(),
            "response already set to {:?}, cannot set to {response:?}",
            self.response
        );
        self.response = Some(Response {
            time: now,
            data: response,
        });
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }

    fn as_bytes(&self) -> FixedSizeBuffer {
        self.request.as_bytes()
    }

    fn register_waker(&mut self, waker: std::task::Waker) {
        self.wakers.push(waker);
    }
}

#[derive(Debug, Clone)]
pub enum ResponseData {
    ExternalAddress(ExternalAddressResponse),
    MapPort(PortMapping),
}

#[derive(Debug, Clone)]
pub struct Response {
    time: Instant,
    data: Result<ResponseData, NatPmpError>,
}

impl Response {
    pub fn data(&self) -> Result<&ResponseData, NatPmpError> {
        self.data.as_ref().map_err(|e| e.clone())
    }

    pub fn time(&self) -> Instant {
        self.time
    }

    pub fn external_address(self) -> Result<ExternalAddressResponse, NatPmpError> {
        match self.data {
            Ok(ResponseData::ExternalAddress(addr)) => Ok(addr),
            Ok(_) => panic!("Response is not an external address response"),
            Err(e) => Err(e),
        }
    }

    pub fn port_mapping(self) -> Result<PortMapping, NatPmpError> {
        match self.data {
            Ok(ResponseData::MapPort(mapping)) => Ok(mapping),
            Ok(_) => panic!("Response is not a port mapping response"),
            Err(e) => Err(e),
        }
    }
}

pub struct ResponseFuture<'client> {
    client: &'client NonblockingClient,
    key: RequestKey,
}

impl<'client> ResponseFuture<'client> {
    fn new(client: &'client NonblockingClient, key: RequestKey) -> Self {
        Self { client, key }
    }

    fn poll_response(&self) -> Option<Response> {
        self.client
            .pending_requests
            .lock()
            .get(&self.key)
            .and_then(|request| request.response.clone())
    }
}

impl<'client> core::future::Future for ResponseFuture<'client> {
    type Output = Response;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if let Some(request) = self.client.pending_requests.lock().get_mut(&self.key) {
            if let Some(response) = &request.response {
                std::task::Poll::Ready(response.clone())
            } else {
                request.register_waker(cx.waker().clone());
                std::task::Poll::Pending
            }
        } else {
            // Not supposed to happen, but should be safe to return Pending
            std::task::Poll::Pending
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RequestKey {
    GetExternalAddress,
    MapUdpPort(u16),
    MapTcpPort(u16),
}

impl RequestKey {
    fn soft_match_opcode(self, opcode: Opcode) -> bool {
        match self {
            RequestKey::GetExternalAddress => opcode == Opcode::GetExternalAddress,
            RequestKey::MapUdpPort(_) => opcode == Opcode::MapUdpPort,
            RequestKey::MapTcpPort(_) => opcode == Opcode::MapTcpPort,
        }
    }
}

pub trait TimeSource {
    fn now(&self) -> Instant;
}

#[derive(Debug)]
struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

pub struct NonblockingClient {
    time_source: Box<dyn TimeSource>,
    pending_requests: Mutex<HashMap<RequestKey, RequestState>>,
}

impl core::fmt::Debug for NonblockingClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonblockingClient")
            .field("pending_requests", &self.pending_requests)
            .finish()
    }
}

impl Default for NonblockingClient {
    fn default() -> Self {
        Self::new(Box::new(SystemTimeSource) as _)
    }
}

impl NonblockingClient {
    pub fn new(time_source: Box<dyn TimeSource>) -> Self {
        Self {
            time_source,
            pending_requests: Default::default(),
        }
    }

    pub fn request(&self, request: Request) -> Result<ResponseFuture, NatPmpError> {
        let key = request.key();
        match self.pending_requests.lock().entry(key) {
            Entry::Occupied(entry) => {
                let existing_request = entry.get();
                existing_request.request.check_compatibility(&request)?;
            }
            Entry::Vacant(entry) => {
                let pending_request = RequestState::new(request, self.time_source.now());
                entry.insert(pending_request);
            }
        }
        let future = ResponseFuture::new(self, key);
        Ok(future)
    }

    pub fn external_address(&self) -> Result<ResponseFuture, NatPmpError> {
        // convenience method
        self.request(Request::ExternalAddress)
    }

    pub fn map_port(
        &self,
        protocol: Protocol,
        external_port: u16,
        internal_port: u16,
        lifetime: Lifetime,
    ) -> Result<ResponseFuture, NatPmpError> {
        // convenience method
        self.request(Request::MapPort {
            protocol,
            external_port,
            internal_port,
            lifetime,
        })
    }

    #[instrument(skip_all, level = "trace")]
    fn parse_packet(&self, _source: Ipv4Addr, data: &[u8]) {
        let Some((header, payload)) = ValidatedResponseHeader::checked_from_bytes(data) else {
            tracing::trace!("Invalid response header");
            return;
        };
        if header.version() != Version::NatPmp {
            tracing::trace!("version mismatch (maybe not a NAT-PMP response)");
        }
        let opcode = header.opcode();
        let mut pending_requests = self.pending_requests.lock();
        let now = self.time_source.now();
        match opcode {
            Opcode::GetExternalAddress => {
                let key = RequestKey::GetExternalAddress;
                let mut entry = {
                    match pending_requests.entry(key) {
                        Entry::Occupied(entry) => entry,
                        Entry::Vacant(_) => {
                            // no matching request
                            return;
                        }
                    }
                };
                let result = header.result();
                if !result.is_success() {
                    entry
                        .get_mut()
                        .set_response(Err(NatPmpError::ProtocolError(result)), now);
                } else if let Some(response) = ExternalAddressResponse::read_from(payload) {
                    entry
                        .get_mut()
                        .set_response(Ok(ResponseData::ExternalAddress(response)), now);
                } else {
                    // invalid response
                    entry
                        .get_mut()
                        .set_response(Err(NatPmpError::BadResponse), now);
                }
            }
            Opcode::MapUdpPort | Opcode::MapTcpPort => {
                // some extra dance steps to get around non-compliant servers
                // and *try* to send a response to the right request even in
                // error cases where the response is missing the payload which
                // would allow us to identify the request
                if let Some(response) = MapPortResponse::read_from(payload) {
                    // easy case: we have a parsable response
                    let internal_port = response.internal_port();
                    let key = match opcode {
                        Opcode::MapUdpPort => RequestKey::MapUdpPort(internal_port),
                        Opcode::MapTcpPort => RequestKey::MapTcpPort(internal_port),
                        _ => unreachable!(),
                    };
                    let protocol = match opcode {
                        Opcode::MapUdpPort => Protocol::Udp,
                        Opcode::MapTcpPort => Protocol::Tcp,
                        _ => unreachable!(),
                    };
                    let mut entry = {
                        match pending_requests.entry(key) {
                            Entry::Occupied(entry) => entry,
                            Entry::Vacant(_) => {
                                // no matching request
                                return;
                            }
                        }
                    };
                    let result = header.result();
                    if !result.is_success() {
                        entry
                            .get_mut()
                            .set_response(Err(NatPmpError::ProtocolError(result)), now);
                        return;
                    }
                    entry.get_mut().set_response(
                        Ok(ResponseData::MapPort(PortMapping::from_response(
                            protocol, &response,
                        ))),
                        now,
                    );
                } else {
                    // Invalid or missing payload. We would like to report an
                    // error to the requester, but we can't in general because
                    // we don't have the internal port number to identify the
                    // request. But a common case is that only one request is
                    // pending at a time, so we can just try to find it.
                    tracing::trace!("Missing or invalid payload in response");
                    let matching_requests = pending_requests
                        .iter_mut()
                        .filter(|(key, _)| key.soft_match_opcode(opcode))
                        .map(|(_, request)| request)
                        .take(2)
                        .collect::<Vec<_>>();
                    if matching_requests.len() != 1 {
                        // no matching request, or multiple matching requests
                        // which we can't disambiguate so we just discard the
                        // packet and let the request time out
                        return;
                    }
                    let request = matching_requests.into_iter().next().unwrap();
                    let result = header.result();
                    request.set_response(Err(NatPmpError::ProtocolError(result)), now);
                }
            }
        };
    }

    fn pending_requests(&self) -> PendingRequests {
        let guard = self.pending_requests.lock();
        PendingRequests {
            client: self,
            guard,
        }
    }
}

struct PendingRequests<'c> {
    client: &'c NonblockingClient,
    guard: MutexGuard<'c, HashMap<RequestKey, RequestState>>,
}

impl<'c> PendingRequests<'c> {
    fn outgoing(&mut self) -> OutgoingIterator {
        let inner = self.guard.iter_mut();
        let now = self.client.time_source.now();
        OutgoingIterator { now, inner }
    }
}

struct FixedSizeBuffer<const MAX_SIZE: usize = 16> {
    buf: [u8; MAX_SIZE],
    len: usize,
}

impl<const MAX_SIZE: usize> FixedSizeBuffer<MAX_SIZE> {
    fn from_pod<T: AsBytes>(data: T) -> Self {
        let bytes = data.as_bytes();
        Self::from_slice(bytes)
    }

    fn from_slice(data: &[u8]) -> Self {
        assert!(data.len() <= MAX_SIZE);
        let mut buf = [0; MAX_SIZE];
        let len = data.len();
        buf[..len].copy_from_slice(data);
        FixedSizeBuffer { buf, len }
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Deref for FixedSizeBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

enum OutgoingItem {
    Send(FixedSizeBuffer),
    Wait(Instant),
}

struct OutgoingIterator<'r> {
    now: Instant,
    inner: std::collections::hash_map::IterMut<'r, RequestKey, RequestState>,
}

impl<'r> Iterator for OutgoingIterator<'r> {
    type Item = OutgoingItem;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (_key, request) = self.inner.next()?;
            match request.should_send(self.now) {
                ShouldSend::No => (),
                ShouldSend::Now => {
                    tracing::info!(?request, "sending request");

                    let buf = request.as_bytes();
                    request.increment_attempts();
                    return Some(OutgoingItem::Send(buf));
                }
                ShouldSend::Later(deadline) => {
                    return Some(OutgoingItem::Wait(deadline));
                }
            }
        }
    }
}

fn ipv4_addr_from_socket_addr(addr: &SocketAddr, default: Ipv4Addr) -> Ipv4Addr {
    match addr {
        SocketAddr::V4(v4) => *v4.ip(),
        _ => default,
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Announcements {
    #[default]
    DontListen,
    Listen,
}

pub struct SyncUdpClient {
    socket: UdpSocket,
    multicast_socket: Option<UdpSocket>,
    inner: NonblockingClient,
}

impl SyncUdpClient {
    pub fn new(
        gateway: Ipv4Addr,
        port: u16,
        announcements: Announcements,
    ) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
        let gw_addr = SocketAddrV4::new(gateway, port);
        socket.connect(gw_addr)?;

        let multicast_socket = if let Announcements::Listen = announcements {
            // From RFC 6886 (3.2.1):
            // IMPLEMENTATION NOTE: A given host may have more than one independent
            // NAT-PMP client running at the same time, and address announcements
            // need to be available to all of them.  Clients should therefore set
            // the SO_REUSEPORT option or equivalent in order to allow other
            // processes to also listen on port 5350.  Additionally, implementers
            // have encountered issues when one or more processes on the same device
            // listen to port 5350 on *all* addresses.  Clients should therefore
            // bind specifically to 224.0.0.1:5350, not to 0.0.0.0:5350.
            //
            // TODO: set SO_REUSEPORT
            let local_addr = socket.local_addr()?;
            let local_ipv4 = ipv4_addr_from_socket_addr(&local_addr, Ipv4Addr::UNSPECIFIED);
            tracing::info!(?local_ipv4, "listening for announcements");
            let multicast_bind_addr = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 5350);
            let multicast_socket = UdpSocket::bind(multicast_bind_addr)?;
            multicast_socket.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 1), &local_ipv4)?;
            Some(multicast_socket)
        } else {
            None
        };

        Ok(Self {
            socket,
            multicast_socket,
            inner: NonblockingClient::default(),
        })
    }

    /// Wait for the next announcement from the gateway.
    /// This method WILL be removed in the future.
    pub fn wait_for_next_announcement(&self) -> Result<ExternalAddressResponse, RequestError> {
        let mut buf = [0; 32];
        #[allow(clippy::never_loop)] // (see TODO below)
        let len = loop {
            let (len, _addr) = self
                .multicast_socket
                .as_ref()
                .unwrap()
                .recv_from(&mut buf)?;

            // From RFC 6886 (3.2.1):
            // Upon receiving a gratuitous address announcement packet, the client
            // MUST check the source IP address, and silently discard the packet if
            // the address is not the address of the client's current configured
            // gateway.  This is to guard against inadvertent misconfigurations
            // where there may be more than one NAT gateway active on the network.
            // TODO: check addr
            break len;
        };
        let header = ResponseHeader::read_from(&buf[..size_of::<ResponseHeader>()])
            .ok_or(NatPmpError::BadResponse)?;
        let bytes = &buf[size_of::<ResponseHeader>()..len];
        tracing::debug!(?header, ?bytes, "received announcement");
        ExternalAddressResponse::read_from(bytes).ok_or(NatPmpError::BadResponse.into())
    }

    pub fn request(&self, request: Request) -> Result<ResponseFuture, NatPmpError> {
        self.inner.request(request)
    }

    pub fn external_address(&self) -> Result<ResponseFuture, NatPmpError> {
        self.request(Request::ExternalAddress)
    }

    pub fn map_port(
        &self,
        protocol: Protocol,
        internal_port: u16,
        external_port: u16,
        lifetime: Lifetime,
    ) -> Result<ResponseFuture, NatPmpError> {
        self.request(Request::MapPort {
            protocol,
            internal_port,
            external_port,
            lifetime,
        })
    }

    pub fn wait_for_responses<'s>(
        &'s self,
        futures: impl IntoIterator<Item = ResponseFuture<'s>> + 's,
    ) -> Result<Vec<Response>, RequestError> {
        let socket = &self.socket;
        let client = &self.inner;
        let mut next_deadline = self.send_outgoing()?;

        let mut pending = futures.into_iter().collect::<Vec<_>>();
        let mut responses = Vec::with_capacity(pending.len());

        let mut buf = [0; 1024];
        loop {
            loop {
                if let Some(next_deadline) = next_deadline {
                    let now = Instant::now();
                    let timeout = next_deadline - now;
                    socket.set_read_timeout(Some(timeout))?;
                }
                match socket.recv_from(&mut buf) {
                    Ok((size, sock_addr)) => {
                        let data = &buf[..size];
                        tracing::trace!(?sock_addr, ?data, "received packet");
                        let source = ipv4_addr_from_socket_addr(&sock_addr, Ipv4Addr::UNSPECIFIED);
                        client.parse_packet(source, data);
                        pending.retain(|f| {
                            if let Some(response) = f.poll_response() {
                                responses.push(response);
                                false
                            } else {
                                true
                            }
                        });
                        if pending.is_empty() {
                            tracing::trace!(?responses, "responses ready");
                            return Ok(responses);
                        }
                    }
                    Err(err) => match err.kind() {
                        ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                            tracing::trace!("no packet received yet");
                            break;
                        }
                        _ => return Err(err.into()),
                    },
                }
            }

            if let Some(deadline) = self.send_outgoing()? {
                next_deadline = Some(deadline);
            } else {
                return Err(NatPmpError::ResponseTimeout.into());
            }
        }
    }

    fn send_outgoing(&self) -> Result<Option<Instant>, std::io::Error> {
        self.inner
            .pending_requests()
            .outgoing()
            .map(|data| match data {
                OutgoingItem::Wait(deadline) => Ok(Some(deadline)),
                OutgoingItem::Send(data) => self.socket.send(&data).map(|_| None),
            })
            .try_fold(None, |next_deadline, item| match item {
                Ok(Some(deadline)) => Ok(Some(
                    next_deadline.map_or(deadline, |d: Instant| d.min(deadline)),
                )),
                Ok(None) => Ok(next_deadline),
                Err(e) => Err(e),
            })
    }
}
