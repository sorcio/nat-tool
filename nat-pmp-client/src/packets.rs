use std::net::Ipv4Addr;

use zerocopy::byteorder::{NetworkEndian, U16, U32};
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};

use crate::{Lifetime, NatPmpError, Result};

/// Implement TryFrom<int> for enums with `#[repr(int)]` attribute.
///
/// # Example
/// ```
/// # #[macro_use] extern crate nat_pmp_client;
/// int_enum! {
///    #[repr(u8)]
///    #[derive(Debug, PartialEq)]
///    pub enum Foo {
///        Bar = 1,
///        Baz = 2,
///    }
/// }
/// let foo = Foo::try_from(1).unwrap();
/// assert_eq!(foo, Foo::Bar);
/// ```
#[macro_export]
macro_rules! int_enum {
    (
        #[repr($int_type:ident)]
        $( #[$attr:meta] )*
        $vis:vis enum $name:ident {
            $(
                $( #[$variant_attr:meta] )*
                $variant:ident = $value:expr
            ),*
            $(,)? // optional trailing comma
        }
    ) => {
        #[repr($int_type)]
        $( #[$attr] )*
        $vis enum $name {
            $(
                $( #[$variant_attr] )*
                $variant = $value
            ),*
        }

        impl ::core::convert::TryFrom<$int_type> for $name {
            type Error = $int_type;

            fn try_from(value: $int_type) -> ::core::result::Result<Self, Self::Error> {
                match value {
                    $(
                        $value => Ok(Self::$variant),
                    )*
                    invalid_value => Err(invalid_value),
                }
            }
        }

        impl ::core::convert::From<$name> for $int_type {
            fn from(value: $name) -> Self {
                value as $int_type
            }
        }
    };
}

int_enum! {
    #[repr(u16)]
    #[derive(Debug, Clone, Copy)]
    pub enum ResultCode {
        /// Success
        Success = 0,
        /// Unsupported Version
        UnsupportedVersion = 1,
        /// Not Authorized/Refused (e.g. box supports mapping, but user has turned feature off)
        NotAuthorized = 2,
        /// Network Failure (e.g. NAT box itself has not obtained a DHCP lease)
        NetworkFailure = 3,
        /// Out of resources (NAT box cannot create any more mappings at this time)
        OutOfResources = 4,
        /// Unsupported opcode
        UnsupportedOpcode = 5,
    }
}

impl ResultCode {
    pub(crate) fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

int_enum! {
    #[repr(u8)]
    #[derive(Debug, Clone, Copy)]
    pub enum Protocol {
        Udp = 1,
        Tcp = 2,
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, AsBytes)]
pub(crate) enum Opcode {
    GetExternalAddress = 0,
    MapUdpPort = 1,
    MapTcpPort = 2,
}

impl Opcode {
    pub(crate) fn get_external_address() -> Self {
        Opcode::GetExternalAddress
    }

    pub(crate) fn map_port(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Udp => Opcode::MapUdpPort,
            Protocol::Tcp => Opcode::MapTcpPort,
        }
    }
}

int_enum! {
    #[repr(u8)]
    #[derive(Debug, Clone, Copy)]
    pub(crate) enum Version {
        NatPmp = 0,
        Pcp = 2,
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, FromZeroes, FromBytes)]
pub(crate) struct ResponseHeader {
    version: u8,
    opcode: u8,
    result: U16<NetworkEndian>,
    timestamp: U32<NetworkEndian>,
}

impl ResponseHeader {
    pub(crate) const SIZE: usize = std::mem::size_of::<Self>();

    pub(crate) fn version(&self) -> core::result::Result<Version, u8> {
        Version::try_from(self.version).map_err(|_| self.version)
    }

    #[allow(unused)] // TODO: see https://datatracker.ietf.org/doc/html/rfc6886#section-3.6
    fn timestamp(&self) -> Lifetime {
        Lifetime::from_secs(self.timestamp.get())
    }

    pub(crate) fn result(&self) -> Result<ResultCode> {
        let raw_code = self.result.get();
        ResultCode::try_from(raw_code).map_err(NatPmpError::UnknownResultCode)
    }
}

#[repr(C, packed)]
#[derive(FromZeroes, FromBytes)]
pub(crate) struct ResponsePacket<T> {
    header: ResponseHeader,
    payload: T,
}

impl<T> ResponsePacket<T> {
    pub(crate) fn header(&self) -> &ResponseHeader {
        &self.header
    }

    pub(crate) fn into_payload(self) -> T {
        self.payload
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, AsBytes)]
pub(crate) struct ExternalAddressRequest {
    version: u8,
    opcode: Opcode,
    reserved: u16,  // PCP compatibility hack
    reserved2: u32, // PCP compatibility hack
}

impl ExternalAddressRequest {
    pub(crate) fn new() -> Self {
        Self {
            version: 0,
            opcode: Opcode::get_external_address(),
            reserved: 0,
            reserved2: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, FromZeroes, FromBytes)]
pub struct ExternalAddressResponse {
    ip: [u8; 4],
}

impl ExternalAddressResponse {
    pub fn ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.ip)
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, AsBytes)]
pub(crate) struct MapPortRequest {
    version: u8,
    opcode: Opcode,
    reserved: u16,
    internal_port_be: [u8; 2],
    external_port_be: [u8; 2],
    lifetime_be: [u8; 4],
}

impl MapPortRequest {
    pub(crate) fn new(
        internal_port: u16,
        external_port: u16,
        protocol: Protocol,
        lifetime: Lifetime,
    ) -> Self {
        let internal_port_be = internal_port.to_be_bytes();
        let external_port_be = external_port.to_be_bytes();
        let lifetime_be = lifetime.to_be_bytes();
        let opcode = Opcode::map_port(protocol);
        Self {
            version: 0,
            opcode,
            reserved: 0,
            internal_port_be,
            external_port_be,
            lifetime_be,
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, FromZeroes, FromBytes)]
pub(crate) struct MapPortResponse {
    internal_port: U16<NetworkEndian>,
    external_port: U16<NetworkEndian>,
    lifetime: U32<NetworkEndian>,
}

impl MapPortResponse {
    pub(crate) fn internal_port(&self) -> u16 {
        self.internal_port.get()
    }

    pub(crate) fn external_port(&self) -> u16 {
        self.external_port.get()
    }

    pub(crate) fn lifetime(&self) -> crate::Lifetime {
        Lifetime::from_secs(self.lifetime.get())
    }
}
