mod default_gw;
mod output;
#[cfg(feature = "server")]
mod server;

use std::time::Duration;
use std::{fmt::Display, net::Ipv4Addr};

use clap::{Parser, Subcommand, ValueEnum};
use miette::{Context, IntoDiagnostic, Result};

#[cfg(feature = "server")]
use nat_pmp_client::server::TestServerOptions;
use nat_pmp_client::{nonblocking, Lifetime, NatPmpClient, Protocol};
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// NAT-PMP gateway IP address (if not specified, try to use the default gateway)
    #[arg(short, long, env)]
    gateway: Option<Ipv4Addr>,
    /// Use this port instead of the NAT-PMP default
    #[arg(short, long, default_value_t = 5351)]
    port: u16,
    #[command(subcommand)]
    command: Commands,
}

impl Cli {
    fn make_client(&self) -> Result<NatPmpClient> {
        let gateway = if let Some(gateway) = self.gateway {
            gateway
        } else {
            default_gw::get_default_gateway()
                .into_diagnostic()
                .wrap_err("no gateway was provided, and no default gateway could be found")?
        };
        NatPmpClient::new(gateway, self.port).into_diagnostic()
    }

    #[cfg(feature = "server")]
    fn make_server_config(&self) -> Result<TestServerOptions> {
        use std::net::SocketAddrV4;

        let Commands::Server(server_args) = &self.command else {
            panic!("make_server_config called with non-Server command");
        };

        use nat_pmp_client::server::TestServerOptionsBuilder;

        let ip = self.gateway.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let port = self.port;
        let bind_address = SocketAddrV4::new(ip, port);
        let mut options = TestServerOptionsBuilder::default();
        options.bind_address(bind_address);
        options.external_address(server_args.external_address.into_option());
        options.port_ranges(server_args.port_mappings.clone());
        Ok(options.build().unwrap())
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Check external address
    ExternalAddress,
    /// Map an external (or public) port to an internal (or private) port.
    MapPort(MapPortArgs),
    /// Run a fake NAT-PMP server (for testing)
    #[cfg(feature = "server")]
    Server(server::ServerArgs),
}

#[derive(Debug, clap::Args)]
struct MapPortArgs {
    /// port type
    #[arg(short, long, value_enum, default_value_t = PortType::Both)]
    protocol: PortType,
    /// the external port number (0 to auto-select, if supported)
    external_port: u16,
    /// the internal port number (0 to auto-select, if supported)
    internal_port: u16,
    /// how long should the mapping stay open (in seconds)
    #[arg(short, long, default_value_t = Lifetime::from_secs(60))]
    lifetime: Lifetime,
    /// automatically repeat the request when lifetime is about to expire
    #[arg(short, long, default_value_t = false)]
    repeat: bool,
    /// monitor external address changes and report them
    /// (only works with the `repeat` option)
    #[arg(short, long, default_value_t = false)]
    external_address: bool,
    /// how to format the output
    #[arg(short, long, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// output the result of the operation as JSON
    Json,
    /// output the result of the operation as human-readable text
    Text,
}

impl Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Text => write!(f, "text"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum PortType {
    /// port numbers indicate a TCP port
    Tcp,
    /// port numbers indicate a UDP port
    Udp,
    /// apply operation to both TCP and UDP ports with the given port number
    Both,
}

impl PortType {
    fn protocols(&self) -> &[Protocol] {
        match self {
            PortType::Tcp => &[Protocol::Tcp],
            PortType::Udp => &[Protocol::Udp],
            PortType::Both => &[Protocol::Tcp, Protocol::Udp],
        }
    }
}

fn external_address(cli: &Cli) -> Result<()> {
    let client = cli.make_client()?;

    let external_address = client.external_address().into_diagnostic()?;
    println!("external address: {}", external_address.ip());
    Ok(())
}

fn map_port(cli: &Cli, map_port_args: &MapPortArgs) -> Result<()> {
    tracing_subscriber::fmt::fmt()
        .with_span_events(FmtSpan::FULL)
        .with_max_level(Level::TRACE)
        .compact()
        .init();

    tracing::info!("starting map_port");
    let client = cli.make_client()?;
    loop {
        let mut least_lifetime = Duration::MAX;
        let mut requests = vec![];
        if map_port_args.external_address {
            requests.push(nonblocking::Request::ExternalAddress);
        }
        requests.extend(map_port_args.protocol.protocols().iter().map(|&protocol| {
            nonblocking::Request::MapPort {
                internal_port: map_port_args.internal_port,
                external_port: map_port_args.external_port,
                protocol,
                lifetime: map_port_args.lifetime,
            }
        }));
        let responses = client
            ._nonblocking_but_blocking_requests(requests)
            .into_diagnostic()
            .wrap_err("cannot send request to NAT-PMP gateway")?;

        let external_address = responses.iter().find_map(|response| match response.data() {
            Ok(nonblocking::ResponseData::ExternalAddress(result)) => Some(result.ip()),
            _ => None,
        });
        tracing::debug!("external address: {:?}", external_address);
        for response in responses {
            match response.data().into_diagnostic()? {
                nonblocking::ResponseData::MapPort(result) => {
                    least_lifetime = result.lifetime.duration().min(least_lifetime);
                    let notification = output::NatPmpNotification::from_response(
                        result.protocol,
                        result.clone(),
                        external_address,
                    );
                    println!("{}", notification.format(map_port_args.format));
                }
                _ => {
                    tracing::debug!(?response, "unexpected response");
                }
            }
        }
        if !map_port_args.repeat {
            break;
        }
        std::thread::sleep(least_lifetime / 2);
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::ExternalAddress => external_address(&cli),
        Commands::MapPort(map_port_args) => map_port(&cli, map_port_args),
        #[cfg(feature = "server")]
        Commands::Server(server_args) => server::run_server(&cli, server_args),
    }
}
