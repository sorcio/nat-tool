mod default_gw;
mod output;
#[cfg(feature = "server")]
mod server;

use std::time::Duration;
use std::{fmt::Display, net::Ipv4Addr};

use clap::{Parser, Subcommand, ValueEnum};
use miette::{Context, IntoDiagnostic, Result};

use nat_pmp_client::nonblocking::SyncUdpClient;
#[cfg(feature = "server")]
use nat_pmp_client::server::TestServerOptions;
use nat_pmp_client::{nonblocking, Lifetime, Protocol};
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// NAT-PMP gateway IP address (if not specified, try to use the default gateway)
    #[arg(short, long, env, global = true)]
    gateway: Option<Ipv4Addr>,
    /// Use this port instead of the NAT-PMP default
    #[arg(short, long, default_value_t = 5351)]
    port: u16,
    #[command(subcommand)]
    command: Commands,
    #[command(flatten)]
    #[group(multiple = false)]
    verbosity: VerbosityArgs,
}

impl Cli {
    fn configure_logging(&self) {
        let level = Option::<Level>::from(self.verbosity.log_level());

        tracing_subscriber::fmt::fmt()
            .with_span_events(FmtSpan::FULL)
            .with_max_level(level)
            .compact()
            .init();
    }

    fn make_client(&self) -> Result<SyncUdpClient> {
        let gateway = if let Some(gateway) = self.gateway {
            gateway
        } else {
            default_gw::get_default_gateway()
                .into_diagnostic()
                .wrap_err("no gateway was provided, and no default gateway could be found")?
        };
        SyncUdpClient::new(gateway, self.port, nonblocking::Announcements::Listen).into_diagnostic()
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

#[derive(clap::Args, Debug, Clone, Default)]
#[command(about = None, long_about = None)]
pub struct VerbosityArgs {
    /// Increase logging verbosity
    #[arg(
        long,
        short = 'v',
        action = clap::ArgAction::Count,
        global = true,
        help_heading = "Logging options",
    )]
    verbose: u8,

    /// Decrease logging verbosity
    #[arg(
        long,
        short = 'q',
        action = clap::ArgAction::Count,
        global = true,
        conflicts_with_all = &["verbose", "log_level"],
        help_heading = "Logging options",
    )]
    quiet: u8,

    /// Logging verbosity level
    ///
    /// Can also be set using the `-v` and `-q` flags.
    #[arg(
        long,
        short = 'l',
        global = true,
        value_enum,
        default_value_t = LogLevel::default(),
        conflicts_with_all = &["verbose", "quiet"],
        help_heading = "Logging options",
    )]
    log_level: LogLevel,
}

impl VerbosityArgs {
    fn modifier(&self) -> i8 {
        self.quiet as i8 - self.verbose as i8
    }

    fn log_level(&self) -> LogLevel {
        self.log_level.modify(self.modifier())
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Off,
}

impl TryFrom<u8> for LogLevel {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        match value {
            0 => Ok(LogLevel::Trace),
            1 => Ok(LogLevel::Debug),
            2 => Ok(LogLevel::Info),
            3 => Ok(LogLevel::Warn),
            4 => Ok(LogLevel::Error),
            5 => Ok(LogLevel::Off),
            _ => Err(()),
        }
    }
}

impl From<LogLevel> for Option<Level> {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Trace => Some(Level::TRACE),
            LogLevel::Debug => Some(Level::DEBUG),
            LogLevel::Info => Some(Level::INFO),
            LogLevel::Warn => Some(Level::WARN),
            LogLevel::Error => Some(Level::ERROR),
            LogLevel::Off => None,
        }
    }
}

impl LogLevel {
    fn modify(self, modifier: i8) -> Self {
        let level = self as u8;
        let modified_level = level
            .saturating_add_signed(modifier)
            .min(LogLevel::Off as u8);

        modified_level.try_into().unwrap()
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
    /// experimental feature: listen to external address changes
    ExternalAddressAnnouncements,
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

    let fut = client.external_address().into_diagnostic()?;
    let response = client
        .wait_for_responses([fut])
        .into_diagnostic()?
        .into_iter()
        .next()
        .unwrap();
    let external_address = response.external_address().into_diagnostic()?;

    println!("external address: {}", external_address.ip());
    Ok(())
}

fn external_address_announcements(cli: &Cli) -> Result<()> {
    let client = cli.make_client()?;
    let mut last_external_address = None;
    loop {
        let external_address = client.wait_for_next_announcement().into_diagnostic()?.ip();
        if last_external_address != Some(external_address) {
            println!("external address: {}", external_address);
            last_external_address = Some(external_address);
        }
    }
}

fn map_port(cli: &Cli, map_port_args: &MapPortArgs) -> Result<()> {
    tracing::info!("starting map_port");
    let client = cli.make_client()?;
    loop {
        let mut least_lifetime = Duration::MAX;
        let mut futures = vec![];
        if map_port_args.external_address {
            futures.push(client.external_address().into_diagnostic()?);
        }
        for protocol in map_port_args.protocol.protocols() {
            futures.push(
                client
                    .map_port(
                        *protocol,
                        map_port_args.internal_port,
                        map_port_args.external_port,
                        map_port_args.lifetime,
                    )
                    .into_diagnostic()?,
            );
        }

        let responses = client
            .wait_for_responses(futures)
            .into_diagnostic()
            .wrap_err("cannot send request to NAT-PMP gateway")?;

        let external_address = responses.iter().find_map(|response| match response.data() {
            Ok(nonblocking::ResponseData::ExternalAddress(result)) => Some(result.ip()),
            _ => None,
        });
        tracing::debug!("external address: {:?}", external_address);
        for response in responses {
            if let nonblocking::ResponseData::MapPort(result) = response.data().into_diagnostic()? {
                least_lifetime = result.lifetime.duration().min(least_lifetime);
                let notification = output::NatPmpNotification::from_response(
                    result.protocol,
                    result.clone(),
                    external_address,
                );
                println!("{}", notification.format(map_port_args.format));
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
    cli.configure_logging();
    match &cli.command {
        Commands::ExternalAddress => external_address(&cli),
        Commands::MapPort(map_port_args) => map_port(&cli, map_port_args),
        #[cfg(feature = "server")]
        Commands::Server(server_args) => server::run_server(&cli, server_args),
        Commands::ExternalAddressAnnouncements => external_address_announcements(&cli),
    }
}
