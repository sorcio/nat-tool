mod client;

use std::net::Ipv4Addr;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use miette::{IntoDiagnostic, Result};

use client::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// NAT-PMP gateway IP address
    #[arg(short, long, env)]
    gateway: Ipv4Addr,
    /// Use this port instead of the NAT-PMP default
    #[arg(short, long, default_value_t = 5351)]
    port: u16,
    #[command(subcommand)]
    command: Commands,
}

impl Cli {
    fn make_client(&self) -> Result<NatPmpClient> {
        NatPmpClient::new(self.gateway, self.port).into_diagnostic()
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Check external address
    ExternalAddress,
    /// Map an external (or public) port to an internal (or private) port.
    MapPort(MapPortArgs),
}

#[derive(Debug, clap::Args)]
struct MapPortArgs {
    /// port type
    #[arg(short, long, value_enum, default_value_t = PortType::Both)]
    protocol: PortType,
    /// the external port number (0 to auto-select, if supported)
    public_port: u16,
    /// the internal port number (0 to auto-select, if supported)
    private_port: u16,
    /// how long should the mapping stay open (in seconds)
    #[arg(short, long, default_value_t = Lifetime::from_secs(60))]
    lifetime: Lifetime,
    /// automatically repeat the request when lifetime is about to expire
    #[arg(short, long, default_value_t = false)]
    repeat: bool,
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

    let public_address = client.public_address().into_diagnostic()?;
    println!("public address: {}", public_address.ip());
    Ok(())
}

fn map_port(cli: &Cli, map_port_args: &MapPortArgs) -> Result<()> {
    let client = cli.make_client()?;

    loop {
        let mut least_lifetime = Duration::MAX;
        for protocol in map_port_args.protocol.protocols() {
            let map_port_result = client
                .map_port(
                    map_port_args.private_port,
                    map_port_args.public_port,
                    *protocol,
                    map_port_args.lifetime,
                )
                .into_diagnostic()?;
            println!(
                "{:?} public port {} -> private port {} ({})",
                protocol,
                map_port_result.private_port(),
                map_port_result.public_port(),
                map_port_result.lifetime(),
            );
            least_lifetime = map_port_result.lifetime().duration().min(least_lifetime);
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
    }
}
