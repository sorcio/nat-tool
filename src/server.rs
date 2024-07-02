use std::net::Ipv4Addr;

use miette::{Context as _, IntoDiagnostic};
use nat_pmp_client::server::{PortMappingOptions, PortRange, ProtocolOptions, UdpServer};
use thiserror::Error;

use crate::Cli;

#[derive(Debug, clap::Args)]
pub(crate) struct ServerArgs {
    /// The address that external address requests should return.
    #[arg(long, default_value = "127.0.0.1", value_parser = parse_optional_value::<Ipv4Addr>)]
    pub(crate) external_address: OptionalValue<Ipv4Addr>,

    /// Specify one or more port mappings to simulate, in the format [<protocol>/]<internal>:<external>
    ///
    /// where:
    /// - <protocol> is either "tcp" or "udp" (optional, default is both)
    /// - <internal> is a port number or range
    /// - <external> is a port number or range, or "no" to disallow mapping
    ///
    /// Multiple mappings can be specified, either separated by commas, or by
    /// repeating the option. When multiple overlapping mappings are specified,
    /// the last one takes precedence. The internal and external ranges must
    /// have the same number of ports.
    ///
    /// When a mapping is not specified, the default is to allow any external
    /// port to map to the same internal port. This is equivalent to specifying
    /// "--port 1-65535:1-65535" as a first option. To disable this behavior,
    /// simply specify "--port 1-65535:no" as the first option.
    ///
    /// Examples:
    ///
    /// 1234:5678                 (single port, both TCP and UDP)
    /// 1000-2000:11000-12000     (range, both TCP and UDP)
    /// tcp/1234:5678             (single port, TCP only)
    /// udp/1000-2000:11000-12000 (range, UDP only)
    /// 1234:no                   (single port, disallowed)
    /// 1000-2000:no              (range, disallowed)
    #[arg(short = 'p', long = "port", value_parser = parse_port_mapping_options, value_delimiter = ',', verbatim_doc_comment)]
    pub(crate) port_mappings: Vec<PortMappingOptions>,
}

#[derive(Debug, Error, PartialEq)]
enum ParsePortMappingOptionsError {
    #[error("invalid protocol, must be 'tcp' or 'udp' if specified")]
    InvalidProtocol,
    #[error("expected [<protocol>/]<internal>:<external>")]
    MissingDelimiter,
    #[error("invalid port number or range")]
    InvalidPort(#[from] std::num::ParseIntError),
    #[error("range must be in the form <start>-<end>")]
    InvalidRange,
    #[error("internal and external ranges must have the same number of ports")]
    MismatchedPortCount,
}

fn parse_port_mapping_options(
    raw: &str,
) -> std::result::Result<PortMappingOptions, ParsePortMappingOptionsError> {
    // accepted formats:
    // [<protocol>/]<internal>:<external>
    // where:
    // - <protocol> is either "tcp" or "udp" (optional, default is both)
    // - <internal> is a port number or range
    // - <external> is a port number or range, or "no" to disallow
    // examples:
    // 1234:5678 (single port)
    // 1000-2000:11000-12000 (range)
    // 1234:no (single port, no external port)
    // 1000-2000:no (range, no external port)
    let (protocol, rest) = if let Some((raw_protocol, rest)) = raw.split_once('/') {
        let protocol = match raw_protocol {
            "tcp" => ProtocolOptions::Tcp,
            "udp" => ProtocolOptions::Udp,
            _ => return Err(ParsePortMappingOptionsError::InvalidProtocol),
        };
        (protocol, rest)
    } else {
        (ProtocolOptions::Both, raw)
    };
    let Some((raw_internal, raw_external)) = rest.split_once(':') else {
        return Err(ParsePortMappingOptionsError::MissingDelimiter);
    };
    let internal = parse_port_range(raw_internal)?;
    let external_start = if raw_external == "no" {
        None
    } else {
        let external = parse_port_range(raw_external)?;
        if internal.len() != external.len() {
            return Err(ParsePortMappingOptionsError::MismatchedPortCount);
        }
        Some(external.start())
    };

    PortMappingOptions::new(protocol, internal, external_start)
        .ok_or(ParsePortMappingOptionsError::InvalidRange)
}

fn parse_port_range(raw: &str) -> std::result::Result<PortRange, ParsePortMappingOptionsError> {
    let (start, end) = if let Some((start, end)) = raw.split_once('-') {
        let start = start.parse()?;
        let end = end.parse()?;
        (start, end)
    } else {
        let port = raw.parse()?;
        (port, port)
    };
    PortRange::checked_new(start, end).ok_or(ParsePortMappingOptionsError::InvalidRange)
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum OptionalValue<T> {
    Enabled(T),
    Disabled,
}

impl<T> OptionalValue<T> {
    pub(crate) fn into_option(self) -> Option<T> {
        match self {
            OptionalValue::Enabled(value) => Some(value),
            OptionalValue::Disabled => None,
        }
    }
}

fn parse_optional_value<T>(raw: &str) -> std::result::Result<OptionalValue<T>, T::Err>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    if raw == "no" {
        Ok(OptionalValue::Disabled)
    } else {
        let value = raw.parse()?;
        Ok(OptionalValue::Enabled(value))
    }
}

pub(crate) fn run_server(cli: &Cli, _server_args: &ServerArgs) -> crate::Result<()> {
    let config = cli.make_server_config()?;

    let server = config.build_server().into_diagnostic()?;
    let server = Box::leak(Box::new(server));
    let handle = std::thread::spawn(|| server.run());

    std::thread::sleep(std::time::Duration::from_millis(100));
    if handle.is_finished() {
        let err = handle.join().expect("server thread panicked");
        return err.into_diagnostic().wrap_err("server exited prematurely");
    }

    if console_handler(server).is_err() {
        // Probably console is not available or was closed, so it's unlikely we
        // can report an error to anyone who cares. Forget about the terminal
        // and just wait the server thread.
        handle
            .join()
            .expect("server thread panicked")
            .into_diagnostic()?;
    }

    Ok(())
}

fn console_handler(server: &UdpServer) -> std::io::Result<()> {
    use console::{Key, Term};
    use std::io::Write;
    let mut term = Term::stdout();
    writeln!(
        term,
        "Fake NAT-PMP server started. Interactive console commands:"
    )?;
    show_help(&mut term)?;

    fn show_help(term: &mut Term) -> std::io::Result<()> {
        writeln!(term, "q: quit (also ctrl-c)")?;
        writeln!(term, "a: announce new external address")?;
        writeln!(term, "h: show this help")?;
        Ok(())
    }

    loop {
        match term.read_key() {
            Ok(Key::Char('q')) => {
                // quit
                return Ok(());
            }
            Ok(Key::Char('h') | Key::Char('?')) => {
                // show help
                show_help(&mut term)?;
            }
            Ok(Key::Char('a')) => {
                // announce new external address
                let current_address = server.external_address();
                writeln!(term, "current address: {}", DisplayAddr(current_address))?;
                let new_address = match prompt_address(&mut term)? {
                    PromptResult::Some(addr) => Some(addr),
                    PromptResult::None => None,
                    PromptResult::Abort => {
                        writeln!(term, "external address unchanged")?;
                        continue;
                    }
                };
                writeln!(
                    term,
                    "setting external address to {}",
                    DisplayAddr(new_address)
                )?;
                if let Err(err) = server.set_external_address(new_address) {
                    writeln!(term, "error while setting external address: {err}")?;
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
}

struct DisplayAddr(Option<Ipv4Addr>);

impl std::fmt::Display for DisplayAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(addr) => write!(f, "{addr}"),
            None => write!(f, "none"),
        }
    }
}

enum PromptResult<T> {
    Some(T),
    None,
    Abort,
}

fn prompt_address(term: &mut console::Term) -> std::io::Result<PromptResult<Ipv4Addr>> {
    loop {
        let prompt = "new external address > ";
        if let Some(new_address) = read_line_initial_text(term, prompt)? {
            let new_address = new_address.trim();
            if new_address.is_empty() {
                return Ok(PromptResult::None);
            } else if let Ok(new_address) = new_address.parse() {
                return Ok(PromptResult::Some(new_address));
            } else {
                term.write_line(&format!(
                    "unable to parse `{new_address}` as an IPv4 address; try again"
                ))?;
            }
        } else {
            return Ok(PromptResult::Abort);
        }
    }
}

pub fn read_line_initial_text(
    term: &console::Term,
    initial: &str,
) -> std::io::Result<Option<String>> {
    // adapted from `console::Term::read_line_initial_text`, additionally responding to
    // escape key as an "abort" option

    use console::Key;

    term.write_str(initial)?;
    let prefix_len = initial.len();
    let mut chars: Vec<char> = initial.chars().collect();
    loop {
        match term.read_key()? {
            Key::Backspace => {
                if prefix_len < chars.len() && chars.pop().is_some() {
                    term.clear_chars(1)?;
                }
                term.flush()?;
            }
            Key::Char(chr) => {
                chars.push(chr);
                let mut bytes_char = [0; 4];
                term.write_str(chr.encode_utf8(&mut bytes_char))?;
                term.flush()?;
            }
            Key::Enter => {
                term.write_str("\n")?;
                term.flush()?;
                break;
            }
            Key::Escape => {
                term.write_str("\n")?;
                term.flush()?;
                return Ok(None);
            }
            _ => (),
        }
    }
    Ok(Some(chars.iter().skip(prefix_len).collect::<String>()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_range_parsing() {
        let single_port = PortRange::new(1234, 1234);
        assert_eq!(parse_port_range("1234").unwrap(), single_port);
        assert_eq!(parse_port_range("1234-1234").unwrap(), single_port);

        assert_eq!(
            parse_port_range("1234-4567").unwrap(),
            PortRange::new(1234, 4567)
        );
        assert_eq!(parse_port_range("1-65535").unwrap(), PortRange::ALL_PORTS);

        assert!(parse_port_range("1234-").is_err());
        assert!(parse_port_range("-1234").is_err());
        assert!(parse_port_range("1234-x").is_err());
        assert!(parse_port_range("x-1234").is_err());
        assert!(parse_port_range("1234-4567-7890").is_err());
        assert!(parse_port_range("1234-1233").is_err());
        assert!(parse_port_range("0-0").is_err());
        assert!(parse_port_range("0-1000").is_err());
    }

    #[test]
    fn port_mapping_options() {
        assert_eq!(
            parse_port_mapping_options("1234:5678").unwrap(),
            PortMappingOptions::new(
                ProtocolOptions::Both,
                PortRange::new(1234, 1234),
                Some(5678)
            )
            .unwrap()
        );
        assert_eq!(
            parse_port_mapping_options("tcp/1234:5678").unwrap(),
            PortMappingOptions::new(ProtocolOptions::Tcp, PortRange::new(1234, 1234), Some(5678))
                .unwrap()
        );
        assert_eq!(
            parse_port_mapping_options("udp/1234:5678").unwrap(),
            PortMappingOptions::new(ProtocolOptions::Udp, PortRange::new(1234, 1234), Some(5678))
                .unwrap()
        );
        assert_eq!(
            parse_port_mapping_options("tcp/1234-1235:5678-5679").unwrap(),
            PortMappingOptions::new(ProtocolOptions::Tcp, PortRange::new(1234, 1235), Some(5678))
                .unwrap()
        );
        assert_eq!(
            parse_port_mapping_options("tcp/1234-1235:no").unwrap(),
            PortMappingOptions::new(ProtocolOptions::Tcp, PortRange::new(1234, 1235), None)
                .unwrap()
        );
        assert_eq!(
            parse_port_mapping_options("tcp/1234-1235:5678").unwrap_err(),
            ParsePortMappingOptionsError::MismatchedPortCount
        );
        assert_eq!(
            parse_port_mapping_options("tcp/1234-1235:5678-5680").unwrap_err(),
            ParsePortMappingOptionsError::MismatchedPortCount
        );
        assert_eq!(
            parse_port_mapping_options("tcp/1234-1233:5678").unwrap_err(),
            ParsePortMappingOptionsError::InvalidRange
        );
        assert!(matches!(
            parse_port_mapping_options("tcp/1234-1235:5678-5679-5680").unwrap_err(),
            ParsePortMappingOptionsError::InvalidPort(_)
        ));
    }
}
