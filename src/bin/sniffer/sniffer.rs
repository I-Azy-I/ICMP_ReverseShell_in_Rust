use std::net::IpAddr;
use std::thread;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes, MutableEthernetPacket};
use pnet::packet::icmp::{echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;

use icmp_rust::{IDENTIFIER, OBFUSCATION_KEY, VALIDATION_BYTES};

use crate::DEBUG;

fn print_debug(value: String) {
    if DEBUG {
        println!("{}", value)
    }
}

fn clear_xor(data: &[u8], key: Vec<u8>) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(data.len());
    for (i, el) in data.iter().enumerate() {
        plaintext.push(el ^ key[i % key.len()]);
    }
    plaintext
}

fn valid_icmp_detected(payload: Vec<u8>, f: fn(Vec<u8>)) {
    f(payload);
}

fn detect_specific_icmp(icmp_packet: EchoRequestPacket, obfuscated: bool, key: Option<Vec<u8>>, fn_detection: fn(Vec<u8>)) {
    print_debug(format!("ICMP received with value: "));
    print_debug(format!("  - identifier: {}", icmp_packet.get_identifier()));
    print_debug(format!("  - sequence: {}", icmp_packet.get_sequence_number()));
    print_debug(format!("  - checksum: {}", icmp_packet.get_checksum()));
    print_debug(format!("  - payload len: {}", icmp_packet.payload().len()));
    print_debug(format!("  - payload: {:?}", icmp_packet.payload()));


    let identifier = icmp_packet.get_identifier();
    if !identifier.eq(&IDENTIFIER) {
        print_debug(format!(
            "Not the good sequence: {} instead of {}",
            identifier, IDENTIFIER
        ));
        return;
    }
    let key = key.unwrap_or_else(|| OBFUSCATION_KEY.to_vec());
    let obfuscated_payload = icmp_packet.payload();
    let _tmp_vec_payload: Vec<u8>;
    let payload =
        if obfuscated {
            clear_xor(obfuscated_payload, key.clone())
        } else {
            obfuscated_payload.to_vec()
        };
    print_debug(format!("  - payload_cleared: {:?}", payload));
    if VALIDATION_BYTES.len() > payload.len() {
        print_debug(format!("Doesn't start with validation bytes"));
        return;
    }
    for (byte_key, byte_payload) in VALIDATION_BYTES.iter().zip(payload.iter()) {
        print_debug(format!("{} {}", byte_key, byte_payload));
        if byte_key != byte_payload {
            print_debug(format!("Doesn't start with the key"));
            return;
        }
    }
    valid_icmp_detected(payload, fn_detection);
    print_debug(format!("ICMP detected"));
}

fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8], obfuscated: bool, key: Option<Vec<u8>>, fn_detection: fn(Vec<u8>)) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => (),
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                print_debug(format!(
                    "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                ));
                detect_specific_icmp(echo_request_packet, obfuscated, key, fn_detection);
            }
            _ => print_debug(format!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmp_packet.get_icmp_type()
            )),
        }
    } else {
        print_debug(format!("[{}]: Malformed ICMP Packet", interface_name));
    }
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    obfuscated: bool,
    key: Option<Vec<u8>>,
    fn_detection: fn(Vec<u8>),
) {
    match protocol {
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(interface_name, source, destination, packet, obfuscated, key, fn_detection)
        }
        _ => (),
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket, obfuscated: bool, key: Option<Vec<u8>>, fn_detection: fn(Vec<u8>)) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            obfuscated,
            key,
            fn_detection,
        );
    } else {
        print_debug(format!("[{}]: Malformed IPv4 Packet", interface_name));
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket, obfuscated: bool, key: Option<Vec<u8>>, fn_detection: fn(Vec<u8>)) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
            obfuscated,
            key,
            fn_detection,
        );
    } else {
        print_debug(format!("[{}]: Malformed IPv6 Packet", interface_name));
    }
}

fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket, obfuscated: bool, key: Option<Vec<u8>>, fn_detection: fn(Vec<u8>)) {
    let interface_name = &interface.name[..];
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet, obfuscated, key, fn_detection),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet, obfuscated, key, fn_detection),
        _ => (),
    }
}

fn find_interface_by_name(iface_name: String) -> Option<NetworkInterface> {
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;
    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    interfaces.into_iter()
        .filter(interface_names_match)
        .next()
}

fn sniff_interface(interface: NetworkInterface, obfuscated: bool, key: Option<Vec<u8>>, fn_detection: fn(Vec<u8>)) {
    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    loop {
        let mut buf: [u8; 1600] = [0u8; 1600];
        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        match rx.next() {
            Ok(packet) => {
                let payload_offset;
                if cfg!(any(target_os = "macos", target_os = "ios"))
                    && interface.is_up()
                    && !interface.is_broadcast()
                    && ((!interface.is_loopback() && interface.is_point_to_point())
                    || interface.is_loopback())
                {
                    if interface.is_loopback() {
                        // The pnet code for BPF loopback adds a zero'd out Ethernet header
                        payload_offset = 14;
                    } else {
                        // Maybe is TUN interface
                        payload_offset = 0;
                    }
                    if packet.len() > payload_offset {
                        let version = Ipv4Packet::new(&packet[payload_offset..])
                            .unwrap()
                            .get_version();
                        if version == 4 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable(), obfuscated, key.clone(), fn_detection);
                            continue;
                        } else if version == 6 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable(), obfuscated, key.clone(), fn_detection);
                            continue;
                        }
                    }
                }
                handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap(), obfuscated, key.clone(), fn_detection);
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}

pub fn sniff(obfuscated: bool, key: Option<Vec<u8>>, specific_interface: Option<&str>, fn_detection: fn(Vec<u8>)) {
    let mut handles = vec![];
    let interfaces = datalink::interfaces();
    match specific_interface {
        Some(interface_name) => {
            let interface = find_interface_by_name(interface_name.to_string()).expect("interface not found");
            let handle = thread::spawn(move || {
                sniff_interface(interface, obfuscated, key, fn_detection);
            });
            handles.push(handle);
        }
        None => {
            for interface in interfaces {
                let copy_key = key.clone();
                print_debug(format!("listening to interface: {}", interface.name));
                let handle = thread::spawn(move || {
                    sniff_interface(interface, obfuscated, copy_key, fn_detection);
                });
                handles.push(handle);
            }
            for handle in handles {
                handle.join().unwrap();
            }
        }
    }
}
