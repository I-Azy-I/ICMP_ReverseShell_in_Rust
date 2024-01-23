# ICMP sniffer in Rust

This is a simple ICMP sniffer written in Rust. It will listen for ICMP packets and run a reverse shell if it receives a
packet with the correct payload.

## Usage

You can edit the configuration in the libs.rs file.

To compile the sniffer:

```bash
cargo build --release --bin sniffer
```

To comiple the ping forger:

```bash

cargo build --release --bin forger
```