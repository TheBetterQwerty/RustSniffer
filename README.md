# Packet Sniffer

A simple packet sniffing program written in rust that captures and displays IP packets on a specified network interface. This program utilizes the `pnet` crate to capture live network traffic.

## Features

- Capture IP packets from a specified network interface.
- Display source and destination IP addresses for each captured packet.
- Support for promiscuous mode.
- User-friendly interface for selecting network devices.

## Requirements

- Cargo package manager

## Installation

1. **Compile Sniffer**
   ```bash
   cargo build
   ```
2. **Run Sniffer**
   ```bash
   cargo run -q 
   ```
