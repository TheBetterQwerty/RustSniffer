/* Imports */
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::env::args;
use pnet::{
    datalink::{self, Channel, NetworkInterface},
    packet::{
        ethernet::{EthernetPacket, EtherTypes},
        ipv4::Ipv4Packet, Packet
    },
};

struct PacketInfo {
    version: u8,
    header_len: u8,
    len: u16,
    identification: u16,
    flag: u8,
    offset: u16,
    ttl: u8,
    protocol: String,
    checksum: u16,
    source: Ipv4Addr,
    destination: Ipv4Addr,
}

fn main() {
    let argv = argparse();
    if let Some(_) = argv.get("exit") {
        return;
    }
    
    let s_dev = argv.get("-i");

    let interface = match select_dev(s_dev.cloned()) {
        Some(x) => x,
        None => {
            println!("[!] Index doesn't exists!");
            return;
        }
    };

    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => {
            println!("[!] Please run this script with root privilages!");
            return;
        }
    };
    

    println!("Sniffing with {}...", interface.name);
    while let Ok(packet) = rx.next() {
        let eth_packet = EthernetPacket::new(packet).expect("Failed to parse Ethernet!");
        if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
            let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).expect("Failed to parse IPv4 packet");
            let protocol = format!("{}", ipv4_packet.get_next_level_protocol());
            if let Some(x) = argv.get("-p") {
                if !protocol.eq_ignore_ascii_case(x) {
                    continue;
                }
            }

            let mypacket: PacketInfo = PacketInfo {
                version: ipv4_packet.get_version(),
                header_len: ipv4_packet.get_header_length() * 4,
                len: ipv4_packet.get_total_length(),
                identification: ipv4_packet.get_identification(),
                flag: ipv4_packet.get_flags(),
                offset: ipv4_packet.get_fragment_offset(),
                ttl: ipv4_packet.get_ttl(),
                protocol: protocol.to_uppercase(),
                checksum: ipv4_packet.get_checksum(),
                source: Ipv4Addr::from(ipv4_packet.get_source()),
                destination: Ipv4Addr::from(ipv4_packet.get_destination()),
            };
            pretty_print(mypacket);
        }
    }
}

fn pretty_print(pkt: PacketInfo) {
    println!("[PACKET]");
    println!("┌─────────────────────────────────────────┐");
    println!("│ Version:           {:<20} │", pkt.version);
    println!("│ Header Length:     {:<20} │", pkt.header_len);
    println!("│ Total Length:      {:<20} │", pkt.len);
    println!("│ Identification:    {:<20} │", format!("0x{:04X}", pkt.identification).to_lowercase());
    println!("│ Flags:             {:<20} │", pkt.flag);
    println!("│ Fragment Offset:   {:<20} │", pkt.offset);
    println!("│ Time to Live:      {:<20} │", pkt.ttl);
    println!("│ Protocol:          {:<20} │", pkt.protocol);
    println!("│ Header checksum:   {:<20} │", format!("0x{:04X}", pkt.checksum).to_lowercase()); 
    println!("│ Source:            {:<20} │", pkt.source);
    println!("│ Destination:       {:<20} │", pkt.destination);
    println!("└─────────────────────────────────────────┘");
}

/* Selects a device */
fn select_dev(opt_s_dev: Option<String>) -> Option<NetworkInterface> {
    let devs = datalink::interfaces();

    if let Some(s_dev) = opt_s_dev {
        return devs.iter().find(|x| (**x).name == s_dev).cloned();
    }
    
    println!("[$] Available devices: ");

    for (idx, dev) in devs.iter().enumerate() {
        print!("{}. {} ", idx + 1, dev.name);
        if !dev.description.is_empty() {
            println!("{}", dev.description);
            continue;
        }
        println!("(No description)");
    }
    
    let mut input = String::new();
    print!("[*] Enter a device index: ");
    let _ = io::stdout()
        .flush();

    io::stdin()
        .read_line(&mut input)
        .expect("[!] Error reading line!");

    let input: usize = input
        .trim()
        .parse()
        .expect("[!] Error parsing input!");

    devs.get(input - 1).cloned()
}

/* Argparser */
fn argparse() -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    let mut argv = args();
    let prog_name = argv.next().unwrap_or("prog".to_string()); // skips the first argument (i.e, program name)

    match argv.next().as_deref() {
        Some("-i") | Some("--interface") => {
            match argv.next() {
                Some(interface) => { map.insert("-i".to_string(), interface); },
                None => { println!("[?] Missing argument for '{}'. Try '{} --help' for more info", "--interface", prog_name); }
            }
        },
        
        Some("-p") | Some("--protocol") => {
            match argv.next() {
                Some(protocol) => { map.insert("-p".to_string(), protocol); },
                None => { println!("[?] Missing argument for '{}'. Try '{} --help' for more info", "--protocol", prog_name); }
            }
        },

        Some("-h") | Some("--help") => {
            println!("\nUsage: {} [OPTIONS]\n", prog_name);
            println!("Options:");
            println!("  -i, --interface <interface>    Specify the network interface");
            println!("  -p, --protocol <protocol>      Specify the protocol (e.g., tcp, udp)");
            println!("  -h, --help                     Show this help message\n");
            map.insert("exit".to_string(), "1".to_string());
        },

        Some(argv) => {
            println!("[?] Invalid argument '{}'. Try '{} --help' for more info", argv, prog_name);
            map.insert("exit".to_string(), "1".to_string());
        },

        None => {}
    }

    map
}
