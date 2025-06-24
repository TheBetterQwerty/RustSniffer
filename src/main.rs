use std::io::{self, Write};
use pnet::{
        datalink::{self, Channel, NetworkInterface},
        packet::{
            ethernet::{EthernetPacket, EtherTypes},
            ipv4::Ipv4Packet,
            Packet, ip::IpNextHeaderProtocol
    },
};
use std::net::Ipv4Addr;

struct PacketInfo {
    version: u8,
    header_len: u8,
    len: u16,
    identification: u16,
    flag: u8,
    offset: u16,
    ttl: u8,
    protocol: IpNextHeaderProtocol,
    checksum: u16,
    source: Ipv4Addr,
    destination: Ipv4Addr,
}

fn main() {
    let interface = match select_dev() {
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
            let mypacket: PacketInfo = PacketInfo {
                version: ipv4_packet.get_version(),
                header_len: ipv4_packet.get_header_length() * 4,
                len: ipv4_packet.get_total_length(),
                identification: ipv4_packet.get_identification(),
                flag: ipv4_packet.get_flags(),
                offset: ipv4_packet.get_fragment_offset(),
                ttl: ipv4_packet.get_ttl(),
                protocol: ipv4_packet.get_next_level_protocol(),
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
    println!("│ Protocol:          {:<20} │", format!("{}", pkt.protocol).to_uppercase());
    println!("│ Header checksum:   {:<20} │", format!("0x{:04X}", pkt.checksum).to_lowercase()); 
    println!("│ Source:            {:<20} │", pkt.source);
    println!("│ Destination:       {:<20} │", pkt.destination);
    println!("└─────────────────────────────────────────┘");
}

fn select_dev() -> Option<NetworkInterface> {
    let devs = datalink::interfaces();
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

