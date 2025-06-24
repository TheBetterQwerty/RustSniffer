use std::io::{self, Write};
use pcap::Device;
use pnet::{
        datalink::{self, Channel},
        packet::{
            ethernet::{EthernetPacket, EtherTypes},
            ipv4::Ipv4Packet,
            Packet,
    },
};
use std::net::Ipv4Addr;

fn main() {
    let dev = select_dev();
    let interface = datalink::interfaces()
        .into_iter()
        .find(|x| x.name == dev.as_str())
        .expect("Device not found!");

    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Root privilage is needed!"),
    };
    
    println!("Sniffing with {}...", dev);
    while let Ok(packet) = rx.next() {
        let eth_packet = EthernetPacket::new(packet).expect("Failed to parse Ethernet!");
        if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
            let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).expect("Failed to parse IPv4 packet");
            let source_ip = Ipv4Addr::from(ipv4_packet.get_source());
            let dest_ip = Ipv4Addr::from(ipv4_packet.get_destination());
            println!("[#] Packet Captured\tSource IP: {}\tDestination IP: {}", source_ip, dest_ip);
        }
    }
}

fn select_dev() -> String {
    let devs = Device::list()
        .unwrap_or_else(|_| panic!("No devices were found!"));
    
    println!("[$] Available devices");
    for (idx, dev) in devs.iter().enumerate() {
        print!("{}. {} ", idx + 1, dev.name);
        if let Some(desc) = dev.desc.clone() {
            println!("({})", desc);
            continue;
        }
        println!("(No description)");
    }
    
    let mut input = String::new();
    print!("[*] Enter a device: ");
    let _ = io::stdout().flush();
    io::stdin().read_line(&mut input).expect("[!] Error reading line!");
    let input: usize = input.trim().parse().expect("[!] Error parsing input!");
    
    if input > devs.len() || input <= 0 {
        println!("[!] Not a valid choice!");
        panic!();
    }

    if let Some(dev) = devs.get(input - 1) {
        return dev.name.clone();
    }

    panic!("[!] Error choosing index");   
}

