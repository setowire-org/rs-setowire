//! Setowire - Chat example

use std::io::{self, BufRead, Write};
use sha2::Digest;
use setowire::{Swarm, Peer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    
    let nick = args.get(1).cloned().unwrap_or_else(|| "anonymous".to_string());
    let room = args.get(2).cloned().unwrap_or_else(|| "general".to_string());
    
    println!("[*] starting... nick={} room={}", nick, room);
    
    // Create swarm
    let mut swarm = Swarm::new().await;
    println!("[*] ready | nat={} | addr=LAN", swarm.nat_type());
    
    // Join topic (room)
    let topic = sha2::Sha256::digest(&room);
    swarm.join(&topic[..], true, true);
    
    // Start the swarm (receive loop)
    swarm.start().await;
    
    // Wait a bit for connections
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    let local_addr = swarm.local_addr();
    println!("[*] nat={} addr={}", swarm.nat_type(), local_addr);
    
    // Track peers
    let peers = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let peers_for_conn = peers.clone();
    let peers_for_disconn = peers.clone();
    let peers_for_data = peers.clone();
    let nick_for_data = nick.clone();
    
    // Handle new connections
    swarm.on_connection(Box::new(move |peer: &Peer| {
        println!("[*] {} connected", &peer.id[..8]);
        peers_for_conn.lock().unwrap().push(peer.id.clone());
    }));
    
    // Handle disconnections
    swarm.on_disconnection(Box::new(move |peer_id: &str| {
        println!("[*] {} disconnected", &peer_id[..8]);
        peers_for_disconn.lock().unwrap().retain(|p| p != peer_id);
    }));
    
    // Handle incoming messages
    swarm.on_data(Box::new(move |data: &[u8], _peer: &Peer| {
        if let Ok(msg) = String::from_utf8(data.to_vec()) {
            if let Some((nick_part, msg_part)) = msg.split_once(':') {
                if nick_part != nick_for_data {
                    println!("{}: {}", nick_part, msg_part.trim());
                }
            }
        }
    }));
    
    // Handle NAT discovery
    swarm.on_nat(Box::new(|| {
        println!("[*] nat discovered");
    }));
    
    println!("[*] commands: /peers /nat /quit");
    
    // Input loop
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let nick_loop = nick.clone();
    
    loop {
        print!("{} > ", nick_loop);
        io::stdout().flush()?;
        
        if let Some(Ok(line)) = lines.next() {
            let line = line.trim();
            
            if line.is_empty() {
                continue;
            }
            
            match line {
                "/peers" => {
                    let count = peers.lock().unwrap().len();
                    println!("[*] {} peer(s) connected", count);
                    for p in peers.lock().unwrap().iter() {
                        println!("[*]   {} nick=? rtt=?ms mesh=true", &p[..8]);
                    }
                }
                "/nat" => {
                    println!("[*] nat={} addr={}", swarm.nat_type(), swarm.local_addr());
                }
                "/quit" | "/exit" => {
                    println!("[*] goodbye!");
                    break;
                }
                _ => {
                    // Broadcast message
                    let msg = format!("{}: {}", nick_loop, line);
                    swarm.broadcast(msg.as_bytes());
                    //println!("{}: {}", nick_loop, line);
                }
            }
        }
    }
    
    swarm.destroy().await;
    Ok(())
}