//! Setowire - Chat example
//!
//! A simple terminal chat application using Setowire P2P networking.

use std::io::{self, BufRead, Write};
use sha2::Digest;
use setowire::{Swarm, Peer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    
    let nick = args.get(1).cloned().unwrap_or_else(|| "anonymous".to_string());
    let room = args.get(2).cloned().unwrap_or_else(|| "default".to_string());
    
    println!("╔════════════════════════════════════════╗");
    println!("║         Setowire Chat v0.1.1            ║");
    println!("╠════════════════════════════════════════╣");
    println!("║  Nick: {:<30}║", &nick);
    println!("║  Room: {:<30}║", &room);
    println!("╚════════════════════════════════════════╝");
    println!("Connecting to network...");
    
    // Create swarm
    let mut swarm = Swarm::new().await;
    
    // Join topic (room)
    let topic = sha2::Sha256::digest(&room);
    swarm.join(&topic[..], true, true);
    
    // Track peers
    let peers = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let peers_for_conn = peers.clone();
    let peers_for_disconn = peers.clone();
    
    // Handle new connections
    swarm.on_connection(Box::new(move |peer: &Peer| {
        println!("🔗 Peer connected: {} ({} peers total)", 
                 &peer.id[..8], peers_for_conn.lock().unwrap().len() + 1);
        peers_for_conn.lock().unwrap().push(peer.id.clone());
    }));
    
    // Handle disconnections
    swarm.on_disconnection(Box::new(move |peer_id: &str| {
        println!("🔌 Peer disconnected: {}", &peer_id[..8]);
        peers_for_disconn.lock().unwrap().retain(|p| p != peer_id);
    }));
    
    // Handle incoming messages
    let nick_for_data = nick.clone();
    swarm.on_data(Box::new(move |data: &[u8], _peer: &Peer| {
        if let Ok(msg) = String::from_utf8(data.to_vec()) {
            if let Some((nick_part, msg_part)) = msg.split_once(':') {
                if nick_part != nick_for_data {
                    println!("[{}] {}", nick_part, msg_part.trim());
                }
            }
        }
    }));
    
    // Wait for NAT discovery
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    
    println!("\n📡 Connected! Type messages to broadcast.\n");
    println!("Commands: /peers, /quit\n");
    
    // Input loop
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let nick_loop = nick.clone();
    
    loop {
        print!("[{}] ", nick_loop);
        io::stdout().flush()?;
        
        if let Some(Ok(line)) = lines.next() {
            let line = line.trim();
            
            if line.is_empty() {
                continue;
            }
            
            match line {
                "/peers" => {
                    let count = swarm.peer_count();
                    println!("👥 Connected peers: {}", count);
                }
                "/nat" => {
                    println!("🌐 NAT type: {}", swarm.nat_type());
                    if let Some(addr) = swarm.public_addr() {
                        println!("📍 Public address: {}", addr);
                    }
                }
                "/quit" | "/exit" => {
                    println!("👋 Goodbye!");
                    break;
                }
                _ => {
                    // Broadcast message
                    let msg = format!("{}: {}", nick_loop, line);
                    swarm.broadcast(msg.as_bytes());
                }
            }
        }
    }
    
    swarm.destroy().await;
    Ok(())
}