//! Setowire - Chat example

use std::io::{self, BufRead, Write};
use std::sync::Arc;
use std::collections::HashMap;
use sha2::Digest;
use setowire::{Swarm, Peer};
use hex;

fn ts() -> String {
    chrono::Local::now().format("[%H:%M]").to_string()
}

// Cores ANSI
const RESET: &str = "\x1b[0m";
const GREEN: &str = "\x1b[32m";

const COLORS: [&str; 8] = [
    "\x1b[36m",  // cyan
    "\x1b[33m",  // yellow  
    "\x1b[35m",  // magenta
    "\x1b[34m",  // blue
    "\x1b[31m",  // red
    "\x1b[92m",  // bright green
    "\x1b[96m",  // bright cyan
    "\x1b[93m",  // bright yellow
];

fn color_nick(nick: &str) -> String {
    let hash: usize = nick.bytes().fold(0, |acc, b| acc.wrapping_add(b as usize));
    let color = COLORS[hash % COLORS.len()];
    format!("{}{}{}", color, nick, RESET)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let nick = args.get(1).cloned().unwrap_or_else(|| "anonymous".to_string());
    let room = args.get(2).cloned().unwrap_or_else(|| "general".to_string());

    println!("{} * starting... nick={} room={}", ts(), nick, room);

    // Override identity with SEED env var if set
    let mut swarm = if let Ok(seed) = std::env::var("SEED") {
        if let Ok(bytes) = hex::decode(&seed) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                println!("{} * using SEED identity", ts());
                Swarm::new_with_seed(arr).await
            } else {
                Swarm::new().await
            }
        } else {
            Swarm::new().await
        }
    } else {
        Swarm::new().await
    };

    println!("{} * ready | nat=unknown | addr=LAN", ts());

    // Join topic (same as JS: SHA256('chat:' + room))
    // The swarm.join() will compute SHA256 internally
    let topic = format!("chat:{}", &room);
    swarm.join(topic.as_bytes(), true, true);

    // Peer tracking: (peer_id -> nick)
    let peers_nicks = Arc::new(std::sync::Mutex::new(std::collections::HashMap::<String, String>::new()));

    let peers_conn = peers_nicks.clone();
    let peers_disc = peers_nicks.clone();
    let nick_data  = nick.clone();

    // Connection callback (don't print - wait for JOIN message with nick)
    swarm.on_connection(Arc::new(move |peer: &Peer| {
        peers_conn.lock().unwrap().insert(peer.id.clone(), String::new());
    }));

    // Disconnection callback - show nick if known, else ID
    swarm.on_disconnection(Arc::new(move |peer_id: &str| {
        let nick = peers_disc.lock().unwrap().remove(peer_id);
        match nick {
            Some(n) if !n.is_empty() => println!("{} * {} left", ts(), n),
            _ => {
                let peer_short = &peer_id[..8.min(peer_id.len())];
                println!("{} * {} left", ts(), peer_short);
            }
        }
    }));

    // Data callback
    swarm.on_data(Arc::new(move |data: &[u8], peer: &Peer| {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) {
            if let Some(msg_type) = json.get("type").and_then(|v| v.as_str()) {
                match msg_type {
                    "JOIN" => {
                        if let Some(nick) = json.get("nick").and_then(|v| v.as_str()) {
                            // Store nick for this peer
                            peers_nicks.lock().unwrap().insert(peer.id.clone(), nick.to_string());
                            println!("{} * {} joined", ts(), nick);
                        }
                    }
                    "MSG" => {
                        if let Some(nick) = json.get("nick").and_then(|v| v.as_str()) {
                            // Store/update nick
                            peers_nicks.lock().unwrap().insert(peer.id.clone(), nick.to_string());
                            if nick != nick_data {
                                if let Some(text) = json.get("text").and_then(|v| v.as_str()) {
                                    let colored = color_nick(nick);
                                    println!("{}: {}", colored, text);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }));

    // NAT callback - we'll get nat info after start
    swarm.on_nat(Arc::new(move || {
        // We'll print from the main loop
    }));

    // Start swarm after registering callbacks
    swarm.start().await;

    // Wait for LAN discovery and get actual values
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    let local_addr = swarm.local_address();
    let nat_type = swarm.nat_type();
    let my_id = swarm.id().to_string();
    println!("{} * nat={} addr={}", ts(), nat_type, local_addr);
    println!("{} * commands: /peers  /nat  /quit", ts());

    // Use Arc for swarm access from multiple tasks
    let swarm_arc = Arc::new(swarm);

    // Periodic task: send JOIN to all connected peers - starts immediately
    let swarm_for_join = swarm_arc.clone();
    let nick_for_join = nick.clone();
    let my_id_clone = my_id.clone();
    tokio::spawn(async move {
        // Send immediately on start
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        loop {
            let peers = swarm_for_join.list_peers().await;
            if peers.is_empty() { 
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                continue;
            }
            let join_msg = serde_json::json!({
                "type": "JOIN",
                "nick": nick_for_join,
                "_selfId": my_id_clone
            });
            for (pid, _addr, _rtt, _connected) in peers {
                let _ = swarm_for_join.send_to(&pid, join_msg.to_string().as_bytes()).await;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        }
    });

    // Input loop (separate thread to not block runtime)
    let nick_loop = nick.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    let swarm_input = swarm_arc.clone();
    let my_id_for_input = my_id.clone();

    std::thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) => { let _ = tx.blocking_send(l); }
                Err(_) => break,
            }
        }
    });

    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let line = match rx.recv().await {
            Some(l) => l,
            None    => break,
        };
        let line = line.trim().to_string();
        if line.is_empty() { continue; }

        match line.as_str() {
            "/peers" => {
                let now = chrono::Local::now();
                let peers = swarm_input.list_peers().await;
                println!("[{}] * {} peer(s) connected", now.format("%H:%M"), peers.len());
                for (id, _addr, rtt, connected) in peers {
                    let status = if connected { "mesh=true" } else { "mesh=false" };
                    println!("[{}] *   {} rtt={:.0}ms {}", 
                        now.format("%H:%M"), 
                        &id[..8.min(id.len())], 
                        rtt, 
                        status
                    );
                }
            }
            "/nat" => {
                println!("{} * nat={} addr={}", ts(), swarm_input.nat_type(), swarm_input.local_address());
            }
            s if s.starts_with("/dial ") => {
                let parts: Vec<&str> = s.split(' ').collect();
                if parts.len() >= 3 {
                    let ip = parts[1];
                    let port: u16 = parts[2].parse().unwrap_or(0);
                    if port > 0 {
                        swarm_input.dial(ip, port).await;
                        println!("{} * dialing {}:{}", ts(), ip, port);
                    } else {
                        println!("{} * invalid port", ts());
                    }
                } else {
                    println!("{} * usage: /dial <ip> <port>", ts());
                }
            }
            "/quit" | "/exit" => {
                println!("{} * goodbye!", ts());
                break;
            }
            _ => {
                // Envia no mesmo formato JSON que o JS espera
                let msg = serde_json::json!({
                    "type": "MSG",
                    "nick": nick_loop,
                    "text": line,
                    "_selfId": my_id_for_input
                });
                let sent = swarm_input.broadcast(msg.to_string().as_bytes());
                // Eco local colorido
                println!("\x1b[32mvoce\x1b[0m: {}", line);
                if sent == 0 {
                    println!("{} * no peers connected yet", ts());
                }
            }
        }
    }

    // Try to get ownership for destroy, otherwise just let it drop
    if let Ok(mut swarm) = Arc::try_unwrap(swarm_arc) {
        swarm.destroy().await;
    }
    Ok(())
}