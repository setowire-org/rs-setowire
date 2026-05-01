//! Setowire - Chat example

use std::io::{self, BufRead, Write};
use std::sync::Arc;
use sha2::Digest;
use setowire::{Swarm, Peer};

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

    let mut swarm = Swarm::new().await;
    println!("{} * ready | nat=unknown | addr=LAN", ts());

    // Join topic
    let topic = sha2::Sha256::digest(&room);
    swarm.join(&topic[..], true, true);

    // Peer tracking
    let peers_list = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    let peers_conn = peers_list.clone();
    let peers_disc = peers_list.clone();
    let nick_data  = nick.clone();

    // Connection callback
    swarm.on_connection(Arc::new(move |peer: &Peer| {
        let peer_short = &peer.id[..8.min(peer.id.len())];
        println!("{} * {} joined", ts(), peer_short);
        peers_conn.lock().unwrap().push(peer.id.clone());
    }));

    // Disconnection callback
    swarm.on_disconnection(Arc::new(move |peer_id: &str| {
        let peer_short = &peer_id[..8.min(peer_id.len())];
        println!("{} * {} left", ts(), peer_short);
        peers_disc.lock().unwrap().retain(|p| p != peer_id);
    }));

    // Data callback
    swarm.on_data(Arc::new(move |data: &[u8], _peer: &Peer| {
        if let Ok(msg) = std::str::from_utf8(data) {
            if let Some((from_nick, text)) = msg.split_once(':') {
                if from_nick != nick_data {
                    let colored = color_nick(from_nick);
                    println!("{}: {}", colored, text.trim());
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
    let local_addr = swarm.local_addr();
    let nat_type = swarm.nat_type();
    println!("{} * nat={} addr={}", ts(), nat_type, local_addr);
    println!("{} * commands: /peers  /nat  /quit", ts());

    // Input loop (separate thread to not block runtime)
    let nick_loop = nick.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);

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
                let peers = swarm.list_peers().await;
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
                println!("{} * nat={} addr={}", ts(), swarm.nat_type(), swarm.local_addr());
            }
            "/quit" | "/exit" => {
                println!("{} * goodbye!", ts());
                break;
            }
            _ => {
                // Remove "nick: " prefixo se o usuário digitar (ex: "bob: olá")
                let text = if line.contains(": ") && !line.starts_with(':') {
                    line.split(": ").nth(1).unwrap_or(&line).trim()
                } else {
                    &line
                };
                // Envia como "nick: mensagem" para o receptor saber quem enviou
                let msg = format!("{}: {}", nick_loop, text);
                let sent = swarm.broadcast(msg.as_bytes());
                // Eco local colorido
                println!("\x1b[32mvoce\x1b[0m: {}", text);
                if sent == 0 {
                    println!("{} * no peers connected yet", ts());
                }
            }
        }
    }

    swarm.destroy().await;
    Ok(())
}