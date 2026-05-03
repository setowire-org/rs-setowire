//! Setowire - Chat example

use std::io::{self, BufRead, Write};
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use setowire::{Swarm, Peer};

fn ts() -> String {
    chrono::Local::now().format("[%H:%M]").to_string()
}

// ANSI colors
const RESET: &str = "\x1b[0m";
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
    let topic = format!("chat:{}", &room);
    swarm.join(topic.as_bytes(), true, true).await;   // async

    // Peer tracking
    let known_peers = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let peers_nicks = Arc::new(std::sync::Mutex::new(HashMap::<String, String>::new()));
    let seen_self_ids = Arc::new(std::sync::Mutex::new(HashSet::<String>::new()));

    let known_peers_conn = known_peers.clone();
    let known_peers_disc = known_peers.clone();
    let peers_nicks_disconnect = peers_nicks.clone();
    let peers_nicks_data = peers_nicks.clone();
    let seen_self_ids_data = seen_self_ids.clone();
    let nick_data = nick.clone();

    // Connection callback – agora evita duplicatas
    swarm.on_connection(Arc::new(move |peer: &Peer| {
        let mut kp = known_peers_conn.lock().unwrap();
        if !kp.contains(&peer.id) {
            kp.push(peer.id.clone());
        }
    }));

    // Disconnection callback – Arc
    swarm.on_disconnection(Arc::new(move |peer_id: &str| {
        known_peers_disc.lock().unwrap().retain(|id| id != peer_id);
        let nick = peers_nicks_disconnect.lock().unwrap().remove(peer_id);
        match nick {
            Some(n) if !n.is_empty() => println!("{} * {} left", ts(), n),
            _ => {
                let peer_short = &peer_id[..8.min(peer_id.len())];
                println!("{} * {} left", ts(), peer_short);
            }
        }
    }));

    // Data callback – Arc
    swarm.on_data(Arc::new(move |data: &[u8], peer: &Peer| {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) {
            if let Some(msg_type) = json.get("type").and_then(|v| v.as_str()) {
                match msg_type {
                    "JOIN" => {
                        if let Some(nick) = json.get("nick").and_then(|v| v.as_str()) {
                            // prefer `_selfId` para identidade persistente; fallback para peer.id
                            let self_id = json.get("_selfId").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| peer.id.clone());

                            // atualiza mapa de nicks (mantém peer-id também)
                            peers_nicks_data.lock().unwrap().insert(peer.id.clone(), nick.to_string());

                            // dedup por `_selfId`
                            let mut seen = seen_self_ids_data.lock().unwrap();
                            if !seen.contains(&self_id) {
                                seen.insert(self_id.clone());
                                println!("{} * {} joined", ts(), nick);
                            }
                        }
                    }
                    "MSG" => {
                        if let Some(nick) = json.get("nick").and_then(|v| v.as_str()) {
                            peers_nicks_data.lock().unwrap().insert(peer.id.clone(), nick.to_string());
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

    // Start swarm
    swarm.start().await;

    // Wait a bit and print status
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    let external = swarm.external_addr().await;
    let local_addr = external.unwrap_or_else(|| swarm.local_addr());
    let _nat_type = swarm.nat_type();
    let my_id = swarm.id().to_string();
    println!("{} * nat={} addr={}", ts(), swarm.nat_type(), local_addr);
    println!("{} * commands: /peers  /nat  /quit", ts());

    let swarm_arc = Arc::new(swarm);
    let joined_peers = Arc::new(std::sync::Mutex::new(HashSet::<String>::new()));

    // Periodic JOIN sender
    let swarm_for_join = swarm_arc.clone();
    let known_peers_join = known_peers.clone();
    let joined_peers_clone = joined_peers.clone();
    let nick_for_join = nick.clone();
    let my_id_clone = my_id.clone();

    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        loop {
            let targets = known_peers_join.lock().unwrap().clone();
            if !targets.is_empty() {
                let join_msg = serde_json::json!({
                    "type": "JOIN",
                    "nick": nick_for_join,
                    "_selfId": my_id_clone
                });
                let join_bytes = join_msg.to_string().into_bytes();
                for pid in &targets {
                    let already_sent = {
                        let mut joined = joined_peers_clone.lock().unwrap();
                        if joined.contains(pid) {
                            true
                        } else {
                            joined.insert(pid.clone());
                            false
                        }
                    };
                    if !already_sent {
                        let _ = swarm_for_join.send_to(pid, &join_bytes).await;
                    }
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        }
    });

    // Input loop
    let nick_loop = nick.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    let swarm_input = swarm_arc.clone();
    let my_id_for_input = my_id.clone();
    let known_peers_input = known_peers.clone();
    let peers_nicks_input = peers_nicks.clone();

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
                let peers_list = known_peers_input.lock().unwrap().clone();
                println!("[{}] * {} peer(s) connected", now.format("%H:%M"), peers_list.len());
                let nicks = peers_nicks_input.lock().unwrap();
                for pid in &peers_list {
                    let nick = nicks.get(pid).cloned().unwrap_or_default();
                    let display = if nick.is_empty() {
                        format!("{}", &pid[..8.min(pid.len())])
                    } else {
                        nick
                    };
                    println!("[{}] *   {}", now.format("%H:%M"), display);
                }
            }
            "/nat" => {
                let addr = swarm_input.external_addr().await.unwrap_or_else(|| swarm_input.local_addr());
                println!("{} * nat={} addr={}", ts(), swarm_input.nat_type(), addr);
            }
            "/quit" | "/exit" => {
                println!("{} * goodbye!", ts());
                break;
            }
            _ => {
                let msg = serde_json::json!({
                    "type": "MSG",
                    "nick": nick_loop,
                    "text": line,
                    "_selfId": my_id_for_input
                });
                let sent = swarm_input.broadcast(msg.to_string().as_bytes()).await;
                println!("\x1b[32myou\x1b[0m: {}", line);
                if sent == 0 {
                    println!("{} * no peers connected yet", ts());
                }
            }
        }
    }

    if let Ok(mut swarm) = Arc::try_unwrap(swarm_arc) {
        swarm.destroy().await;
    }
    Ok(())
}

//on00dev