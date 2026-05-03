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

// Cor para mensagens do próprio usuário (verde)
const COLOR_SELF: &str = "\x1b[32m";
// Cor para mensagens do sistema (cinza)
const COLOR_SYS: &str = "\x1b[90m";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let nick = args.get(1).cloned().unwrap_or_else(|| "anonymous".to_string());
    let room = args.get(2).cloned().unwrap_or_else(|| "general".to_string());

    println!("{}{} * starting... nick={} room={}{}", COLOR_SYS, ts(), nick, room, RESET);

    let mut swarm = Swarm::new().await;
    let my_id = swarm.id().to_string();
    let my_id_arc = Arc::new(my_id.clone());
    println!("{}{} * ready | nat=unknown | addr=LAN{}", COLOR_SYS, ts(), RESET);

    // Join topic
    let topic = format!("chat:{}", &room);
    swarm.join(topic.as_bytes(), true, true).await;

    // Peer tracking - simplificado como no JS
    let peers_nicks = Arc::new(std::sync::Mutex::new(HashMap::<String, String>::new()));
    let handshook = Arc::new(std::sync::Mutex::new(HashSet::<String>::new()));
    let nick_for_callback = Arc::new(nick.clone());

    let peers_nicks_disconnect = peers_nicks.clone();
    let peers_nicks_data = peers_nicks.clone();
    let handshook_data = handshook.clone();
    let nick_for_callback_data = nick_for_callback.clone();

    // Connection callback - não pode escrever (peer.write precisa de &mut)
    // Vamos enviar nosso JOIN quando conectarmos em vez de no callback
    swarm.on_connection(Arc::new(move |_peer: &Peer| {
        // Não podemos escrever aqui - &mut necessário para peer.write()
    }));

    // Disconnection callback - "disconnected" como no JS
    swarm.on_disconnection(Arc::new(move |peer_id: &str| {
        let peer_nick = peers_nicks_disconnect.lock().unwrap().remove(peer_id);
        handshook.lock().unwrap().remove(peer_id);
        // Usa clearLine + prompt como no JS
        print!("\r\x1b[2K");
        match peer_nick {
            Some(n) if !n.is_empty() => println!("{}{} * {} disconnected{}", COLOR_SYS, ts(), n, RESET),
            _ => {
                let peer_short = &peer_id[..8.min(peer_id.len())];
                println!("{}{} * {} disconnected{}", COLOR_SYS, ts(), peer_short, RESET);
            }
        }
    }));

    // Data callback - simplificado como no JS (usa _selfId para filtrar mensagens próprias)
    swarm.on_data(Arc::new(move |data: &[u8], peer: &Peer| {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) {
            // Ignora mensagens próprias como no JS
            if let Some(self_id) = json.get("_selfId").and_then(|v| v.as_str()) {
                if self_id == my_id_arc.as_str() {
                    return;
                }
            }

            if let Some(msg_type) = json.get("type").and_then(|v| v.as_str()) {
                match msg_type {
                    "JOIN" => {
                        if let Some(nick) = json.get("nick").and_then(|v| v.as_str()) {
                            let fresh = !peers_nicks_data.lock().unwrap().contains_key(&peer.id);
                            peers_nicks_data.lock().unwrap().insert(peer.id.clone(), nick.to_string());
                            if fresh {
                                // Usa clearLine + prompt como no JS
                                let current_nick = nick_for_callback_data.as_str();
                                print!("\r\x1b[2K");
                                println!("{}{} * {} joined{}", COLOR_SYS, ts(), nick, RESET);
                                print!("{}{}{} > ", COLOR_SELF, current_nick, RESET);
                                io::stdout().flush().unwrap();
                            }
                        }
                    }
                    "MSG" => {
                        if let Some(nick) = json.get("nick").and_then(|v| v.as_str()) {
                            if let Some(text) = json.get("text").and_then(|v| v.as_str()) {
                                let current_nick = nick_for_callback_data.as_str();
                                // Usa clearLine + prompt como no JS
                                print!("\r\x1b[2K");
                                print!("{}[{}] ", COLOR_SYS, chrono::Local::now().format("%H:%M"));
                                println!("{}: {}", color_nick(nick), text);
                                print!("{}{}{} > ", COLOR_SELF, current_nick, RESET);
                                io::stdout().flush().unwrap();
                            }
                        }
                    }
                    "LEAVE" => {
                        if let Some(nick) = json.get("nick").and_then(|v| v.as_str()) {
                            let current_nick = nick_for_callback_data.as_str();
                            print!("\r\x1b[2K");
                            println!("{}{} * {} disconnected{}", COLOR_SYS, ts(), nick, RESET);
                            print!("{}{}{} > ", COLOR_SELF, current_nick, RESET);
                            io::stdout().flush().unwrap();
                            peers_nicks_data.lock().unwrap().remove(&peer.id);
                            handshook_data.lock().unwrap().remove(&peer.id);
                        }
                    }
                    _ => {}
                }
            }
        }
    }));

    // Start swarm
    swarm.start().await;

    // Create Arc after start for loop input
    let swarm_arc = Arc::new(swarm);

    // Wait a bit and print status
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    let external = swarm_arc.external_addr().await;
    let local_addr = external.unwrap_or_else(|| swarm_arc.local_addr());
    println!("{}{} * nat={} addr={}{}", COLOR_SYS, ts(), swarm_arc.nat_type(), local_addr, RESET);
    println!("{}{} * commands: /peers  /nat  /quit{}", COLOR_SYS, ts(), RESET);

    // Input loop
    let nick_loop = nick.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    let swarm_input = swarm_arc.clone();
    let my_id_for_input = my_id.clone();
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
        // Flush stdout before waiting for input
        io::stdout().flush().unwrap();
        print!("{}{}{} > ", COLOR_SELF, nick_loop, RESET);
        io::stdout().flush().unwrap();

        let line = match rx.recv().await {
            Some(l) => l,
            None    => break,
        };
        let line = line.trim().to_string();
        if line.is_empty() { continue; }

        // Clear line and newline BEFORE processing command (like JS does)
        print!("\r\x1b[2K");

        match line.as_str() {
            "/peers" => {
                let peers_info = swarm_input.list_peers().await;
                println!("{} * {} peer(s) connected", COLOR_SYS, peers_info.len());
                let nicks = peers_nicks_input.lock().unwrap();
                for (pid, rtt, in_mesh) in peers_info {
                    let peer_nick = nicks.get(&pid).cloned().unwrap_or_else(|| "?".to_string());
                    let display = format!("{} nick={} rtt={:.0}ms mesh={}", &pid[..8.min(pid.len())], peer_nick, rtt, in_mesh);
                    println!("{}   {}", COLOR_SYS, display);
                }
            }
            "/nat" => {
                let addr = swarm_input.external_addr().await.unwrap_or_else(|| swarm_input.local_addr());
                println!("{}{} * nat={} addr={}{}", COLOR_SYS, ts(), swarm_input.nat_type(), addr, RESET);
            }
            "/quit" | "/exit" => {
                // Envia LEAVE como no JS
                let leave_msg = serde_json::json!({
                    "type": "LEAVE",
                    "nick": nick_loop
                });
                swarm_input.broadcast(leave_msg.to_string().as_bytes()).await;
                println!("{}{} * goodbye!{}", COLOR_SYS, ts(), RESET);
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
                // Se broadcast não alcançou ninguém, tenta enviar diretamente como no JS
                if sent == 0 {
                    let peers_info = swarm_input.list_peers().await;
                    for (pid, _rtt, _in_mesh) in peers_info {
                        let _ = swarm_input.send_to(&pid, msg.to_string().as_bytes()).await;
                    }
                }
                // Própria mensagem com cor baseada em hash como os outros
                print!("{}[{}] ", COLOR_SYS, chrono::Local::now().format("%H:%M"));
                println!("{}: {}", color_nick(&nick_loop), line);
                if sent == 0 {
                    println!("{}{} * no peers connected yet{}", COLOR_SYS, ts(), RESET);
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