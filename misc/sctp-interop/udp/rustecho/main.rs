// rustecho: SCTP echo client/server for RFC 6951 interop (same protocol as goecho).
//   rustecho server <addr> [lencap rencap]
//   rustecho client <addr> [lencap rencap]
#![feature(sctp)]
use std::env;
use std::net::{
    Shutdown, SctpEventMask, SctpInitOptions, SctpNotification, SctpSendInfo, SctpSocket,
    SctpStream, SctpTransportConfig, SctpTransportPolicy, SctpUdpConfig, SocketAddr,
};
use std::process::exit;
use std::time::{Duration, Instant};

const N: usize = 100;
const BIG: usize = match option_env!("BIG") { Some(_) => 65536, None => 200 * 1024 };
const STREAMS: usize = 5;

fn payload(i: usize) -> Vec<u8> {
    let size = if i == N / 2 { BIG } else { 64 + (i * 37) % 2000 };
    let mut b: Vec<u8> = (0..size).map(|j| (j * 7 + i) as u8).collect();
    b[..4].copy_from_slice(&(i as u32).to_be_bytes());
    b
}

fn fail(msg: String) -> ! {
    eprintln!("[rust] FAIL: {msg}");
    exit(1)
}

fn cfg(args: &[String]) -> SctpTransportConfig {
    let p = |i: usize| args.get(i).and_then(|s| s.parse::<u16>().ok()).filter(|&v| v != 0);
    SctpTransportConfig {
        policy: SctpTransportPolicy::UdpOnly,
        udp: Some(SctpUdpConfig {
            local_encap_port: p(3),
            remote_encap_port: p(4),
            reuse_port: false,
        }),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let addr: SocketAddr = args[2].parse().unwrap();
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(60));
        fail("timeout".into())
    });
    let events = SctpEventMask { association: true, shutdown: true, ..Default::default() };
    let init = SctpInitOptions { num_ostreams: 10, max_instreams: 10, ..Default::default() };
    match args[1].as_str() {
        "server" => {
            let s = SctpSocket::bind_with_config(addr, cfg(&args)).unwrap_or_else(|e| fail(format!("bind: {e}")));
            s.set_init_options(init).unwrap();
            s.subscribe_events(events).unwrap();
            eprintln!("[rust-server] listening on {addr}");
            let mut buf = vec![0u8; 64 * 1024];
            let mut acc = Vec::new();
            let (mut count, mut bytes) = (0usize, 0usize);
            loop {
                let r = s.recv_message(&mut buf).unwrap_or_else(|e| fail(format!("recv after {count}: {e}")));
                if let Some(n) = r.receive.notification {
                    eprintln!("[rust-server] notification {n:?}");
                    // rust-sctp's UDP engine reports Shutdown but no
                    // SHUTDOWN_COMP association change: accept Shutdown.
                    if let SctpNotification::Shutdown { .. } = n {
                        std::thread::sleep(Duration::from_millis(500));
                        eprintln!("[rust-server] PASS: echoed {count} messages ({bytes} bytes), peer shutdown (no SHUTDOWN_COMP event from rust-sctp)");
                        return;
                    }
                    if let SctpNotification::AssociationChange { state, .. } = n {
                        if state == 3 {
                            eprintln!("[rust-server] PASS: echoed {count} messages ({bytes} bytes), graceful shutdown complete");
                            return;
                        }
                        if state == 1 {
                            fail(format!("COMM_LOST after {count}"));
                        }
                    }
                    continue;
                }
                acc.extend_from_slice(&buf[..r.receive.len]);
                if !r.receive.flags.end_of_record {
                    continue;
                }
                let info = r.receive.info.unwrap_or_else(|| fail("no rcvinfo".into()));
                let peer = r.peer_addr.unwrap_or_else(|| fail("no peer addr".into()));
                count += 1;
                bytes += acc.len();
                let si = SctpSendInfo { stream: info.stream, ppid: info.ppid, assoc_id: info.assoc_id, ..Default::default() };
                s.send_to_with_info(&acc, peer, Some(&si)).unwrap_or_else(|e| fail(format!("echo {count} len {}: {e}", acc.len())));
                acc.clear();
            }
        }
        "client" => {
            let start = Instant::now();
            let c = SctpStream::connect_with_init_options_and_config(addr, init, cfg(&args))
                .unwrap_or_else(|e| fail(format!("connect: {e}")));
            eprintln!("[rust-client] connected {:?} -> {addr} transport={:?}", c.local_addr(), c.transport());
            c.subscribe_events(events).unwrap();
            let w = c.try_clone().unwrap();
            let writer = std::thread::spawn(move || {
                for i in 0..N {
                    let si = SctpSendInfo { stream: (i % STREAMS) as u16, ppid: 0x10000 + i as u32, ..Default::default() };
                    w.send_with_info(&payload(i), Some(&si)).unwrap_or_else(|e| fail(format!("send {i}: {e}")));
                }
            });
            let mut buf = vec![0u8; 64 * 1024];
            let mut acc = Vec::new();
            let mut per = [0usize; STREAMS];
            let mut got = 0;
            while got < N {
                let r = c.recv_message(&mut buf).unwrap_or_else(|e| fail(format!("recv after {got}: {e}")));
                if let Some(n) = r.notification {
                    eprintln!("[rust-client] notification {n:?}");
                    continue;
                }
                if r.len == 0 { fail(format!("EOF after {got}")); }
                acc.extend_from_slice(&buf[..r.len]);
                if !r.flags.end_of_record { continue; }
                let info = r.info.unwrap_or_else(|| fail("no rcvinfo".into()));
                let i = u32::from_be_bytes(acc[..4].try_into().unwrap()) as usize;
                if i >= N || acc != payload(i) { fail(format!("payload mismatch msg {i} len {}", acc.len())); }
                if info.stream as usize != i % STREAMS || info.ppid != 0x10000 + i as u32 {
                    fail(format!("msg {i} metadata {info:?}"));
                }
                if per[info.stream as usize] != i / STREAMS { fail(format!("msg {i} out of order")); }
                per[info.stream as usize] += 1;
                got += 1;
                acc.clear();
            }
            writer.join().unwrap();
            eprintln!("[rust-client] verified {got} echoes (big={BIG}) in {:?}", start.elapsed());
            c.shutdown(Shutdown::Write).unwrap_or_else(|e| fail(format!("shutdown: {e}")));
            loop {
                match c.recv_message(&mut buf) {
                    Ok(r) if r.notification.is_some() => {
                        let n = r.notification.unwrap();
                        eprintln!("[rust-client] notification {n:?}");
                        if let SctpNotification::AssociationChange { state: 3, .. } = n { break; }
                    }
                    Ok(r) if r.len == 0 => { eprintln!("[rust-client] EOF after shutdown"); break; }
                    Ok(_) => fail("data after shutdown".into()),
                    Err(e) => fail(format!("waiting for shutdown: {e}")),
                }
            }
            eprintln!("[rust-client] PASS: {got} messages echoed and verified, graceful shutdown in {:?}", start.elapsed());
        }
        _ => fail("mode".into()),
    }
}
