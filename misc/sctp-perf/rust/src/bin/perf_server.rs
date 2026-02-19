#![feature(sctp)]

use std::env;
use std::io;
use std::net::{SctpListener, SctpSendInfo};
use std::time::{Duration, Instant};

const FRAME_DATA: u8 = 1;
const FRAME_STOP: u8 = 2;
const FRAME_RESULT: u8 = 3;
fn encode_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn decode_frame(frame: &[u8]) -> io::Result<(u8, &[u8])> {
    if frame.len() < 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short frame"));
    }
    let size = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
    if frame.len() != 5 + size {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame length mismatch"));
    }
    Ok((frame[0], &frame[5..]))
}

fn parse_args() -> io::Result<(String, u16, String, usize, usize)> {
    let mut host = "127.0.0.1".to_string();
    let mut port: u16 = 19100;
    let mut mode = "rtt".to_string();
    let mut iterations: usize = 200;
    let mut payload_size: usize = 256;

    let args: Vec<String> = env::args().collect();
    if let Some(v) = args.get(1) {
        host = v.clone();
    }
    if let Some(v) = args.get(2) {
        port = v
            .parse::<u16>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid port: {e}")))?;
    }
    if let Some(v) = args.get(3) {
        mode = v.clone();
    }
    if let Some(v) = args.get(4) {
        iterations = v.parse::<usize>().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid iterations: {e}"))
        })?;
    }
    if let Some(v) = args.get(5) {
        payload_size = v.parse::<usize>().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid payload size: {e}"))
        })?;
    }
    if mode != "rtt" && mode != "throughput" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid mode {mode} (expected rtt|throughput)"),
        ));
    }
    if iterations == 0 || payload_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "iterations and payload size must be positive",
        ));
    }
    Ok((host, port, mode, iterations, payload_size))
}

fn run() -> io::Result<()> {
    let (host, port, mode, iterations, payload_size) = parse_args()?;
    let bind_addr = format!("{host}:{port}");
    let listener = SctpListener::bind(bind_addr.as_str())?;
    let (stream, _peer) = listener.accept()?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;

    println!(
        "PERF_SERVER_READY lang=rust mode={} bind={} iterations={} size={}",
        mode, bind_addr, iterations, payload_size
    );

    let mut recv_buf = vec![0_u8; payload_size + 4096];
    let mut started = false;
    let mut start = Instant::now();
    let mut msgs: usize = 0;
    let mut bytes: usize = 0;

    loop {
        let (n, info) = stream.recv_with_info(&mut recv_buf)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed"));
        }
        let (kind, payload) = decode_frame(&recv_buf[..n])?;

        if mode == "rtt" {
            if kind != FRAME_DATA {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected frame type in rtt mode: {kind}"),
                ));
            }
            if !started {
                started = true;
                start = Instant::now();
            }
            msgs += 1;
            bytes += payload.len();

            let send_info = info.map(|i| SctpSendInfo {
                stream: i.stream,
                ppid: i.ppid,
                assoc_id: i.assoc_id,
                ..Default::default()
            });
            stream.send_with_info(&encode_frame(FRAME_DATA, payload), send_info.as_ref())?;
            if msgs >= iterations {
                let elapsed = start.elapsed().as_secs_f64();
                println!(
                    "PERF_SERVER_DONE lang=rust mode=rtt messages={} bytes={} seconds={:.6}",
                    msgs, bytes, elapsed
                );
                return Ok(());
            }
            continue;
        }

        if kind == FRAME_DATA {
            if !started {
                started = true;
                start = Instant::now();
            }
            msgs += 1;
            bytes += payload.len();
            continue;
        }
        if kind != FRAME_STOP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected frame type in throughput mode: {kind}"),
            ));
        }
        let elapsed = start.elapsed().as_secs_f64();
        let result = format!("messages={} bytes={} seconds={:.6}", msgs, bytes, elapsed);
        let send_info = info.map(|i| SctpSendInfo {
            stream: i.stream,
            ppid: i.ppid,
            assoc_id: i.assoc_id,
            ..Default::default()
        });
        stream.send_with_info(&encode_frame(FRAME_RESULT, result.as_bytes()), send_info.as_ref())?;
        println!(
            "PERF_SERVER_DONE lang=rust mode=throughput messages={} bytes={} seconds={:.6}",
            msgs, bytes, elapsed
        );
        return Ok(());
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
