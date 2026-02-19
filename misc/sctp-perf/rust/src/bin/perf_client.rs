#![feature(sctp)]

use std::env;
use std::io;
use std::net::{SctpSendInfo, SctpStream};
use std::time::{Duration, Instant};

const FRAME_DATA: u8 = 1;
const FRAME_STOP: u8 = 2;
const FRAME_RESULT: u8 = 3;
const DEFAULT_PPID: u32 = 0x5052_4631; // "PRF1"

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

fn recv_user_frame(stream: &SctpStream, recv_buf: &mut [u8]) -> io::Result<(u8, usize)> {
    let (n, _) = stream.recv_with_info(recv_buf)?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed"));
    }
    let (kind, payload) = decode_frame(&recv_buf[..n])?;
    Ok((kind, payload.len()))
}

fn run() -> io::Result<()> {
    let (host, port, mode, iterations, payload_size) = parse_args()?;
    let stream = SctpStream::connect((host.as_str(), port))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;

    let payload = vec![b'x'; payload_size];
    let send_info = SctpSendInfo {
        stream: 0,
        ppid: DEFAULT_PPID,
        assoc_id: 0,
        ..Default::default()
    };
    let mut recv_buf = vec![0_u8; payload_size + 4096];

    let start = Instant::now();
    if mode == "rtt" {
        for _ in 0..iterations {
            stream.send_with_info(&encode_frame(FRAME_DATA, &payload), Some(&send_info))?;
            let (kind, recv_size) = recv_user_frame(&stream, &mut recv_buf)?;
            if kind != FRAME_DATA {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected frame type in rtt response: {kind}"),
                ));
            }
            if recv_size != payload_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected payload size in rtt response: {recv_size}"),
                ));
            }
        }
        let elapsed = start.elapsed().as_secs_f64();
        let rtt_us = (elapsed / iterations as f64) * 1_000_000.0;
        println!(
            "PERF_CLIENT_RESULT lang=rust mode=rtt iterations={} size={} elapsed_s={:.6} rtt_us_avg={:.3} throughput_mbps=0.000",
            iterations, payload_size, elapsed, rtt_us
        );
        return Ok(());
    }

    for _ in 0..iterations {
        stream.send_with_info(&encode_frame(FRAME_DATA, &payload), Some(&send_info))?;
    }
    stream.send_with_info(&encode_frame(FRAME_STOP, &[]), Some(&send_info))?;
    let (kind, _) = recv_user_frame(&stream, &mut recv_buf)?;
    if kind != FRAME_RESULT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected frame type in throughput response: {kind}"),
        ));
    }
    let elapsed = start.elapsed().as_secs_f64();
    let throughput_mbps = ((iterations * payload_size) as f64 * 8.0) / elapsed / 1_000_000.0;
    println!(
        "PERF_CLIENT_RESULT lang=rust mode=throughput iterations={} size={} elapsed_s={:.6} rtt_us_avg=0.000 throughput_mbps={:.3}",
        iterations, payload_size, elapsed, throughput_mbps
    );
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
