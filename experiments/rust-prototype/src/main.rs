//! Runnable experiment, not a production plugin replacement. All credentials use stdin.
mod protocol;
mod transport;

use protocol::{Codec, Replay, MAX_FRAME, MAX_PAYLOAD};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashMap, io::{BufRead, Write}, net::{IpAddr, SocketAddr}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use tokio::{net::UdpSocket, sync::watch, time::{sleep, timeout}};
use transport::{TurnConfig, TurnEndpoint};

type Result<T, E = &'static str> = std::result::Result<T, E>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TurnInput { host: String, connect_ip: String, port: u16, username: String, password: String, expires_unix: f64 }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer { host: String, port: u16, key_hex: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Workload {
    payload_bytes: usize, latency_packets: u64, throughput_bytes: u64, window: usize,
    packet_timeout_s: f64, idle_s: f64, renewal_soak_s: f64, renewals: u64,
    recovery: bool, run_timeout_s: f64,
}
#[derive(Deserialize)]
#[serde(tag = "role", rename_all = "lowercase", deny_unknown_fields)]
enum Request {
    Client { version: u8, turn: TurnInput, peer: Peer, workload: Workload },
    Echo { version: u8, bind_host: String, advertise_host: String, key_hex: String, max_duration_s: f64, max_bytes: u64 },
    Relay { version: u8, turn: TurnInput, peer: Peer, listen_port: u16, max_duration_s: f64 },
}

fn emit(value: Value) { let mut out = std::io::stdout().lock(); let _ = serde_json::to_writer(&mut out, &value); let _ = out.write_all(b"\n"); let _ = out.flush(); }
fn phase(name: &str) { emit(json!({"event":"state","state":"phase","phase":name})); }
fn finite(value: f64, min: f64, max: f64) -> Result<Duration> {
    if !value.is_finite() || value < min || value > max { return Err("invalid_request"); }
    Ok(Duration::from_secs_f64(value))
}
fn key(value: &str) -> Result<[u8;32]> {
    let mut key = [0;32];
    if value.len() != 64 { return Err("invalid_request"); }
    hex::decode_to_slice(value, &mut key).map_err(|_| "invalid_request")?;
    Ok(key)
}
fn address(host: &str, port: u16) -> Result<SocketAddr> {
    if port == 0 { return Err("invalid_request"); }
    let ip: IpAddr = host.parse().map_err(|_| "invalid_request")?;
    if !ip.is_ipv4() { return Err("invalid_request"); }
    Ok(SocketAddr::new(ip, port))
}
fn turn_config(value: TurnInput) -> Result<(TurnConfig, Duration)> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "clock_error")?.as_secs_f64();
    let valid = finite(value.expires_unix - now, 30., 172800.)?;
    address(&value.connect_ip, value.port)?;
    if value.host.is_empty() || value.host.len() > 253 || !value.host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        || value.username.is_empty() || value.username.len() > 4096 || value.password.is_empty() || value.password.len() > 4096 { return Err("invalid_request"); }
    if let Ok(ip) = value.host.parse::<IpAddr>() { if ip.to_string() != value.connect_ip { return Err("turn_ip_mismatch"); } }
    Ok((TurnConfig { host:value.host, ip:value.connect_ip, port:value.port, username:value.username, password:value.password }, valid))
}
fn read_record() -> Result<Value> {
    let input = std::io::stdin();
    let mut reader = input.lock();
    let mut bytes = Vec::with_capacity(4096);
    loop {
        let available = reader.fill_buf().map_err(|_| "invalid_input")?;
        if available.is_empty() { return Err("input_closed"); }
        let end = available.iter().position(|b| *b == b'\n');
        let count = end.map_or(available.len(), |n| n + 1);
        if bytes.len() + count > 65536 { return Err("invalid_input"); }
        bytes.extend_from_slice(&available[..count]);
        reader.consume(count);
        if end.is_some() { break; }
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid_input")
}
async fn stopped(mut stop: watch::Receiver<bool>) { while !*stop.borrow() { if stop.changed().await.is_err() { break; } } }

struct WorkBuffers {
    codec: Codec, payload: Vec<u8>, wire: Vec<u8>, incoming: Vec<u8>, next_id: u64, clock: Instant,
}
impl WorkBuffers {
    fn new(key: [u8;32], size: usize) -> Self {
        let mut payload = vec![0;size];
        payload[..4].copy_from_slice(b"TTRB");
        for (i, byte) in payload[20..].iter_mut().enumerate() { *byte = (i % 251) as u8; }
        Self { codec:Codec::new(key), payload, wire:Vec::with_capacity(MAX_FRAME), incoming:vec![0;MAX_FRAME], next_id:1, clock:Instant::now() }
    }
    fn stamp(&self) -> u64 { self.clock.elapsed().as_nanos().min(u64::MAX as u128) as u64 }
}
#[derive(Default)]
struct Counts { sent:u64, acked:u64, bytes:u64, timeouts:u64, integrity:u64, late:u64 }
fn percentile(values:&mut [f64], q:f64)->Value {
    if values.is_empty() { return Value::Null; }
    values.sort_by(f64::total_cmp);
    json!(values[((values.len() as f64 * q).ceil() as usize).saturating_sub(1)])
}
async fn exchange(endpoint:&TurnEndpoint, buffers:&mut WorkBuffers, work:&Workload, phase_name:&str, packets:u64, window:usize, report:bool)->Result<Value> {
    phase(phase_name);
    let started=Instant::now();
    let mut pending:HashMap<u64,u64>=HashMap::with_capacity(window);
    let mut counts=Counts::default();
    let mut rtts=Vec::with_capacity(if phase_name=="latency" { packets as usize } else { 0 });
    let timeout_ns=(work.packet_timeout_s*1e9) as u64;
    while counts.sent<packets || !pending.is_empty() {
        while counts.sent<packets && pending.len()<window {
            let id=buffers.next_id; buffers.next_id=buffers.next_id.checked_add(1).ok_or("sequence_exhausted")?;
            let stamp=buffers.stamp();
            buffers.payload[4..12].copy_from_slice(&id.to_be_bytes());
            buffers.payload[12..20].copy_from_slice(&stamp.to_be_bytes());
            buffers.codec.encode(&buffers.payload,&mut buffers.wire).map_err(|_|"framing_error")?;
            pending.insert(id,stamp);
            endpoint.send(&buffers.wire).await.map_err(|_|"turn_transport")?;
            counts.sent+=1;
        }
        let now=buffers.stamp();
        pending.retain(|_,stamp| { if now.saturating_sub(*stamp)>=timeout_ns {counts.timeouts+=1;false} else {true} });
        let Some(oldest)=pending.values().min().copied() else {continue;};
        let remaining=Duration::from_nanos((oldest+timeout_ns).saturating_sub(buffers.stamp()));
        let size=match timeout(remaining,endpoint.recv(&mut buffers.incoming)).await {
            Ok(Ok(size))=>size, Ok(Err(_))=>return Err("turn_transport"), Err(_)=>continue,
        };
        let arrived=buffers.stamp();
        let Some(payload)=buffers.codec.decode(&buffers.incoming[..size]) else {continue;};
        if payload.len()!=work.payload_bytes || &payload[..4]!=b"TTRB" || !payload[20..].iter().enumerate().all(|(i,b)| *b==(i%251) as u8) {counts.integrity+=1;continue;}
        let id=u64::from_be_bytes(payload[4..12].try_into().map_err(|_|"framing_error")?);
        let stamp=u64::from_be_bytes(payload[12..20].try_into().map_err(|_|"framing_error")?);
        let Some(expected)=pending.get(&id).copied() else {counts.late+=1;continue;};
        if arrived.saturating_sub(expected)>=timeout_ns {pending.remove(&id);counts.timeouts+=1;counts.late+=1;continue;}
        if stamp!=expected {counts.integrity+=1;continue;}
        pending.remove(&id);counts.acked+=1;counts.bytes+=payload.len() as u64;
        if phase_name=="latency" {rtts.push(arrived.saturating_sub(stamp) as f64/1e6);}
    }
    let duration=started.elapsed().as_secs_f64();
    let mut sample=json!({"event":"sample","phase":phase_name,"sent_packets":counts.sent,"sent_bytes":counts.sent*work.payload_bytes as u64,"acked_packets":counts.acked,"acked_bytes":counts.bytes,"timeouts":counts.timeouts,"integrity_errors":counts.integrity,"late_packets":counts.late,"duration_s":duration,"loss_packets":counts.sent-counts.acked});
    if phase_name=="latency" {sample["p50_ms"]=percentile(&mut rtts,0.5);sample["p95_ms"]=percentile(&mut rtts,0.95);}
    if phase_name=="throughput" {sample["target_bytes"]=json!(work.throughput_bytes);sample["throughput_bps"]=json!(counts.bytes as f64*8./duration.max(1e-9));}
    if report {emit(sample.clone());}
    Ok(sample)
}
async fn workload(endpoint:&mut TurnEndpoint,cfg:&TurnConfig,peer:SocketAddr,buffers:&mut WorkBuffers,work:&Workload)->Result<()> {
    phase("idle");let idle=Instant::now();sleep(Duration::from_secs_f64(work.idle_s)).await;
    if endpoint.stats().remaining_ms==0 {return Err("allocation_expired");}
    emit(json!({"event":"sample","phase":"idle","duration_s":idle.elapsed().as_secs_f64()}));
    exchange(endpoint,buffers,work,"latency",work.latency_packets,1,true).await?;
    exchange(endpoint,buffers,work,"throughput",work.throughput_bytes/work.payload_bytes as u64,work.window,true).await?;
    if work.renewal_soak_s>0. || work.renewals>0 {
        phase("renewal");let before=endpoint.stats().refreshes;let start=Instant::now();
        while start.elapsed().as_secs_f64()<work.renewal_soak_s {
            if endpoint.stats().remaining_ms==0 {return Err("allocation_expired");}
            sleep(Duration::from_millis(100)).await;
        }
        let count=endpoint.stats().refreshes.saturating_sub(before);
        emit(json!({"event":"sample","phase":"renewal","duration_s":start.elapsed().as_secs_f64(),"successful_renewals":count,"required_renewals":work.renewals,"success":u8::from(count>=work.renewals)}));
    }
    if work.recovery {
        phase("recovery");let start=Instant::now();endpoint.abort();
        let failed=endpoint.send(b"not-a-valid-gateway-frame").await.is_err();
        if !failed {return Err("abort_not_observed");}
        let detection=start.elapsed().as_secs_f64()*1000.;endpoint.close().await;
        *endpoint=TurnEndpoint::connect(cfg,peer).await.map_err(|_|"recovery_failed")?;
        let mut sample=exchange(endpoint,buffers,work,"recovery",1,1,false).await?;
        sample["detection_ms"]=json!(detection);sample["recovery_ms"]=json!(start.elapsed().as_secs_f64()*1000.);
        sample["success"]=json!(u8::from(sample["acked_packets"].as_u64()==Some(1)));emit(sample);
    }
    Ok(())
}
async fn client(turn:TurnInput,peer:Peer,work:Workload,stop:watch::Receiver<bool>)->Result<()> {
    if !(20..=MAX_PAYLOAD).contains(&work.payload_bytes) || !(1..=5000).contains(&work.latency_packets)
        || work.latency_packets*work.payload_bytes as u64>1024*1024 || work.throughput_bytes>16*1024*1024
        || !(1..=1024).contains(&work.window) || work.renewals>3 {return Err("invalid_request");}
    finite(work.packet_timeout_s,0.05,10.)?;finite(work.idle_s,0.,30.)?;finite(work.renewal_soak_s,0.,300.)?;
    let bound=finite(work.run_timeout_s,1.,600.)?;
    let (cfg,valid)=turn_config(turn)?;let peer_addr=address(&peer.host,peer.port)?;
    let mut buffers=WorkBuffers::new(key(&peer.key_hex)?,work.payload_bytes);
    let mut endpoint=tokio::select! {
        result=TurnEndpoint::connect(&cfg,peer_addr)=>result.map_err(|_|"turn_connect")?,
        _=stopped(stop.clone())=>return Ok(()),
    };
    emit(json!({"event":"ready"}));
    let result=tokio::select! {
        result=timeout(bound.min(valid),workload(&mut endpoint,&cfg,peer_addr,&mut buffers,&work))=>result.map_err(|_|"run_timeout").and_then(|v|v),
        _=stopped(stop.clone())=>Ok(()),
    };
    if result.is_ok() && !*stop.borrow() {
        emit(json!({"event":"done"}));
        tokio::select! {_=stopped(stop)=>{},_=sleep(Duration::from_secs(30))=>{endpoint.close().await;return Err("stop_timeout");}}
    }
    endpoint.close().await;
    result
}

struct ServerFlow { replay:Replay, sequence:u64 }
async fn echo(bind_host:String,advertise_host:String,key_hex:String,max_duration_s:f64,max_bytes:u64,stop:watch::Receiver<bool>)->Result<()> {
    let key=key(&key_hex)?;let duration=finite(max_duration_s,1.,3600.)?;
    if max_bytes==0 || max_bytes>128*1024*1024 {return Err("invalid_request");}
    let bind:IpAddr=bind_host.parse().map_err(|_|"invalid_request")?;
    let advertise:IpAddr=advertise_host.parse().map_err(|_|"invalid_request")?;
    if !bind.is_ipv4() || !advertise.is_ipv4() {return Err("invalid_request");}
    let socket=UdpSocket::bind(SocketAddr::new(bind,0)).await.map_err(|_|"bind_failed")?;
    emit(json!({"event":"ready","host":advertise.to_string(),"port":socket.local_addr().map_err(|_|"bind_failed")?.port()}));
    let mut flows:HashMap<u64,ServerFlow>=HashMap::new();let mut input=vec![0;MAX_FRAME];let mut output=Vec::with_capacity(MAX_FRAME);
    let mut packets=0u64;let mut bytes=0u64;let mut rejected=0u64;let mut replay_rejections=0u64;
    let loop_work=async {
        loop {
            let (size,remote)=socket.recv_from(&mut input).await.map_err(|_|"socket_error")?;
            let Some((id,seq,payload))=protocol::decode(&key,1,&input[..size]) else {rejected+=1;continue;};
            if !flows.contains_key(&id) && flows.len()>=64 {rejected+=1;continue;}
            let flow=flows.entry(id).or_insert_with(||ServerFlow{replay:Replay::default(),sequence:0});
            if !flow.replay.accept(seq) {replay_rejections+=1;continue;}
            if bytes+payload.len() as u64>max_bytes {return Ok(());}
            flow.sequence=flow.sequence.checked_add(1).ok_or("sequence_exhausted")?;
            protocol::encode(&key,2,id,flow.sequence,payload,&mut output).map_err(|_|"framing_error")?;
            socket.send_to(&output,remote).await.map_err(|_|"socket_error")?;
            packets+=1;bytes+=payload.len() as u64;
        }
    };
    let result=tokio::select! {r=loop_work=>r,_=stopped(stop)=>Ok(()),_=sleep(duration)=>Ok(())};
    emit(json!({"event":"sample","phase":"echo","echoed_packets":packets,"echoed_bytes":bytes,"rejected_packets":rejected,"replay_rejections":replay_rejections}));
    result
}

async fn relay(turn:TurnInput,peer:Peer,listen_port:u16,max_duration_s:f64,stop:watch::Receiver<bool>)->Result<()> {
    if listen_port<1024 {return Err("invalid_request");}
    let (cfg,valid)=turn_config(turn)?;let bound=finite(max_duration_s,1.,1800.)?.min(valid);
    let peer_addr=address(&peer.host,peer.port)?;let session_key=key(&peer.key_hex)?;
    let local=UdpSocket::bind(("127.0.0.1",listen_port)).await.map_err(|_|"bind_failed")?;
    let mut endpoint=TurnEndpoint::connect(&cfg,peer_addr).await.map_err(|_|"turn_connect")?;
    let mut flows:HashMap<SocketAddr,Codec>=HashMap::new();
    let mut local_buf=vec![0;MAX_PAYLOAD];let mut remote_buf=vec![0;MAX_FRAME];let mut wire=Vec::with_capacity(MAX_FRAME);
    emit(json!({"event":"ready","host":"127.0.0.1","port":listen_port}));
    let serving=async {
        loop {
            let failed=tokio::select! {
                data=local.recv_from(&mut local_buf)=>{
                    let (size,source)=data.map_err(|_|"socket_error")?;
                    if !flows.contains_key(&source) && flows.len()>=16 {continue;}
                    let codec=flows.entry(source).or_insert_with(||Codec::new(session_key));
                    codec.encode(&local_buf[..size],&mut wire).map_err(|_|"framing_error")?;
                    endpoint.send(&wire).await.err()
                },
                data=endpoint.recv(&mut remote_buf)=>{
                    match data {
                        Ok(size)=>{
                            if size>=24 {
                                let id=u64::from_be_bytes(remote_buf[6..14].try_into().map_err(|_|"framing_error")?);
                                if let Some((source,codec))=flows.iter_mut().find(|(_,codec)|codec.flow==id) {
                                    if let Some(payload)=codec.decode(&remote_buf[..size]) {local.send_to(payload,*source).await.map_err(|_|"socket_error")?;}
                                }
                            }
                            None
                        },Err(error)=>Some(error),
                    }
                },
            };
            if let Some(error)=failed {
                if !error.recoverable() {return Err("fatal_transport");}
                emit(json!({"event":"state","state":"recovering"}));endpoint.close().await;
                let mut rebuilt=None;
                for wait in [1,2,5] {
                    sleep(Duration::from_secs(wait)).await;
                    match TurnEndpoint::connect(&cfg,peer_addr).await {
                        Ok(next)=>{rebuilt=Some(next);break;},
                        Err(error) if !error.recoverable()=>return Err("fatal_transport"),
                        Err(_)=>{},
                    }
                }
                endpoint=rebuilt.ok_or("recovery_exhausted")?;
                emit(json!({"event":"state","state":"ready"}));
            }
        }
    };
    let result=tokio::select! {r=serving=>r,_=stopped(stop)=>Ok(()),_=sleep(bound)=>Err("run_timeout")};
    endpoint.close().await;
    result
}

fn main() {
    if std::env::args().nth(1).as_deref()==Some("--help") {
        println!("EXPERIMENT ONLY: one bounded JSON request on stdin; roles client, echo, relay; then {{\"command\":\"stop\"}}. Never put credentials in arguments.");return;
    }
    let initial=read_record().and_then(|value|serde_json::from_value::<Request>(value).map_err(|_|"invalid_request"));
    let request=match initial {Ok(v)=>v,Err(code)=>{emit(json!({"event":"error","code":code}));std::process::exit(2)}};
    let (stop_tx,stop_rx)=watch::channel(false);
    std::thread::spawn(move|| {let _=read_record();let _=stop_tx.send(true);});
    let runtime=match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(v)=>v,Err(_)=>{emit(json!({"event":"error","code":"runtime_failed"}));std::process::exit(2)},
    };
    let result=runtime.block_on(async {
        match request {
            Request::Client{version:1,turn,peer,workload}=>client(turn,peer,workload,stop_rx).await,
            Request::Echo{version:1,bind_host,advertise_host,key_hex,max_duration_s,max_bytes}=>echo(bind_host,advertise_host,key_hex,max_duration_s,max_bytes,stop_rx).await,
            Request::Relay{version:1,turn,peer,listen_port,max_duration_s}=>relay(turn,peer,listen_port,max_duration_s,stop_rx).await,
            _=>Err("invalid_request"),
        }
    });
    runtime.shutdown_timeout(Duration::from_secs(2));
    match result {Ok(())=>emit(json!({"event":"stopped"})),Err(code)=>{emit(json!({"event":"error","code":code}));std::process::exit(1)}}
}
