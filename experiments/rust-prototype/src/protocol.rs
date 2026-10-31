//! Wire-compatible TTRG v1 codec. Experiment only; no production registration.
use hmac::{Hmac, Mac};
use sha2::Sha256;

const HEADER: usize = 24;
const TAG: usize = 16;
pub const MAX_PAYLOAD: usize = 65_000;
pub const MAX_FRAME: usize = MAX_PAYLOAD + HEADER + TAG;
type Auth = Hmac<Sha256>;

pub fn encode(key: &[u8; 32], direction: u8, flow: u64, seq: u64, payload: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    if !matches!(direction, 1 | 2) || seq == 0 || payload.len() > MAX_PAYLOAD { return Err(()); }
    out.clear();
    out.extend_from_slice(b"TTRG");
    out.extend_from_slice(&[1, direction]);
    out.extend_from_slice(&flow.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    let mut mac = Auth::new_from_slice(key).map_err(|_| ())?;
    mac.update(out);
    out.extend_from_slice(&mac.finalize().into_bytes()[..TAG]);
    Ok(())
}

pub fn decode<'a>(key: &[u8; 32], direction: u8, data: &'a [u8]) -> Option<(u64, u64, &'a [u8])> {
    if data.len() < HEADER + TAG || data.len() > MAX_FRAME || &data[..4] != b"TTRG" || data[4] != 1 || data[5] != direction { return None; }
    let size = u16::from_be_bytes(data[22..24].try_into().ok()?) as usize;
    if size > MAX_PAYLOAD || data.len() != HEADER + size + TAG { return None; }
    let flow = u64::from_be_bytes(data[6..14].try_into().ok()?);
    let seq = u64::from_be_bytes(data[14..22].try_into().ok()?);
    if seq == 0 { return None; }
    let body = &data[..HEADER + size];
    let mut mac = Auth::new_from_slice(key).ok()?;
    mac.update(body);
    mac.verify_truncated_left(&data[HEADER + size..]).ok()?;
    Some((flow, seq, &data[HEADER..HEADER + size]))
}

#[derive(Default)]
pub struct Replay {
    high: u64,
    bits: [u64; 16],
}
impl Replay {
    pub fn accept(&mut self, seq: u64) -> bool {
        if seq == 0 { return false; }
        if seq > self.high {
            let distance = seq - self.high;
            if distance >= 1024 { self.bits.fill(0); }
            else {
                let words = (distance / 64) as usize;
                let shift = (distance % 64) as u32;
                for i in (0..16).rev() {
                    self.bits[i] = if i >= words { self.bits[i - words] << shift } else { 0 };
                    if shift != 0 && i > words { self.bits[i] |= self.bits[i - words - 1] >> (64 - shift); }
                }
            }
            self.high = seq;
            self.bits[0] |= 1;
            return true;
        }
        let distance = self.high - seq;
        if distance >= 1024 { return false; }
        let word = (distance / 64) as usize;
        let bit = 1u64 << (distance % 64);
        if self.bits[word] & bit != 0 { return false; }
        self.bits[word] |= bit;
        true
    }
}

pub struct Codec {
    key: [u8; 32],
    pub flow: u64,
    sequence: u64,
    replay: Replay,
}
impl Codec {
    pub fn new(key: [u8; 32]) -> Self { Self { key, flow: rand::random(), sequence: 0, replay: Replay::default() } }
    pub fn encode(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
        self.sequence = self.sequence.checked_add(1).ok_or(())?;
        encode(&self.key, 1, self.flow, self.sequence, payload, out)
    }
    pub fn decode<'a>(&mut self, data: &'a [u8]) -> Option<&'a [u8]> {
        let (flow, seq, payload) = decode(&self.key, 2, data)?;
        if flow != self.flow || !self.replay.accept(seq) { return None; }
        Some(payload)
    }
}
