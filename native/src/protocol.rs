//! Direction-bound TTRG v1 framing. Authentication is verified before replay state changes.
use crate::common::{Error, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const CLIENT_TO_SERVER: u8 = 1;
pub const SERVER_TO_CLIENT: u8 = 2;
const HEADER: usize = 24;
const TAG: usize = 16;
pub const MAX_PAYLOAD: usize = 65_000;
pub const MAX_FRAME: usize = MAX_PAYLOAD + HEADER + TAG;
type Auth = Hmac<Sha256>;

#[cfg(test)]
pub fn encode(
    key: &[u8; 32],
    direction: u8,
    flow: u64,
    sequence: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(HEADER + payload.len() + TAG);
    encode_into(key, direction, flow, sequence, payload, &mut out)?;
    Ok(out)
}

pub fn encode_into(
    key: &[u8; 32],
    direction: u8,
    flow: u64,
    sequence: u64,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    if !matches!(direction, CLIENT_TO_SERVER | SERVER_TO_CLIENT)
        || sequence == 0
        || payload.len() > MAX_PAYLOAD
    {
        return Err(Error::new(
            "protocol_error",
            "Invalid authenticated gateway frame.",
        ));
    }
    out.clear();
    out.extend_from_slice(b"TTRG");
    out.extend_from_slice(&[1, direction]);
    out.extend_from_slice(&flow.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    let mut mac = Auth::new_from_slice(key).expect("fixed size HMAC key");
    mac.update(out);
    out.extend_from_slice(&mac.finalize().into_bytes()[..TAG]);
    Ok(())
}

pub fn decode<'a>(key: &[u8; 32], direction: u8, frame: &'a [u8]) -> Option<(u64, u64, &'a [u8])> {
    if !matches!(direction, CLIENT_TO_SERVER | SERVER_TO_CLIENT)
        || frame.len() < HEADER + TAG
        || frame.len() > MAX_FRAME
        || &frame[..4] != b"TTRG"
        || frame[4] != 1
        || frame[5] != direction
    {
        return None;
    }
    let size = u16::from_be_bytes(frame[22..24].try_into().ok()?) as usize;
    if size > MAX_PAYLOAD || frame.len() != HEADER + size + TAG {
        return None;
    }
    let flow = u64::from_be_bytes(frame[6..14].try_into().ok()?);
    let sequence = u64::from_be_bytes(frame[14..22].try_into().ok()?);
    if sequence == 0 {
        return None;
    }
    let mut mac = Auth::new_from_slice(key).ok()?;
    mac.update(&frame[..HEADER + size]);
    mac.verify_truncated_left(&frame[HEADER + size..]).ok()?;
    Some((flow, sequence, &frame[HEADER..HEADER + size]))
}

#[derive(Default)]
pub struct ReplayWindow {
    high: u64,
    bits: [u64; 16],
}

impl ReplayWindow {
    pub fn highest(&self) -> u64 {
        self.high
    }

    pub fn accept(&mut self, sequence: u64) -> bool {
        if sequence == 0 {
            return false;
        }
        if sequence > self.high {
            let distance = sequence - self.high;
            if distance >= 1024 {
                self.bits.fill(0);
            } else {
                let words = (distance / 64) as usize;
                let shift = (distance % 64) as u32;
                for i in (0..16).rev() {
                    self.bits[i] = if i >= words {
                        self.bits[i - words] << shift
                    } else {
                        0
                    };
                    if shift != 0 && i > words {
                        self.bits[i] |= self.bits[i - words - 1] >> (64 - shift);
                    }
                }
            }
            self.high = sequence;
            self.bits[0] |= 1;
            return true;
        }
        let distance = self.high - sequence;
        if distance >= 1024 {
            return false;
        }
        let word = (distance / 64) as usize;
        let bit = 1u64 << (distance % 64);
        if self.bits[word] & bit != 0 {
            return false;
        }
        self.bits[word] |= bit;
        true
    }
}

/// Retained across TURN reallocations, discarded when the gateway key changes.
pub struct Codec {
    key: [u8; 32],
    pub flow: u64,
    sequence: u64,
    replay: ReplayWindow,
}

impl Codec {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            flow: rand::random(),
            sequence: 0,
            replay: ReplayWindow::default(),
        }
    }

    pub fn encode(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| Error::new("protocol_error", "Gateway frame sequence exhausted."))?;
        encode_into(
            &self.key,
            CLIENT_TO_SERVER,
            self.flow,
            sequence,
            payload,
            out,
        )?;
        self.sequence = sequence;
        Ok(())
    }

    pub fn decode<'a>(&mut self, frame: &'a [u8]) -> Option<&'a [u8]> {
        let (flow, sequence, payload) = decode(&self.key, SERVER_TO_CLIENT, frame)?;
        if flow != self.flow || !self.replay.accept(sequence) {
            return None;
        }
        Some(payload)
    }
}

impl Drop for Codec {
    fn drop(&mut self) {
        for byte in &mut self.key {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_binds_direction_key_and_every_byte() {
        let key = [7; 32];
        let frame = encode(&key, CLIENT_TO_SERVER, 42, 1, b"payload").unwrap();
        assert_eq!(
            decode(&key, CLIENT_TO_SERVER, &frame),
            Some((42, 1, &b"payload"[..]))
        );
        assert!(decode(&key, SERVER_TO_CLIENT, &frame).is_none());
        assert!(decode(&[8; 32], CLIENT_TO_SERVER, &frame).is_none());
        for index in 0..frame.len() {
            let mut corrupt = frame.clone();
            corrupt[index] ^= 1;
            assert!(decode(&key, CLIENT_TO_SERVER, &corrupt).is_none());
        }
        assert!(encode(&key, 0, 42, 1, b"").is_err());
        assert!(encode(&key, CLIENT_TO_SERVER, 42, 0, b"").is_err());
        assert!(encode(&key, CLIENT_TO_SERVER, 42, 1, &vec![0; MAX_PAYLOAD + 1]).is_err());
    }

    #[test]
    fn replay_window_matches_bounded_set_for_reordering_and_word_shifts() {
        let mut replay = ReplayWindow::default();
        let mut seen = std::collections::HashSet::new();
        let mut high = 0u64;
        let sequences = [
            0,
            1,
            65,
            2,
            64,
            65,
            129,
            128,
            1024,
            1,
            1025,
            1,
            2,
            2049,
            1025,
            1026,
            2048,
            2048,
            u64::MAX,
            u64::MAX - 1023,
            u64::MAX - 1024,
            u64::MAX,
        ];
        for sequence in sequences {
            let expected = sequence != 0
                && (sequence > high || (high - sequence < 1024 && !seen.contains(&sequence)));
            assert_eq!(replay.accept(sequence), expected, "sequence {sequence}");
            if expected {
                high = high.max(sequence);
                seen.insert(sequence);
                seen.retain(|value| high - *value < 1024);
            }
            assert_eq!(replay.highest(), high);
        }
    }

    #[test]
    fn rejected_frames_do_not_advance_client_replay() {
        let key = [9; 32];
        let mut codec = Codec::new(key);
        let valid = encode(&key, SERVER_TO_CLIENT, codec.flow, 10, b"reply").unwrap();
        let wrong_flow = encode(&key, SERVER_TO_CLIENT, codec.flow ^ 1, 10, b"reply").unwrap();
        assert!(codec.decode(&wrong_flow).is_none());
        let mut corrupt = valid.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(codec.decode(&corrupt).is_none());
        assert_eq!(codec.decode(&valid), Some(&b"reply"[..]));
        assert!(codec.decode(&valid).is_none());
    }

    #[test]
    fn failed_encode_does_not_consume_sequence_and_overflow_fails_closed() {
        let mut codec = Codec::new([1; 32]);
        let mut frame = Vec::new();
        assert!(codec.encode(&vec![0; MAX_PAYLOAD + 1], &mut frame).is_err());
        codec.encode(b"first", &mut frame).unwrap();
        assert_eq!(decode(&[1; 32], CLIENT_TO_SERVER, &frame).unwrap().1, 1);
        codec.sequence = u64::MAX;
        assert!(codec.encode(b"overflow", &mut frame).is_err());
        assert_eq!(codec.sequence, u64::MAX);
    }
}
