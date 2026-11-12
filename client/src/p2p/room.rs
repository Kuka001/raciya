//! «Комната» P2P: секрет сервера и всё, что из него выводится, плюс код приглашения v2.
//!
//! Секрет (16 случайных байт) создаёт сервер; он попадает к друзьям только в коде приглашения.
//! Из него выводятся:
//! - `ih_srv` — ключ в DHT, под которым сервер публикует свой внешний адрес;
//! - `ih_cli` — ключ, под которым клиенты сообщают свои адреса (сервер «стучится» им навстречу);
//! - `k_auth` — ключ HMAC пакетов рукопожатия: без кода приглашения сервер не ответит вообще.
//!
//! Код приглашения: `raciya:<ключ>[;lan=адрес,...][;zt=сеть@адрес]`, где ключ — base32 от
//! секрета, первых 16 байт отпечатка сертификата сервера и контрольного байта.

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use std::net::SocketAddr;

pub const PREFIX: &str = "raciya:";

#[derive(Clone)]
pub struct Room {
    pub secret: [u8; 16],
    pub ih_srv: [u8; 20],
    pub ih_cli: [u8; 20],
    k_auth: hmac::Key,
}

fn derive(secret: &[u8; 16], label: &str) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&k, label.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

impl Room {
    pub fn new(secret: [u8; 16]) -> Room {
        let mut ih_srv = [0u8; 20];
        ih_srv.copy_from_slice(&derive(&secret, "raciya/dht-server/v1")[..20]);
        let mut ih_cli = [0u8; 20];
        ih_cli.copy_from_slice(&derive(&secret, "raciya/dht-clients/v1")[..20]);
        let k_auth = hmac::Key::new(hmac::HMAC_SHA256, &derive(&secret, "raciya/auth/v1"));
        Room { secret, ih_srv, ih_cli, k_auth }
    }

    pub fn generate() -> [u8; 16] {
        let mut s = [0u8; 16];
        SystemRandom::new().fill(&mut s).expect("random");
        s
    }

    pub fn mac(&self, data: &[u8]) -> [u8; 16] {
        let tag = hmac::sign(&self.k_auth, data);
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag.as_ref()[..16]);
        out
    }

    /// Сравнение за постоянное время.
    pub fn check(&self, data: &[u8], mac: &[u8]) -> bool {
        let expect = self.mac(data);
        mac.len() == 16 && expect.iter().zip(mac).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
    }
}

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

pub fn base32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn unbase32(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in text.chars().filter(|c| !matches!(c, '-' | ' ')) {
        let v = ALPHABET.iter().position(|&a| a as char == c.to_ascii_lowercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

fn check_byte(data: &[u8]) -> u8 {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref()[0]
}

/// Код приглашения v2.
#[derive(Clone, Debug, PartialEq)]
pub struct Invite {
    pub secret: [u8; 16],
    /// Первые 16 байт SHA-256 сертификата сервера: клиент проверяет, что попал именно туда.
    pub fingerprint: [u8; 16],
    /// Адреса сервера в локальной сети (P2P-порт) — если друг рядом, NAT пробивать не нужно.
    pub lan: Vec<SocketAddr>,
    /// Запасной путь: сеть ZeroTier и адрес сервера в ней (`сеть@адрес[:порт]`).
    pub zt: Option<String>,
}

impl Invite {
    pub fn encode(&self) -> String {
        let mut raw = Vec::with_capacity(33);
        raw.extend_from_slice(&self.secret);
        raw.extend_from_slice(&self.fingerprint);
        raw.push(check_byte(&raw));
        let mut s = format!("{PREFIX}{}", base32(&raw));
        if !self.lan.is_empty() {
            let lan: Vec<String> = self.lan.iter().map(|a| a.to_string()).collect();
            s.push_str(&format!(";lan={}", lan.join(",")));
        }
        if let Some(zt) = &self.zt {
            s.push_str(&format!(";zt={zt}"));
        }
        s
    }

    pub fn parse(text: &str) -> Option<Invite> {
        let t = text.trim();
        let rest = t.get(..PREFIX.len()).filter(|p| p.eq_ignore_ascii_case(PREFIX)).map(|_| &t[PREFIX.len()..])?;
        let mut parts = rest.split(';');
        let raw = unbase32(parts.next()?.trim())?;
        if raw.len() != 33 || check_byte(&raw[..32]) != raw[32] {
            return None;
        }
        let mut inv = Invite { secret: [0; 16], fingerprint: [0; 16], lan: Vec::new(), zt: None };
        inv.secret.copy_from_slice(&raw[..16]);
        inv.fingerprint.copy_from_slice(&raw[16..32]);
        for p in parts {
            match p.trim().split_once('=') {
                Some(("lan", v)) => inv.lan = v.split(',').filter_map(|a| a.trim().parse().ok()).collect(),
                Some(("zt", v)) if crate::system::parse_invite(v).map(|i| i.network.is_some()).unwrap_or(false) => {
                    inv.zt = Some(v.trim().to_string())
                }
                _ => {}
            }
        }
        Some(inv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(unbase32(&base32(&data)).unwrap(), data);
        }
        assert_eq!(base32(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn invite_roundtrip_and_typos() {
        let inv = Invite {
            secret: [7; 16],
            fingerprint: [9; 16],
            lan: vec!["192.168.0.15:41234".parse().unwrap()],
            zt: Some("33b5003c53a6763b@10.77.64.1".into()),
        };
        let code = inv.encode();
        assert!(code.starts_with("raciya:"));
        assert_eq!(Invite::parse(&code), Some(inv.clone()));
        assert_eq!(Invite::parse(&format!("  {}  ", code.to_uppercase().replacen("RACIYA:", "raciya:", 1))).map(|i| i.secret), Some(inv.secret));
        // Опечатка в ключе ловится контрольным байтом.
        let key_start = PREFIX.len();
        let mut broken: Vec<char> = code.chars().collect();
        broken[key_start + 3] = if broken[key_start + 3] == 'a' { 'b' } else { 'a' };
        assert!(Invite::parse(&broken.into_iter().collect::<String>()).is_none());
        assert!(Invite::parse("raciya:").is_none());
        assert!(Invite::parse("10.77.64.1").is_none());
        // Без дополнительных частей тоже работает.
        let bare = Invite { lan: vec![], zt: None, ..inv };
        assert_eq!(Invite::parse(&bare.encode()), Some(bare));
    }

    #[test]
    fn keys_differ_and_mac_checks() {
        let r = Room::new([1; 16]);
        assert_ne!(r.ih_srv, r.ih_cli);
        let m = r.mac(b"hello");
        assert!(r.check(b"hello", &m));
        assert!(!r.check(b"hellp", &m));
        assert!(!Room::new([2; 16]).check(b"hello", &m));
    }
}
