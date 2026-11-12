//! «Комната» P2P: секрет сервера и всё, что из него выводится, плюс код приглашения v2.
//!
//! Секрет (16 случайных байт) создаёт сервер; он попадает к друзьям только в коде приглашения.
//! Из него выводятся:
//! - ключ подписи Ed25519 для записей в DHT (BEP 44): сервер публикует свой адрес, клиент —
//!   просьбу «постучаться»; подложные записи отбрасываются по подписи;
//! - `ih_srv` — запасной ключ, под которым сервер ещё и анонсирует адрес обычным `announce_peer`;
//! - `k_auth` — ключ HMAC пакетов рукопожатия: без кода приглашения сервер не ответит вообще.
//!
//! Код приглашения: `raciya:<ключ>[;lan=адрес,...][;zt=сеть@адрес]`, где ключ — base32 от
//! секрета, первых 16 байт отпечатка сертификата сервера и контрольного байта.

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use std::net::SocketAddr;

pub const PREFIX: &str = "raciya:";

#[derive(Clone)]
pub struct Room {
    pub ih_srv: [u8; 20],
    k_auth: hmac::Key,
    /// Ключ подписи записей в DHT (BEP 44): одинаковый у всех, кто знает код приглашения.
    item_seed: [u8; 32],
    pub item_public: [u8; 32],
}

/// Записи в DHT (BEP 44, изменяемые элементы): сервер публикует свой адрес, клиент — просьбу
/// «постучаться» навстречу. Подписаны ключом комнаты: подложные записи отбрасываются.
pub const SALT_SERVER: &[u8] = b"raciya-srv";
pub const SALT_KNOCK: &[u8] = b"raciya-cli";

/// Ключ записи в DHT: SHA-1(открытый ключ ‖ соль).
pub fn item_target(public: &[u8; 32], salt: &[u8]) -> [u8; 20] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(public);
    ctx.update(salt);
    let mut out = [0u8; 20];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// Что подписывается по BEP 44: `4:salt<len>:<salt>3:seqi<seq>e1:v<bencode(v)>`.
pub fn item_signable(salt: &[u8], seq: i64, v: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + salt.len() + v.len());
    if !salt.is_empty() {
        m.extend_from_slice(format!("4:salt{}:", salt.len()).as_bytes());
        m.extend_from_slice(salt);
    }
    m.extend_from_slice(format!("3:seqi{seq}e1:v").as_bytes());
    m.extend_from_slice(v);
    m
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
        let k_auth = hmac::Key::new(hmac::HMAC_SHA256, &derive(&secret, "raciya/auth/v1"));
        let item_seed = derive(&secret, "raciya/bep44/v1");
        let kp = Ed25519KeyPair::from_seed_unchecked(&item_seed).expect("ed25519 seed");
        let mut item_public = [0u8; 32];
        item_public.copy_from_slice(kp.public_key().as_ref());
        Room { ih_srv, k_auth, item_seed, item_public }
    }

    pub fn item_target(&self, salt: &[u8]) -> [u8; 20] {
        item_target(&self.item_public, salt)
    }

    pub fn sign_item(&self, salt: &[u8], seq: i64, v: &[u8]) -> [u8; 64] {
        let kp = Ed25519KeyPair::from_seed_unchecked(&self.item_seed).expect("ed25519 seed");
        let sig = kp.sign(&item_signable(salt, seq, v));
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }

    /// Подпись записи из DHT сделана ключом этой комнаты.
    pub fn verify_item(&self, salt: &[u8], seq: i64, v: &[u8], k: &[u8], sig: &[u8]) -> bool {
        k == self.item_public
            && UnparsedPublicKey::new(&ED25519, &self.item_public).verify(&item_signable(salt, seq, v), sig).is_ok()
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
    fn signed_items() {
        let r = Room::new([5; 16]);
        let v = b"d1:e6:abcdefe";
        let sig = r.sign_item(SALT_KNOCK, 42, v);
        assert!(r.verify_item(SALT_KNOCK, 42, v, &r.item_public, &sig));
        assert!(!r.verify_item(SALT_KNOCK, 43, v, &r.item_public, &sig));
        assert!(!r.verify_item(SALT_SERVER, 42, v, &r.item_public, &sig));
        assert!(!Room::new([6; 16]).verify_item(SALT_KNOCK, 42, v, &r.item_public, &sig));
        assert_ne!(r.item_target(SALT_KNOCK), r.item_target(SALT_SERVER));
        // Формат подписываемой строки — как в примере BEP 44.
        assert_eq!(item_signable(b"foobar", 4, b"12:Hello World!"), b"4:salt6:foobar3:seqi4e1:v12:Hello World!".to_vec());
    }

    #[test]
    fn keys_differ_and_mac_checks() {
        let r = Room::new([1; 16]);
        assert_ne!(r.ih_srv[..], r.item_target(SALT_SERVER)[..]);
        let m = r.mac(b"hello");
        assert!(r.check(b"hello", &m));
        assert!(!r.check(b"hellp", &m));
        assert!(!Room::new([2; 16]).check(b"hello", &m));
    }
}
