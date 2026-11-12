//! STUN (RFC 5389): узнать, каким адресом и портом наш UDP-сокет виден из интернета.
//! Если два разных сервера видят один и тот же порт — NAT «пробиваемый» (EIM).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const MAGIC: u32 = 0x2112_A442;

pub const SERVERS: [&str; 3] = ["stun.l.google.com:19302", "stun.cloudflare.com:3478", "stun1.l.google.com:19302"];

pub fn request(tid: &[u8; 12]) -> [u8; 20] {
    let mut p = [0u8; 20];
    p[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
    p[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    p[8..20].copy_from_slice(tid);
    p
}

/// Похож ли пакет на ответ STUN (по нему решается, куда его отдать).
pub fn is_stun(p: &[u8]) -> bool {
    p.len() >= 20 && p[0] < 0x40 && p[4..8] == MAGIC.to_be_bytes()
}

pub fn transaction(p: &[u8]) -> Option<[u8; 12]> {
    p.get(8..20)?.try_into().ok()
}

/// Внешний адрес из успешного ответа (XOR-MAPPED-ADDRESS, иначе MAPPED-ADDRESS).
pub fn mapped(p: &[u8]) -> Option<SocketAddr> {
    if !is_stun(p) || u16::from_be_bytes([p[0], p[1]]) != 0x0101 {
        return None;
    }
    let len = u16::from_be_bytes([p[2], p[3]]) as usize;
    let body = p.get(20..20 + len)?;
    let mut pos = 0;
    let mut plain = None;
    while pos + 4 <= body.len() {
        let ty = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let alen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        let v = body.get(pos + 4..pos + 4 + alen)?;
        if v.len() >= 8 && v[1] == 0x01 {
            let port = u16::from_be_bytes([v[2], v[3]]);
            let ip = u32::from_be_bytes([v[4], v[5], v[6], v[7]]);
            match ty {
                0x0020 => {
                    let port = port ^ (MAGIC >> 16) as u16;
                    let ip = Ipv4Addr::from(ip ^ MAGIC);
                    return Some(SocketAddr::new(IpAddr::V4(ip), port));
                }
                0x0001 => plain = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)),
                _ => {}
            }
        }
        pos += 4 + alen.div_ceil(4) * 4;
    }
    plain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_mapped_address() {
        let tid = [3u8; 12];
        let mut r = vec![0x01, 0x01, 0x00, 0x0C];
        r.extend_from_slice(&MAGIC.to_be_bytes());
        r.extend_from_slice(&tid);
        // XOR-MAPPED-ADDRESS 82.115.59.120:60635
        let port: u16 = 60635 ^ (MAGIC >> 16) as u16;
        let ip: u32 = u32::from(Ipv4Addr::new(82, 115, 59, 120)) ^ MAGIC;
        r.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
        r.extend_from_slice(&port.to_be_bytes());
        r.extend_from_slice(&ip.to_be_bytes());
        assert!(is_stun(&r));
        assert_eq!(transaction(&r), Some(tid));
        assert_eq!(mapped(&r), Some("82.115.59.120:60635".parse().unwrap()));
        assert!(!is_stun(&request(&tid)[..10]));
    }
}
