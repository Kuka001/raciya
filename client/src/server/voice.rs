//! Голос: приём UDP, расшифровка, пересылка остальным участникам.
//!
//! Формат («классический», протокол 1.4): первый байт — тип (3 бита) и цель (5 бит).
//! От клиента: `[тип|цель][varint номер][opus...]`; клиентам: `[тип|0][varint сессия][varint номер][opus...]`.
//! Тип 1 — ping, сервер возвращает его как есть. Тип 4 — Opus. Цель 0 — всем, 31 — себе (проверка),
//! 1–30 — шёпот (не поддерживается, отбрасывается).

use super::{Client, Shared};
use crate::proto::T_CRYPTSETUP;
use crate::varint::write_varint;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Самый длинный голосовой пакет, который пересылает сервер.
const MAX_VOICE: usize = 1024;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Via {
    Udp,
    Tcp,
}

/// Пакет для остальных: вставляет номер сессии отправителя после первого байта.
pub(crate) fn rewrite(plain: &[u8], session: u32, out: &mut Vec<u8>) {
    out.clear();
    out.push(plain[0] & 0xE0);
    write_varint(out, session as u64);
    out.extend_from_slice(&plain[1..]);
}

pub(crate) fn handle(sh: &Shared, from: &Arc<Client>, plain: &[u8], via: Via) {
    if plain.is_empty() || plain.len() > MAX_VOICE {
        return;
    }
    let kind = plain[0] >> 5;
    let target = plain[0] & 0x1F;
    match kind {
        1 => match via {
            Via::Udp => send_udp(sh, from, plain),
            Via::Tcp => from.send_tunnel(plain),
        },
        4 => {
            if !from.rate.lock().unwrap().allow() {
                return;
            }
            if from.self_mute.load(Ordering::Relaxed) || from.self_deaf.load(Ordering::Relaxed) {
                return;
            }
            let mut out = Vec::with_capacity(plain.len() + 5);
            rewrite(plain, from.session, &mut out);
            match target {
                0 => {
                    let targets: Vec<Arc<Client>> = {
                        let st = sh.state.lock().unwrap();
                        st.clients
                            .values()
                            .filter(|c| c.session != from.session && !c.self_deaf.load(Ordering::Relaxed))
                            .cloned()
                            .collect()
                    };
                    for t in targets {
                        deliver(sh, &t, &out);
                    }
                }
                31 => deliver(sh, from, &out),
                _ => {}
            }
        }
        _ => {}
    }
}

fn deliver(sh: &Shared, to: &Client, plain: &[u8]) {
    if to.udp_ok.load(Ordering::Relaxed) {
        let addr = *to.udp_addr.lock().unwrap();
        if let Some(addr) = addr {
            send_udp_to(sh, to, addr, plain);
            return;
        }
    }
    to.send_tunnel(plain);
}

fn send_udp(sh: &Shared, to: &Client, plain: &[u8]) {
    let addr = *to.udp_addr.lock().unwrap();
    if let Some(addr) = addr {
        send_udp_to(sh, to, addr, plain);
    }
}

fn send_udp_to(sh: &Shared, to: &Client, addr: SocketAddr, plain: &[u8]) {
    let mut buf = [0u8; MAX_VOICE + 16];
    if plain.len() + 4 > buf.len() {
        return;
    }
    let n = to.crypt.lock().unwrap().encrypt(plain, &mut buf);
    if n > 0 {
        sh.udp.send_to(&buf[..n], addr);
    }
}

pub(crate) fn udp_loop(sh: Arc<Shared>) {
    let mut buf = [0u8; 2048];
    let mut plain = [0u8; 2048];
    while !sh.stop.load(Ordering::SeqCst) {
        let (n, addr) = match sh.udp.recv_from(&mut buf) {
            Some(Ok(x)) => x,
            Some(Err(_)) => continue,
            None => break,
        };
        // 4 байта заголовка шифрования + хотя бы 1 байт данных.
        if !(5..=1500).contains(&n) {
            continue;
        }
        let known = {
            let st = sh.state.lock().unwrap();
            st.by_udp.get(&addr).and_then(|s| st.clients.get(s)).cloned()
        };
        let client = match known {
            Some(c) => {
                if !c.crypt.lock().unwrap().decrypt(&buf[..n], &mut plain[..n - 4]) {
                    request_resync(&sh, &c);
                    continue;
                }
                c
            }
            None => match bind_by_trial(&sh, addr, &buf[..n], &mut plain) {
                Some(c) => c,
                None => continue,
            },
        };
        client.udp_ok.store(true, Ordering::Relaxed);
        client.last_udp_good_ms.store(sh.now_ms(), Ordering::Relaxed);
        handle(&sh, &client, &plain[..n - 4], Via::Udp);
    }
}

/// Пакет с нового адреса: пробуем ключи участников с тем же IP (как Murmur).
/// Так узнаём, с какого UDP-порта говорит участник, даже за NAT.
fn bind_by_trial(sh: &Shared, addr: SocketAddr, data: &[u8], plain: &mut [u8]) -> Option<Arc<Client>> {
    let candidates: Vec<Arc<Client>> = {
        let st = sh.state.lock().unwrap();
        st.clients
            .values()
            .filter(|c| c.peer.ip() == addr.ip() && !c.dead.load(Ordering::Relaxed))
            .cloned()
            .collect()
    };
    for c in candidates {
        if c.crypt.lock().unwrap().decrypt(data, &mut plain[..data.len() - 4]) {
            let mut st = sh.state.lock().unwrap();
            let old = c.udp_addr.lock().unwrap().replace(addr);
            if let Some(old) = old {
                if st.by_udp.get(&old) == Some(&c.session) {
                    st.by_udp.remove(&old);
                }
            }
            st.by_udp.insert(addr, c.session);
            return Some(c);
        }
    }
    None
}

/// Пакеты от участника перестали расшифровываться: счётчики разошлись. Просим у клиента его
/// счётчик, но не чаще раза в 5 секунд и только если хороших пакетов давно не было.
fn request_resync(sh: &Shared, c: &Client) {
    let now = sh.now_ms();
    if now.saturating_sub(c.last_udp_good_ms.load(Ordering::Relaxed)) < 5000 {
        return;
    }
    if now.saturating_sub(c.last_resync_req_ms.load(Ordering::Relaxed)) < 5000 {
        return;
    }
    c.last_resync_req_ms.store(now, Ordering::Relaxed);
    c.send(crate::framing::frame_msg(T_CRYPTSETUP, &crate::proto::CryptSetup::default()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::read_varint;

    #[test]
    fn rewrite_inserts_session() {
        // Пакет клиента: Opus, цель 0, номер 300, длина 3 с признаком конца, данные.
        let mut pkt = Vec::new();
        crate::net::build_voice_packet(&mut pkt, 300, &[9, 8, 7], true);
        let mut out = Vec::new();
        rewrite(&pkt, 4242, &mut out);
        assert_eq!(out[0], 4 << 5);
        let mut pos = 1;
        assert_eq!(read_varint(&out, &mut pos), Some(4242));
        // Остаток — байт в байт как у отправителя.
        assert_eq!(&out[pos..], &pkt[1..]);
        // Цель «себе» (31) превращается в обычную речь.
        let mut loopback = pkt.clone();
        loopback[0] |= 31;
        rewrite(&loopback, 1, &mut out);
        assert_eq!(out[0], 4 << 5);
    }
}
