//! Проверки P2P на одном компьютере (без DHT): рукопожатие, надёжный поток на «плохой сети»,
//! весь стек сервера поверх P2P.

use super::*;
use crate::transport::{Datagrams, Stream};
use std::sync::mpsc::{channel, Receiver};

/// UDP-посредник, который портит связь: теряет `loss` пакетов, ещё 10 % дублирует,
/// 10 % задерживает на 30 мс (перестановка). Первый отправитель считается клиентом.
fn bad_network(target: SocketAddr, loss: f64) -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
    let addr = s.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut client: Option<SocketAddr> = None;
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % 10_000) as f64 / 10_000.0
        };
        let mut delayed: Vec<(Instant, Vec<u8>, SocketAddr)> = Vec::new();
        let mut buf = [0u8; 2048];
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(60) {
            if let Ok((n, from)) = s.recv_from(&mut buf) {
                let dest = if from == target {
                    match client {
                        Some(c) => c,
                        None => continue,
                    }
                } else {
                    client = Some(from);
                    target
                };
                let r = rnd();
                let p = buf[..n].to_vec();
                if r < loss {
                } else if r < loss + 0.1 {
                    let _ = s.send_to(&p, dest);
                    let _ = s.send_to(&p, dest);
                } else if r < loss + 0.2 {
                    delayed.push((Instant::now() + Duration::from_millis(30), p, dest));
                } else {
                    let _ = s.send_to(&p, dest);
                }
            }
            let now = Instant::now();
            delayed.retain(|(at, p, d)| {
                if *at <= now {
                    let _ = s.send_to(p, d);
                    false
                } else {
                    true
                }
            });
        }
    });
    addr
}

fn host(room: &Room) -> (Arc<Host>, Receiver<Arc<Flow>>) {
    let (tx, rx) = channel();
    let tx = Mutex::new(tx);
    let h = Host::start(room.clone(), 0, false, Box::new(move |f| {
        let _ = tx.lock().unwrap().send(f);
    }))
    .unwrap();
    (h, rx)
}

fn local(h: &Host) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], h.port()))
}

fn read_exact(s: &dyn Stream, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(30);
    while out.len() < len {
        assert!(Instant::now() < deadline, "получено только {} из {len}", out.len());
        match s.recv(&mut buf) {
            Ok(0) => panic!("поток закрыт, получено {} из {len}", out.len()),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
    }
    out
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + seed as usize) % 251) as u8).collect()
}

#[test]
fn stream_survives_bad_network() {
    let room = Room::new(Room::generate());
    let (h, flows) = host(&room);
    let via = bad_network(local(&h), 0.2);
    let conn = dial(&room, &[via], false, Duration::from_secs(10), &|_| {}).expect("рукопожатие через плохую сеть");
    let server_side = flows.recv_timeout(Duration::from_secs(5)).unwrap();
    server_side.set_timeout(Duration::from_secs(30));
    Stream::set_timeout(&conn, Duration::from_secs(30));

    let up = pattern(200_000, 1);
    let down = pattern(150_000, 2);
    let c = std::thread::spawn({
        let up = up.clone();
        let conn = Arc::new(conn);
        move || {
            conn.send_all(&up).unwrap();
            let got = read_exact(conn.as_ref(), 150_000);
            (conn, got)
        }
    });
    let got_up = read_exact(server_side.as_ref(), up.len());
    assert!(got_up == up, "данные клиент → сервер искажены");
    server_side.send_all(&down).unwrap();
    let (conn, got_down) = c.join().unwrap();
    assert!(got_down == down, "данные сервер → клиент искажены");

    // Датаграммы: доходят без повторов (часть теряется — это нормально для голоса).
    for i in 0..100u8 {
        Datagrams::send(conn.as_ref(), &[i; 40]).unwrap();
    }
    let mut got = 0;
    let mut buf = [0u8; 64];
    while let Ok(n) = Datagrams::recv(server_side.as_ref(), &mut buf) {
        assert_eq!(n, 40);
        got += 1;
    }
    assert!((60..=120).contains(&got), "дошло датаграмм: {got}");
    h.stop();
}

#[test]
fn wrong_room_gets_no_answer() {
    let room = Room::new(Room::generate());
    let (h, flows) = host(&room);
    let stranger = Room::new(Room::generate());
    let r = dial(&stranger, &[local(&h)], false, Duration::from_millis(1500), &|_| {});
    assert!(r.is_err(), "сервер ответил на чужой код");
    assert!(flows.try_recv().is_err());
    h.stop();
}

#[test]
fn close_is_seen_by_peer() {
    let room = Room::new(Room::generate());
    let (h, flows) = host(&room);
    let conn = dial(&room, &[local(&h)], false, Duration::from_secs(5), &|_| {}).unwrap();
    let server_side = flows.recv_timeout(Duration::from_secs(5)).unwrap();
    drop(conn);
    server_side.set_timeout(Duration::from_secs(3));
    let mut buf = [0u8; 16];
    assert_eq!(Stream::recv(server_side.as_ref(), &mut buf).unwrap(), 0, "сервер не увидел закрытия");
    h.stop();
}

/// Весь стек: встроенный сервер с P2P, клиент по коду приглашения и обычный клиент по TCP.
#[test]
fn server_over_p2p() {
    use crate::net::{build_voice_packet, Link, LinkEvent, LinkHandler};
    use crate::server::{P2pSettings, Server, Settings};

    struct Probe(Mutex<std::sync::mpsc::Sender<(u32, u64, Option<u32>)>>);
    impl LinkHandler for Probe {
        fn on_voice(&self, session: u32, seq: u64, _opus: &[u8], _last: bool) {
            let _ = self.0.lock().unwrap().send((session, seq, None));
        }
        fn on_event(&self, ev: LinkEvent) {
            match ev {
                LinkEvent::Synced { session, .. } => {
                    let _ = self.0.lock().unwrap().send((0, 0, Some(session)));
                }
                LinkEvent::Rejected { kind, .. } => panic!("отказ {kind}"),
                _ => {}
            }
        }
    }
    let probe = || {
        let (tx, rx) = channel();
        (Arc::new(Probe(Mutex::new(tx))), rx)
    };
    let synced = |rx: &Receiver<(u32, u64, Option<u32>)>| loop {
        match rx.recv_timeout(Duration::from_secs(8)).expect("вход") {
            (_, _, Some(s)) => break s,
            _ => {}
        }
    };

    let secret = Room::generate();
    let dir = std::env::temp_dir().join(format!("raciya-p2p-test-{}", std::process::id()));
    let settings = Settings {
        port: 0,
        password: "pw".into(),
        p2p: Some(P2pSettings { secret, port: 0, dht: false }),
        ..Settings::default()
    };
    let server = Server::start(settings, dir, Box::new(|| {})).expect("сервер");
    let p2p_port = server.p2p_port().expect("P2P запущен");
    let hint = SocketAddr::from(([127, 0, 0, 1], p2p_port));

    let conn = dial(&Room::new(secret), &[hint], false, Duration::from_secs(5), &|_| {}).expect("P2P");
    let (pa, ra) = probe();
    let a = Link::connect_p2p(Arc::new(conn), server.fingerprint_prefix(), "p2p-user", "pw", pa).unwrap();
    let sa = synced(&ra);
    let (pb, rb) = probe();
    let b = Link::connect("127.0.0.1", server.port(), "tcp-user", "pw", pb).unwrap();
    let sb = synced(&rb);
    let users: Vec<(String, bool)> = server.users().into_iter().map(|u| (u.name, u.udp)).collect();
    assert_eq!(users.len(), 2, "{users:?}");

    // Ждём, пока у обоих заработает голосовой канал (ответ на UDP ping).
    let deadline = Instant::now() + Duration::from_secs(8);
    while !(a.udp_active() && b.udp_active()) {
        assert!(Instant::now() < deadline, "голосовой канал не заработал: p2p={} tcp={}", a.udp_active(), b.udp_active());
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut pkt = Vec::new();
    for seq in 0..100u64 {
        build_voice_packet(&mut pkt, seq, &[1, 2, 3], seq == 99);
        a.send_voice(&pkt);
        b.send_voice(&pkt);
        std::thread::sleep(Duration::from_millis(2));
    }
    let count = |rx: &Receiver<(u32, u64, Option<u32>)>, from: u32| {
        let mut n = 0;
        while let Ok((s, _, None)) = rx.recv_timeout(Duration::from_millis(500)) {
            if s == from {
                n += 1;
            }
        }
        n
    };
    let at_b = count(&rb, sa);
    let at_a = count(&ra, sb);
    assert_eq!(at_b, 100, "от P2P-участника дошло {at_b} из 100");
    assert_eq!(at_a, 100, "P2P-участнику дошло {at_a} из 100");

    // Подменённый сервер (другой отпечаток) клиент не принимает.
    let conn = dial(&Room::new(secret), &[hint], false, Duration::from_secs(5), &|_| {}).unwrap();
    let (pc, rc) = probe();
    let _c = Link::connect_p2p(Arc::new(conn), [0xEE; 16], "mallory", "pw", pc).unwrap();
    assert!(rc.recv_timeout(Duration::from_secs(3)).is_err(), "вход при чужом отпечатке");
    server.stop();
}
