//! Проверки встроенного сервера с настоящим клиентом (`net::Link`) через 127.0.0.1.
//! Звуковые устройства не нужны: голосовые пакеты собираются вручную.

use super::{Server, Settings, StartError};
use crate::net::{build_voice_packet, Link, LinkEvent, LinkHandler};
use crate::proto;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

enum Seen {
    Synced(u32),
    User { session: u32, name: Option<String>, self_mute: Option<bool> },
    Removed(u32),
    Rejected(i32),
    Ping { udp: bool },
    Closed,
    Voice { session: u32, seq: u64, data: Vec<u8> },
}

struct Probe {
    tx: Mutex<Sender<Seen>>,
}

impl LinkHandler for Probe {
    fn on_voice(&self, session: u32, seq: u64, opus: &[u8], _last: bool) {
        let _ = self.tx.lock().unwrap().send(Seen::Voice { session, seq, data: opus.to_vec() });
    }

    fn on_event(&self, ev: LinkEvent) {
        let s = match ev {
            LinkEvent::Synced { session, .. } => Seen::Synced(session),
            LinkEvent::UserState(u) => Seen::User { session: u.session.unwrap_or(0), name: u.name, self_mute: u.self_mute },
            LinkEvent::UserRemove { session, .. } => Seen::Removed(session),
            LinkEvent::Rejected { kind, .. } => Seen::Rejected(kind),
            LinkEvent::Ping { udp, .. } => Seen::Ping { udp },
            LinkEvent::Closed(_) => Seen::Closed,
            _ => return,
        };
        let _ = self.tx.lock().unwrap().send(s);
    }
}

fn probe() -> (Arc<Probe>, Receiver<Seen>) {
    let (tx, rx) = channel();
    (Arc::new(Probe { tx: Mutex::new(tx) }), rx)
}

/// Ждёт событие, для которого `f` вернёт `Some`. Остальные события пропускаются.
fn wait<T>(rx: &Receiver<Seen>, what: &str, mut f: impl FnMut(&Seen) -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(ev) => {
                if let Some(v) = f(&ev) {
                    return v;
                }
            }
            Err(_) => panic!("не дождались: {what}"),
        }
    }
}

fn test_dir() -> std::path::PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let d = std::env::temp_dir().join(format!("raciya-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::create_dir_all(&d);
    d
}

fn start(max_users: u32) -> Arc<Server> {
    let settings = Settings { port: 0, password: "секрет".into(), max_users, welcome: "привет".into(), name: "Тест".into() };
    // Порт 0: TCP получает свободный порт, UDP пробует такой же; в редком случае он занят — повторяем.
    for _ in 0..5 {
        match Server::start(settings.clone(), test_dir(), Box::new(|| {})) {
            Ok(s) => return s,
            Err(StartError::InUse { .. }) | Err(StartError::Reserved { .. }) => continue,
            Err(e) => panic!("сервер не запустился: {e:?}"),
        }
    }
    panic!("не нашлось свободного порта");
}

/// Входит на сервер. Возвращает и участников, о которых сервер сообщил до `ServerSync`.
fn join_full(server: &Server, name: &str) -> (Arc<Link>, Receiver<Seen>, u32, Vec<(u32, String)>) {
    let (p, rx) = probe();
    let link = Link::connect("127.0.0.1", server.port(), name, "секрет", p).expect("connect");
    let mut users = Vec::new();
    let session = wait(&rx, "вход", |e| match e {
        Seen::Synced(s) => Some(*s),
        Seen::Rejected(k) => panic!("отказ {k}"),
        Seen::User { session, name: Some(n), .. } => {
            users.push((*session, n.clone()));
            None
        }
        _ => None,
    });
    (link, rx, session, users)
}

fn join(server: &Server, name: &str) -> (Arc<Link>, Receiver<Seen>, u32) {
    let (link, rx, session, _) = join_full(server, name);
    (link, rx, session)
}

fn wait_udp(rx: &Receiver<Seen>) {
    wait(rx, "UDP", |e| matches!(e, Seen::Ping { udp: true }).then_some(()));
}

fn send_frames(link: &Link, count: u64) {
    let mut pkt = Vec::new();
    for seq in 0..count {
        build_voice_packet(&mut pkt, seq, &[seq as u8, 0xAB, 0xCD], seq + 1 == count);
        link.send_voice(&pkt);
        if seq % 20 == 19 {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn receive_frames(rx: &Receiver<Seen>, from: u32, count: u64, within: Duration) -> Vec<u64> {
    let mut got = Vec::new();
    let deadline = Instant::now() + within;
    while (got.len() as u64) < count && Instant::now() < deadline {
        if let Ok(Seen::Voice { session, seq, data }) = rx.recv_timeout(Duration::from_millis(200)) {
            assert_eq!(session, from, "голос от чужой сессии");
            assert_eq!(data, vec![seq as u8, 0xAB, 0xCD], "данные искажены");
            got.push(seq);
        }
    }
    got
}

#[test]
fn two_clients_talk_over_udp() {
    let server = start(10);
    let (a, ra, sa, first) = join_full(&server, "alice");
    let (b, rb, sb, second) = join_full(&server, "bob");
    assert_ne!(sa, sb);
    // Каждый знает себя; второй получил первого в списке при входе, первый узнал о втором позже.
    assert!(first.contains(&(sa, "alice".into())), "alice не видит себя: {first:?}");
    assert!(second.contains(&(sa, "alice".into())) && second.contains(&(sb, "bob".into())), "bob видит: {second:?}");
    wait(&ra, "alice видит bob", |e| match e {
        Seen::User { session, name: Some(n), .. } if *session == sb && n == "bob" => Some(()),
        _ => None,
    });
    wait_udp(&ra);
    wait_udp(&rb);
    assert!(a.udp_active() && b.udp_active());

    send_frames(&a, 300);
    let mut got = receive_frames(&rb, sa, 300, Duration::from_secs(8));
    got.sort_unstable();
    assert_eq!(got, (0..300).collect::<Vec<u64>>(), "дошло {} из 300 кадров", got.len());

    // «Микрофон выключен» доходит до другого участника.
    a.send_self_state(true, false);
    wait(&rb, "self_mute alice", |e| match e {
        Seen::User { session, self_mute: Some(true), .. } if *session == sa => Some(()),
        _ => None,
    });
    // С выключенным микрофоном сервер голос не пересылает.
    send_frames(&a, 10);
    assert!(receive_frames(&rb, sa, 1, Duration::from_millis(800)).is_empty());

    assert_eq!(server.users().len(), 2);
    a.close();
    wait(&rb, "уход alice", |e| matches!(e, Seen::Removed(s) if *s == sa).then_some(()));
    server.stop();
}

#[test]
fn tcp_tunnel_when_udp_is_blocked() {
    let server = start(10);
    let (a, ra, sa) = join(&server, "alice");
    let (b, rb, sb) = join(&server, "bob");
    a.set_udp_disabled(true);
    wait_udp(&rb);
    // A говорит через туннель, B слышит (B — по UDP).
    send_frames(&a, 100);
    let got = receive_frames(&rb, sa, 100, Duration::from_secs(8));
    assert_eq!(got.len(), 100, "через туннель дошло {} из 100", got.len());
    // B говорит, A слышит через туннель (сервер видит, что A шлёт голос по TCP).
    send_frames(&b, 100);
    let got = receive_frames(&ra, sb, 100, Duration::from_secs(8));
    assert!(got.len() >= 95, "в туннель дошло {} из 100", got.len());
    server.stop();
}

#[test]
fn rejects() {
    let server = start(2);
    // Неверный пароль.
    let (p, rx) = probe();
    let _bad = Link::connect("127.0.0.1", server.port(), "mallory", "не тот", p).unwrap();
    let kind = wait(&rx, "отказ", |e| match e {
        Seen::Rejected(k) => Some(*k),
        Seen::Synced(_) => panic!("вошёл с неверным паролем"),
        _ => None,
    });
    assert_eq!(kind, proto::REJECT_WRONG_SERVER_PW);

    let (_a, _ra, _) = join(&server, "alice");
    let (_b, _rb, _) = join(&server, "bob");
    // Мест два — третьему отказ.
    let (p, rx) = probe();
    let _c = Link::connect("127.0.0.1", server.port(), "carol", "секрет", p).unwrap();
    let kind = wait(&rx, "сервер заполнен", |e| match e {
        Seen::Rejected(k) => Some(*k),
        Seen::Synced(_) => panic!("вошёл сверх мест"),
        _ => None,
    });
    assert_eq!(kind, proto::REJECT_SERVER_FULL);
    // Недопустимое имя.
    let (p, rx) = probe();
    let _d = Link::connect("127.0.0.1", server.port(), "   ", "секрет", p).unwrap();
    let kind = wait(&rx, "недопустимое имя", |e| match e {
        Seen::Rejected(k) => Some(*k),
        _ => None,
    });
    assert_eq!(kind, proto::REJECT_INVALID_USERNAME);
    server.stop();
}

#[test]
fn reconnect_with_same_name_replaces_old_session() {
    let server = start(10);
    let (_old, rold, s_old) = join(&server, "Alice");
    let (_bob, rbob, _) = join(&server, "bob");
    // Тот же человек с того же адреса после «обрыва»: имя совпадает без учёта регистра.
    let (_new, _rnew, s_new) = join(&server, "alice");
    assert_ne!(s_old, s_new);
    wait(&rold, "старая сессия закрыта", |e| matches!(e, Seen::Closed).then_some(()));
    wait(&rbob, "bob узнал об уходе старой сессии", |e| matches!(e, Seen::Removed(s) if *s == s_old).then_some(()));
    let names: Vec<String> = server.users().into_iter().map(|u| u.name).collect();
    assert_eq!(names.len(), 2, "участники: {names:?}");
    server.stop();
}

#[test]
fn port_in_use_is_reported() {
    let server = start(10);
    let again = Server::start(
        Settings { port: server.port(), ..Settings::default() },
        test_dir(),
        Box::new(|| {}),
    );
    match again {
        Err(StartError::InUse { port, .. }) => assert_eq!(port, server.port()),
        Err(e) => panic!("ожидали «порт занят», получили {e:?}"),
        Ok(_) => panic!("второй сервер занял тот же порт"),
    }
    server.stop();
    // После остановки порт свободен.
    std::thread::sleep(Duration::from_millis(300));
    let third = Server::start(Settings { port: server.port(), ..Settings::default() }, test_dir(), Box::new(|| {}));
    assert!(third.is_ok(), "порт не освободился: {:?}", third.err());
}

#[test]
fn certificate_is_kept() {
    let dir = test_dir();
    let a = Server::start(Settings { port: 0, ..Settings::default() }, dir.clone(), Box::new(|| {})).unwrap();
    let fp = a.fingerprint().to_string();
    a.stop();
    let b = Server::start(Settings { port: 0, ..Settings::default() }, dir, Box::new(|| {})).unwrap();
    assert_eq!(b.fingerprint(), fp, "сертификат должен сохраняться между запусками");
    assert_eq!(fp.len(), 64);
    b.stop();
}
