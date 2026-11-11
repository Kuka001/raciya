//! Одно соединение участника: TLS, вход, управляющие сообщения.

use super::{voice, Client, Rate, Shared, MAX_BANDWIDTH, PERMISSIONS};
use crate::framing::{frame_msg, Deframer};
use crate::ocb2::CryptState;
use crate::proto::*;
use prost::Message;
use ring::rand::SecureRandom;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Самое длинное управляющее сообщение, которое примет сервер.
const MAX_MESSAGE: usize = 64 * 1024;
/// Время на TLS и вход.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);
/// Клиенты шлют ping раз в 5 секунд; тишина дольше — обрыв.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_TEXT: usize = 5000;

/// Транспорт управляющего канала: сейчас TCP, в будущем — P2P-поток.
pub(crate) trait Wire: Send + Sync + 'static {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn send_all(&self, buf: &[u8]) -> io::Result<()>;
    fn set_timeout(&self, t: Duration);
    fn close(&self);
}

impl Wire for TcpStream {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self).read(buf)
    }

    fn send_all(&self, buf: &[u8]) -> io::Result<()> {
        (&*self).write_all(buf)
    }

    fn set_timeout(&self, t: Duration) {
        let _ = self.set_read_timeout(Some(t));
    }

    fn close(&self) {
        let _ = self.shutdown(Shutdown::Both);
    }
}

struct WireWriter<'a>(&'a dyn Wire);

impl Write for WireWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.send_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// TLS поверх транспорта. Читает один поток, пишут несколько (под замком).
pub(crate) struct Pipe {
    tls: Mutex<rustls::ServerConnection>,
    wire: Box<dyn Wire>,
}

impl Pipe {
    fn flush(&self, tls: &mut rustls::ServerConnection) -> io::Result<()> {
        let mut w = WireWriter(self.wire.as_ref());
        while tls.wants_write() {
            tls.write_tls(&mut w)?;
        }
        Ok(())
    }

    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        let mut tls = self.tls.lock().unwrap();
        tls.writer().write_all(data)?;
        self.flush(&mut tls)
    }

    /// Одно чтение из сети: расшифрованное попадает в `out`. `Ok(false)` — соединение закрыто.
    fn pump(&self, raw: &mut [u8], out: &mut Deframer) -> io::Result<bool> {
        let n = self.wire.recv(raw)?;
        if n == 0 {
            return Ok(false);
        }
        let mut tls = self.tls.lock().unwrap();
        let mut rd = &raw[..n];
        let mut tmp = [0u8; 4096];
        while !rd.is_empty() {
            tls.read_tls(&mut rd)?;
            tls.process_new_packets().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            loop {
                match tls.reader().read(&mut tmp) {
                    Ok(0) => return Ok(false),
                    Ok(k) => out.push(&tmp[..k]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }
        self.flush(&mut tls)?;
        Ok(true)
    }

    pub fn close(&self) {
        self.wire.close();
    }
}

fn server_version() -> Version {
    Version {
        version_v1: Some(PROTOCOL_VERSION),
        release: Some(format!("Raciya {}", env!("CARGO_PKG_VERSION"))),
        os: Some("Windows".into()),
        os_version: None,
        version_v2: None,
    }
}

fn reject(pipe: &Pipe, kind: i32, reason: &str) {
    let _ = pipe.send(&frame_msg(T_REJECT, &Reject { kind: Some(kind), reason: Some(reason.into()) }));
}

fn deny(c: &Client, reason: &str) {
    c.send(frame_msg(
        T_PERMISSIONDENIED,
        &PermissionDenied { reason: Some(reason.into()), kind: Some(0), ..Default::default() },
    ));
}

/// Обслуживает соединение от начала до конца.
pub(crate) fn serve(sh: &Arc<Shared>, stream: TcpStream, peer: SocketAddr) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    stream.set_timeout(LOGIN_TIMEOUT);
    let Ok(conn) = rustls::ServerConnection::new(sh.tls.clone()) else { return };
    let pipe = Arc::new(Pipe { tls: Mutex::new(conn), wire: Box::new(stream) });
    // Сервер представляется первым (rustls придержит данные до конца рукопожатия).
    if pipe.send(&frame_msg(T_VERSION, &server_version())).is_err() {
        return;
    }

    let mut raw = vec![0u8; 16 * 1024];
    let mut frames = Deframer::new(MAX_MESSAGE);
    let deadline = Instant::now() + LOGIN_TIMEOUT;
    let auth = 'login: loop {
        if Instant::now() > deadline {
            return;
        }
        match pipe.pump(&mut raw, &mut frames) {
            Ok(true) => {}
            _ => return,
        }
        loop {
            match frames.next() {
                Ok(Some((T_AUTHENTICATE, body))) => match Authenticate::decode(body) {
                    Ok(a) => break 'login a,
                    Err(_) => return,
                },
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => return,
            }
        }
    };

    let (tx, rx) = sync_channel::<Vec<u8>>(256);
    let mut key = [0u8; 16];
    let mut client_nonce = [0u8; 16];
    let mut server_nonce = [0u8; 16];
    if sh.rng.fill(&mut key).is_err() || sh.rng.fill(&mut client_nonce).is_err() || sh.rng.fill(&mut server_nonce).is_err() {
        return;
    }
    // Сервер шифрует своим счётчиком (server_nonce), расшифровывает счётчиком клиента.
    let Some(crypt) = CryptState::new(&key, &server_nonce, &client_nonce) else { return };

    let name = auth.username.clone().unwrap_or_default().trim().to_string();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(|c| c.is_control()) {
        reject(&pipe, REJECT_INVALID_USERNAME, "недопустимое имя");
        return;
    }
    {
        let rt = sh.runtime.read().unwrap();
        if let Some(tag) = &rt.password_tag {
            let given = auth.password.clone().unwrap_or_default();
            if ring::hmac::verify(&rt.password_key, given.as_bytes(), tag).is_err() {
                drop(rt);
                let banned = sh.guard.lock().unwrap().failed(peer.ip(), Instant::now());
                slog!("{peer}: неверный пароль (имя «{name}»){}", if banned { " — адрес заблокирован на 5 минут" } else { "" });
                reject(&pipe, REJECT_WRONG_SERVER_PW, "неверный пароль сервера");
                return;
            }
        }
    }
    sh.guard.lock().unwrap().succeeded(peer.ip());

    // Регистрация участника. Под замком: проверка имени и мест, выдача номера, первые сообщения.
    let lower = name.to_lowercase();
    let (client, kicked) = {
        let max_users = sh.runtime.read().unwrap().max_users;
        let mut st = sh.state.lock().unwrap();
        let mut kicked = None;
        if let Some(old) = st.clients.values().find(|o| o.name.to_lowercase() == lower).cloned() {
            if old.peer.ip() == peer.ip() {
                // Тот же человек переподключается после обрыва: прежняя сессия уже не нужна.
                st.clients.remove(&old.session);
                if let Some(a) = *old.udp_addr.lock().unwrap() {
                    st.by_udp.remove(&a);
                }
                kicked = Some(old);
            } else {
                drop(st);
                slog!("{peer}: имя «{name}» уже занято");
                reject(&pipe, REJECT_USERNAME_IN_USE, "это имя уже занято");
                return;
            }
        }
        if st.clients.len() as u32 >= max_users {
            drop(st);
            if let Some(old) = kicked {
                old.close();
            }
            slog!("{peer}: сервер заполнен");
            reject(&pipe, REJECT_SERVER_FULL, "сервер заполнен");
            return;
        }
        let mut session = st.next_session.max(1);
        while st.clients.contains_key(&session) {
            session = session.wrapping_add(1).max(1);
        }
        st.next_session = session.wrapping_add(1).max(1);
        let client = Arc::new(Client {
            session,
            name: name.clone(),
            peer,
            tx,
            pipe: pipe.clone(),
            crypt: Mutex::new(crypt),
            udp_addr: Mutex::new(None),
            udp_ok: AtomicBool::new(false),
            self_mute: AtomicBool::new(false),
            self_deaf: AtomicBool::new(false),
            last_udp_good_ms: AtomicU64::new(0),
            last_resync_req_ms: AtomicU64::new(0),
            resync: AtomicU32::new(0),
            rate: Mutex::new(Rate::new()),
            dead: AtomicBool::new(false),
        });
        for f in super::welcome_frames(sh, &key, &client_nonce, &server_nonce) {
            client.send(f);
        }
        for other in st.clients.values() {
            client.send(frame_msg(T_USERSTATE, &other.state_message()));
        }
        st.clients.insert(session, client.clone());
        (client, kicked)
    };

    let p = pipe.clone();
    let writer = std::thread::Builder::new()
        .name("srv-tx".into())
        .stack_size(256 * 1024)
        .spawn(move || writer_loop(p, rx));
    if writer.is_err() {
        sh.forget(&client);
        return;
    }

    if let Some(old) = kicked {
        old.close();
        // Новой сессии о старой не сообщаем — она её и не видела.
        sh.broadcast(
            &frame_msg(T_USERREMOVE, &UserRemove { session: old.session, reason: Some("переподключение".into()), ..Default::default() }),
            Some(client.session),
        );
    }
    sh.broadcast(&frame_msg(T_USERSTATE, &client.state_message()), None);
    {
        let rt = sh.runtime.read().unwrap();
        client.send(frame_msg(
            T_SERVERSYNC,
            &ServerSync {
                session: Some(client.session),
                max_bandwidth: Some(MAX_BANDWIDTH),
                welcome_text: Some(rt.welcome.clone()),
                permissions: Some(PERMISSIONS as u64),
            },
        ));
        client.send(frame_msg(
            T_SERVERCONFIG,
            &ServerConfig {
                max_bandwidth: Some(MAX_BANDWIDTH),
                welcome_text: Some(rt.welcome.clone()),
                allow_html: Some(false),
                message_length: Some(MAX_TEXT as u32),
                image_message_length: Some(0),
                max_users: Some(rt.max_users),
            },
        ));
    }
    let client_ver = if auth.opus == Some(false) { " (клиент без Opus — звук не услышит)" } else { "" };
    slog!("вошёл: «{}» с {peer}, сессия {}{client_ver}", client.name, client.session);
    (sh.notify)();

    pipe.wire.set_timeout(IDLE_TIMEOUT);
    let reason = message_loop(sh, &client, &pipe, &mut raw, &mut frames);

    client.close();
    if sh.forget(&client) {
        sh.broadcast(&frame_msg(T_USERREMOVE, &UserRemove { session: client.session, ..Default::default() }), None);
        slog!("вышел: «{}» ({reason})", client.name);
        (sh.notify)();
    }
}

fn writer_loop(pipe: Arc<Pipe>, rx: Receiver<Vec<u8>>) {
    while let Ok(f) = rx.recv() {
        if f.is_empty() || pipe.send(&f).is_err() {
            break;
        }
    }
    pipe.close();
}

fn message_loop(sh: &Arc<Shared>, c: &Arc<Client>, pipe: &Pipe, raw: &mut [u8], frames: &mut Deframer) -> String {
    loop {
        if c.dead.load(Ordering::SeqCst) || sh.stop.load(Ordering::SeqCst) {
            return "соединение закрыто сервером".into();
        }
        match pipe.pump(raw, frames) {
            Ok(true) => {}
            Ok(false) => return "отключился".into(),
            Err(e) if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => {
                return "нет ответа 30 секунд".into()
            }
            Err(e) => return format!("обрыв: {e}"),
        }
        loop {
            match frames.next() {
                Ok(Some((ty, body))) => handle(sh, c, ty, body),
                Ok(None) => break,
                Err(len) => return format!("слишком длинное сообщение ({len} байт)"),
            }
        }
    }
}

fn handle(sh: &Arc<Shared>, c: &Arc<Client>, ty: u16, body: &[u8]) {
    match ty {
        T_PING => {
            let Ok(p) = Ping::decode(body) else { return };
            let (good, late, lost) = {
                let cs = c.crypt.lock().unwrap();
                (cs.good, cs.late, cs.lost)
            };
            c.send(frame_msg(
                T_PING,
                &Ping {
                    timestamp: p.timestamp,
                    good: Some(good),
                    late: Some(late),
                    lost: Some(lost),
                    resync: Some(c.resync.load(Ordering::Relaxed)),
                },
            ));
        }
        T_UDPTUNNEL => {
            // Клиент шлёт голос через TCP — значит, его UDP сейчас не работает: отвечаем так же.
            c.udp_ok.store(false, Ordering::Relaxed);
            voice::handle(sh, c, body, voice::Via::Tcp);
        }
        T_USERSTATE => user_state(sh, c, body),
        T_CRYPTSETUP => {
            let Ok(m) = CryptSetup::decode(body) else { return };
            match m.client_nonce {
                Some(cn) if cn.len() == 16 => {
                    c.crypt.lock().unwrap().set_decrypt_iv(&cn);
                    c.resync.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    let iv = c.crypt.lock().unwrap().encrypt_iv();
                    c.send(frame_msg(
                        T_CRYPTSETUP,
                        &CryptSetup { key: None, client_nonce: None, server_nonce: Some(iv.to_vec()) },
                    ));
                }
            }
        }
        T_PERMISSIONQUERY => {
            let q = PermissionQuery::decode(body).unwrap_or_default();
            c.send(frame_msg(
                T_PERMISSIONQUERY,
                &PermissionQuery { channel_id: Some(q.channel_id.unwrap_or(0)), permissions: Some(PERMISSIONS), flush: None },
            ));
        }
        T_TEXTMESSAGE => text_message(sh, c, body),
        T_CHANNELSTATE | T_CHANNELREMOVE | T_USERREMOVE | T_BANLIST | T_ACL => {
            deny(c, "на этом сервере нельзя менять каналы и других участников")
        }
        _ => {}
    }
}

fn user_state(sh: &Arc<Shared>, c: &Arc<Client>, body: &[u8]) {
    let Ok(u) = UserState::decode(body) else { return };
    if let Some(s) = u.session {
        if s != c.session {
            deny(c, "менять можно только своё состояние");
            return;
        }
    }
    if u.self_mute.is_none() && u.self_deaf.is_none() {
        return;
    }
    // Как в Murmur: «выключить звук» включает и «выключить микрофон»,
    // а включение микрофона возвращает звук.
    if let Some(d) = u.self_deaf {
        c.self_deaf.store(d, Ordering::Relaxed);
        if d {
            c.self_mute.store(true, Ordering::Relaxed);
        }
    }
    if let Some(m) = u.self_mute {
        c.self_mute.store(m, Ordering::Relaxed);
        if !m {
            c.self_deaf.store(false, Ordering::Relaxed);
        }
    }
    let msg = UserState {
        session: Some(c.session),
        actor: Some(c.session),
        self_mute: Some(c.self_mute.load(Ordering::Relaxed)),
        self_deaf: Some(c.self_deaf.load(Ordering::Relaxed)),
        ..Default::default()
    };
    sh.broadcast(&frame_msg(T_USERSTATE, &msg), None);
}

fn text_message(sh: &Arc<Shared>, c: &Arc<Client>, body: &[u8]) {
    let Ok(t) = TextMessage::decode(body) else { return };
    if t.message.len() > MAX_TEXT {
        deny(c, "слишком длинное сообщение");
        return;
    }
    let out = frame_msg(
        T_TEXTMESSAGE,
        &TextMessage {
            actor: Some(c.session),
            session: t.session.clone(),
            channel_id: t.channel_id.clone(),
            tree_id: Vec::new(),
            message: t.message,
        },
    );
    if t.session.is_empty() {
        sh.broadcast(&out, Some(c.session));
    } else {
        let targets: Vec<Arc<Client>> = {
            let st = sh.state.lock().unwrap();
            t.session.iter().filter_map(|s| st.clients.get(s).cloned()).collect()
        };
        for x in targets {
            x.send(out.clone());
        }
    }
}
