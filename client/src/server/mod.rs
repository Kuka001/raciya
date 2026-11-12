//! Встроенный сервер голосового чата — подмножество протокола Mumble.
//!
//! К нему подключаются наш клиент (в том числе старые версии) и официальные приложения Mumble.
//! Один корневой канал, без регистрации пользователей: вход по имени и паролю сервера.
//!
//! Потоки: `srv-accept` (приём TCP), на каждого участника `srv-conn` (чтение) и `srv-tx`
//! (запись из очереди), `srv-udp` (голос, высокий приоритет). Медленный участник не может
//! задержать голос остальным: голос ему отправляется только через неблокирующую очередь.

mod conn;
mod guard;
pub mod migrate;
pub mod ports;
mod tls;
mod voice;

#[cfg(test)]
mod tests;

use crate::framing::frame_msg;
use crate::ocb2::CryptState;
use crate::proto::*;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const DEFAULT_PORT: u16 = 64738;

/// Папка сервера: сертификат, журнал (и резервная копия настроек Mumble Server из версии 0.2).
pub fn data_dir() -> PathBuf {
    crate::config::roaming_dir().join("server")
}
pub const DEFAULT_MAX_USERS: u32 = 10;
/// Права обычного участника: проход, вход, речь, шёпот, текстовые сообщения.
pub const PERMISSIONS: u32 = 0x2 | 0x4 | 0x8 | 0x100 | 0x200;
/// Сколько трафика разрешено одному участнику (бит/с) — официальные клиенты подстраиваются.
pub const MAX_BANDWIDTH: u32 = 128_000;

/// Доступ к серверу через свой P2P (поиск по коду приглашения в DHT, пробивание NAT).
#[derive(Clone, Debug, PartialEq)]
pub struct P2pSettings {
    pub secret: [u8; 16],
    /// UDP-порт P2P (0 — любой свободный).
    pub port: u16,
    /// Публиковать адрес в DHT (без этого — только по адресам из кода, для проверок).
    pub dht: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub port: u16,
    /// Пустой пароль — вход без пароля (только для локальной сети).
    pub password: String,
    pub max_users: u32,
    pub welcome: String,
    pub name: String,
    pub p2p: Option<P2pSettings>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            port: DEFAULT_PORT,
            password: String::new(),
            max_users: DEFAULT_MAX_USERS,
            welcome: String::new(),
            name: "Рация".into(),
            p2p: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum StartError {
    /// Windows зарезервировала порт (Hyper-V, WSL, Docker): нужна системная настройка.
    Reserved { port: u16, range: Option<(u16, u16)> },
    /// Порт занят другой программой.
    InUse { port: u16, owner: Option<String> },
    Other(String),
}

impl StartError {
    pub fn describe(&self) -> String {
        match self {
            StartError::Reserved { port, range: Some((a, b)) } => format!(
                "порт {port} зарезервирован Windows (Hyper-V/WSL держат диапазон {a}–{b}). Нажмите «Исправить» — порт закрепится за «Рацией»"
            ),
            StartError::Reserved { port, range: None } => {
                format!("Windows не даёт открыть порт {port}. Нажмите «Исправить» или выберите другой порт")
            }
            StartError::InUse { port, owner: Some(o) } => {
                format!("порт {port} уже занят программой {o}. Закройте её или выберите другой порт")
            }
            StartError::InUse { port, owner: None } => {
                format!("порт {port} уже занят другой программой. Выберите другой порт")
            }
            StartError::Other(e) => format!("сервер не запустился: {e}"),
        }
    }

    /// Можно ли исправить системной настройкой (права администратора).
    pub fn fixable(&self) -> bool {
        matches!(self, StartError::Reserved { .. })
    }
}

#[derive(Clone, Debug)]
pub struct UserInfo {
    pub session: u32,
    pub name: String,
    pub addr: SocketAddr,
    pub udp: bool,
}

pub(crate) struct Runtime {
    /// Пароль хранится как HMAC со случайным ключом: сравнение за постоянное время.
    pub password_key: ring::hmac::Key,
    pub password_tag: Option<Vec<u8>>,
    pub max_users: u32,
    pub welcome: String,
    pub name: String,
}

impl Runtime {
    fn new(s: &Settings, rng: &ring::rand::SystemRandom) -> Runtime {
        let key = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, rng).expect("random");
        let tag = (!s.password.is_empty()).then(|| ring::hmac::sign(&key, s.password.as_bytes()).as_ref().to_vec());
        Runtime {
            password_key: key,
            password_tag: tag,
            max_users: s.max_users.clamp(1, 1000),
            welcome: s.welcome.clone(),
            name: if s.name.trim().is_empty() { "Рация".into() } else { s.name.clone() },
        }
    }
}

#[derive(Default)]
pub(crate) struct State {
    pub clients: HashMap<u32, Arc<Client>>,
    pub by_udp: HashMap<SocketAddr, u32>,
    pub next_session: u32,
}

/// UDP-сокет сервера, который можно закрыть явно: порт освобождается сразу при остановке,
/// даже если где-то ещё живут ссылки на общее состояние.
pub(crate) struct UdpPort {
    sock: RwLock<Option<UdpSocket>>,
}

impl UdpPort {
    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) {
        if let Some(s) = self.sock.read().unwrap().as_ref() {
            let _ = s.send_to(buf, addr);
        }
    }

    /// `None` — сокет уже закрыт.
    pub fn recv_from(&self, buf: &mut [u8]) -> Option<std::io::Result<(usize, SocketAddr)>> {
        self.sock.read().unwrap().as_ref().map(|s| s.recv_from(buf))
    }

    fn close(&self) {
        self.sock.write().unwrap().take();
    }
}

pub(crate) struct Shared {
    pub runtime: RwLock<Runtime>,
    pub tls: Arc<rustls::ServerConfig>,
    pub udp: UdpPort,
    pub stop: AtomicBool,
    pub state: Mutex<State>,
    pub guard: Mutex<guard::Guard>,
    pub start: Instant,
    pub notify: Box<dyn Fn() + Send + Sync>,
    pub rng: ring::rand::SystemRandom,
}

impl Shared {
    pub fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Всем участникам (кроме `except`).
    pub fn broadcast(&self, frame: &[u8], except: Option<u32>) {
        let targets: Vec<Arc<Client>> = {
            let st = self.state.lock().unwrap();
            st.clients.values().filter(|c| Some(c.session) != except).cloned().collect()
        };
        for t in targets {
            t.send(frame.to_vec());
        }
    }

    /// Убирает участника из списков. `true` — он ещё был там (значит, остальным нужно сообщить).
    pub fn forget(&self, c: &Arc<Client>) -> bool {
        let mut st = self.state.lock().unwrap();
        let present = st.clients.get(&c.session).map(|x| Arc::ptr_eq(x, c)).unwrap_or(false);
        if present {
            st.clients.remove(&c.session);
            if let Some(a) = *c.udp_addr.lock().unwrap() {
                if st.by_udp.get(&a) == Some(&c.session) {
                    st.by_udp.remove(&a);
                }
            }
        }
        present
    }
}

/// Ограничение частоты голосовых пакетов одного участника (200 в секунду, запас 400).
pub(crate) struct Rate {
    tokens: f32,
    last: Instant,
}

impl Rate {
    fn new() -> Rate {
        Rate { tokens: 400.0, last: Instant::now() }
    }

    pub fn allow(&mut self) -> bool {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f32();
        self.last = now;
        self.tokens = (self.tokens + dt * 200.0).min(400.0);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub(crate) struct Client {
    pub session: u32,
    pub name: String,
    pub peer: SocketAddr,
    /// Кадры для потока записи; пустой кадр — сигнал завершиться.
    pub tx: SyncSender<Vec<u8>>,
    pub pipe: Arc<conn::Pipe>,
    pub crypt: Mutex<CryptState>,
    pub udp_addr: Mutex<Option<SocketAddr>>,
    /// Голос этому участнику можно слать по UDP (от него недавно пришёл правильный UDP-пакет).
    pub udp_ok: AtomicBool,
    pub self_mute: AtomicBool,
    pub self_deaf: AtomicBool,
    pub last_udp_good_ms: AtomicU64,
    pub last_resync_req_ms: AtomicU64,
    pub resync: AtomicU32,
    pub rate: Mutex<Rate>,
    pub dead: AtomicBool,
    /// Участник пришёл через P2P: голос идёт датаграммами в этом потоке.
    pub p2p: Option<Arc<crate::p2p::flow::Flow>>,
}

impl Client {
    /// Управляющее сообщение. Если очередь переполнена, участник не успевает принимать данные —
    /// его соединение закрывается (иначе он задерживал бы остальных).
    pub fn send(&self, frame: Vec<u8>) {
        match self.tx.try_send(frame) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                slog!("{}: не успевает принимать данные — отключаю", self.name);
                self.close();
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    /// Голос через TCP-туннель: при переполнении пакет просто отбрасывается.
    pub fn send_tunnel(&self, plain: &[u8]) {
        let _ = self.tx.try_send(crate::framing::frame(T_UDPTUNNEL, plain));
    }

    pub fn close(&self) {
        self.dead.store(true, Ordering::SeqCst);
        let _ = self.tx.try_send(Vec::new());
        self.pipe.close();
    }

    pub fn state_message(&self) -> UserState {
        UserState {
            session: Some(self.session),
            name: Some(self.name.clone()),
            channel_id: Some(0),
            self_mute: Some(self.self_mute.load(Ordering::Relaxed)),
            self_deaf: Some(self.self_deaf.load(Ordering::Relaxed)),
            ..Default::default()
        }
    }
}

pub struct Server {
    shared: Arc<Shared>,
    port: u16,
    fingerprint: String,
    accept: Mutex<Option<JoinHandle<()>>>,
    p2p: Option<Arc<crate::p2p::Host>>,
}

fn classify(e: std::io::Error, port: u16, udp: bool) -> StartError {
    match e.raw_os_error() {
        // WSAEACCES: порт в диапазоне, зарезервированном Windows, или занят «эксклюзивно».
        Some(10013) => {
            let proto = if udp { "udp" } else { "tcp" };
            if let Some(r) = ports::excluded(proto).into_iter().find(|r| !r.administered && r.contains(port)) {
                StartError::Reserved { port, range: Some((r.start, r.end)) }
            } else if let Some(owner) = crate::win::port_owner(port, udp) {
                StartError::InUse { port, owner: Some(owner) }
            } else {
                StartError::Reserved { port, range: None }
            }
        }
        // WSAEADDRINUSE
        Some(10048) => StartError::InUse { port, owner: crate::win::port_owner(port, udp) },
        _ => StartError::Other(e.to_string()),
    }
}

impl Server {
    /// Открывает порт (TCP и UDP) и запускает сервер. Ошибка порта видна сразу.
    /// `data_dir` — папка с сертификатом; `notify` вызывается, когда меняется список участников.
    pub fn start(
        settings: Settings,
        data_dir: PathBuf,
        notify: Box<dyn Fn() + Send + Sync>,
    ) -> Result<Arc<Server>, StartError> {
        let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let listener = TcpListener::bind((any, settings.port)).map_err(|e| classify(e, settings.port, false))?;
        let port = listener.local_addr().map_err(|e| StartError::Other(e.to_string()))?.port();
        let udp = UdpSocket::bind((any, port)).map_err(|e| classify(e, port, true))?;
        let _ = udp.set_read_timeout(Some(Duration::from_millis(500)));
        crate::win::mark_voice_socket(&udp);
        crate::win::disable_udp_connreset(&udp);

        let identity = tls::load_or_create(&data_dir).map_err(StartError::Other)?;
        let tls = tls::server_config(&identity).map_err(StartError::Other)?;
        let rng = ring::rand::SystemRandom::new();
        let shared = Arc::new(Shared {
            runtime: RwLock::new(Runtime::new(&settings, &rng)),
            tls,
            udp: UdpPort { sock: RwLock::new(Some(udp)) },
            stop: AtomicBool::new(false),
            state: Mutex::new(State { next_session: 1, ..Default::default() }),
            guard: Mutex::new(guard::Guard::default()),
            start: Instant::now(),
            notify,
            rng,
        });

        let sh = shared.clone();
        let accept = std::thread::Builder::new()
            .name("srv-accept".into())
            .spawn(move || {
                crate::win::set_thread_priority(crate::win::Prio::Low);
                accept_loop(sh, listener);
            })
            .map_err(|e| StartError::Other(e.to_string()))?;
        let sh = shared.clone();
        std::thread::Builder::new()
            .name("srv-udp".into())
            .spawn(move || {
                crate::win::set_thread_priority(crate::win::Prio::High);
                voice::udp_loop(sh);
            })
            .map_err(|e| StartError::Other(e.to_string()))?;

        let p2p = settings.p2p.as_ref().and_then(|ps| start_p2p(&shared, ps));
        slog!(
            "сервер запущен: порт {port}, мест {}, пароль {}{}",
            settings.max_users,
            if settings.password.is_empty() { "не задан" } else { "задан" },
            p2p.as_ref().map(|h| format!(", P2P на UDP {}", h.port())).unwrap_or_default()
        );
        Ok(Arc::new(Server {
            shared,
            port,
            fingerprint: identity.fingerprint(),
            accept: Mutex::new(Some(accept)),
            p2p,
        }))
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Первые 16 байт отпечатка сертификата — для кода приглашения.
    pub fn fingerprint_prefix(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        if let Some(b) = crate::win::from_hex(&self.fingerprint) {
            out.copy_from_slice(&b[..16]);
        }
        out
    }

    /// UDP-порт P2P, если доступ через интернет включён и работает.
    pub fn p2p_port(&self) -> Option<u16> {
        self.p2p.as_ref().map(|h| h.port())
    }

    pub fn p2p_status(&self) -> Option<crate::p2p::HostStatus> {
        self.p2p.as_ref().map(|h| h.status())
    }

    pub fn users(&self) -> Vec<UserInfo> {
        let st = self.shared.state.lock().unwrap();
        let mut v: Vec<UserInfo> = st
            .clients
            .values()
            .map(|c| UserInfo {
                session: c.session,
                name: c.name.clone(),
                addr: c.peer,
                udp: c.udp_ok.load(Ordering::Relaxed),
            })
            .collect();
        v.sort_by_key(|u| u.session);
        v
    }

    /// Пароль, число мест, приветствие и имя применяются сразу (порт — только перезапуском).
    pub fn update(&self, settings: &Settings) {
        *self.shared.runtime.write().unwrap() = Runtime::new(settings, &self.shared.rng);
        slog!("настройки сервера обновлены");
    }

    pub fn stop(&self) {
        if self.shared.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        // Будим поток приёма, чтобы он увидел флаг остановки и закрыл порт, и ждём его.
        let _ = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], self.port)), Duration::from_millis(300));
        if let Some(h) = self.accept.lock().unwrap().take() {
            let _ = h.join();
        }
        self.shared.udp.close();
        if let Some(h) = &self.p2p {
            h.stop();
        }
        let clients: Vec<Arc<Client>> = {
            let mut st = self.shared.state.lock().unwrap();
            st.by_udp.clear();
            st.clients.drain().map(|(_, c)| c).collect()
        };
        for c in clients {
            c.close();
        }
        slog!("сервер остановлен");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(sh: Arc<Shared>, listener: TcpListener) {
    for stream in listener.incoming() {
        if sh.stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = stream else {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        };
        let Ok(peer) = stream.peer_addr() else { continue };
        if !sh.guard.lock().unwrap().admit(peer.ip(), Instant::now()) {
            continue;
        }
        let _ = stream.set_nodelay(true);
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        let s = sh.clone();
        let spawned = std::thread::Builder::new().name("srv-conn".into()).stack_size(512 * 1024).spawn(move || {
            crate::win::set_thread_priority(crate::win::Prio::Low);
            conn::serve(&s, Box::new(stream), peer, None);
            s.guard.lock().unwrap().release(peer.ip());
        });
        if spawned.is_err() {
            sh.guard.lock().unwrap().release(peer.ip());
        }
    }
}

/// Запускает P2P-доступ. Если заданный порт занят — берёт любой свободный (код приглашения
/// всё равно найдёт сервер через DHT; меняются только адреса для локальной сети).
fn start_p2p(sh: &Arc<Shared>, ps: &P2pSettings) -> Option<Arc<crate::p2p::Host>> {
    let room = crate::p2p::Room::new(ps.secret);
    let make = |port: u16| {
        let weak = Arc::downgrade(sh);
        let weak_notify = Arc::downgrade(sh);
        crate::p2p::Host::start_with(
            room.clone(),
            port,
            ps.dht,
            Box::new(move |flow: Arc<crate::p2p::flow::Flow>| {
                let Some(s) = weak.upgrade() else { return };
                let peer = flow.peer;
                if s.stop.load(Ordering::SeqCst) || !s.guard.lock().unwrap().admit(peer.ip(), Instant::now()) {
                    flow.shutdown();
                    return;
                }
                let s2 = s.clone();
                let spawned = std::thread::Builder::new().name("srv-p2p".into()).stack_size(512 * 1024).spawn(move || {
                    crate::win::set_thread_priority(crate::win::Prio::Low);
                    let wire: Box<dyn crate::transport::Stream> = Box::new(FlowStream(flow.clone()));
                    conn::serve(&s, wire, peer, Some(flow));
                    s.guard.lock().unwrap().release(peer.ip());
                });
                if spawned.is_err() {
                    s2.guard.lock().unwrap().release(peer.ip());
                }
            }),
            Arc::new(move || {
                if let Some(s) = weak_notify.upgrade() {
                    (s.notify)();
                }
            }),
        )
    };
    match make(ps.port).or_else(|e| {
        slog!("P2P: порт {} недоступен ({e}), беру свободный", ps.port);
        make(0)
    }) {
        Ok(h) => Some(h),
        Err(e) => {
            slog!("P2P не запустился: {e}");
            None
        }
    }
}

/// Поток P2P как транспорт управляющего канала.
struct FlowStream(Arc<crate::p2p::flow::Flow>);

impl crate::transport::Stream for FlowStream {
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        crate::transport::Stream::recv(self.0.as_ref(), buf)
    }

    fn send_all(&self, buf: &[u8]) -> std::io::Result<()> {
        crate::transport::Stream::send_all(self.0.as_ref(), buf)
    }

    fn set_timeout(&self, t: Duration) {
        crate::transport::Stream::set_timeout(self.0.as_ref(), t)
    }

    fn close(&self) {
        self.0.shutdown()
    }
}

/// Сообщения, которыми сервер встречает нового участника (до списка участников).
pub(crate) fn welcome_frames(sh: &Shared, key: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> Vec<Vec<u8>> {
    let rt = sh.runtime.read().unwrap();
    vec![
        frame_msg(
            T_CRYPTSETUP,
            &CryptSetup {
                key: Some(key.to_vec()),
                client_nonce: Some(client_nonce.to_vec()),
                server_nonce: Some(server_nonce.to_vec()),
            },
        ),
        frame_msg(
            T_CODECVERSION,
            &CodecVersion { alpha: 0x8000_000Bu32 as i32, beta: 0, prefer_alpha: true, opus: Some(true) },
        ),
        frame_msg(
            T_CHANNELSTATE,
            &ChannelState {
                channel_id: Some(0),
                name: Some(rt.name.clone()),
                position: Some(0),
                max_users: Some(0),
                ..Default::default()
            },
        ),
    ]
}
