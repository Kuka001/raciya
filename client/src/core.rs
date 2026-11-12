//! Ядро клиента: состояние, автопереподключение, список участников, клавиша «говорить».
//! Интерфейс получает события через функцию-приёмник и вызывает методы `Core`.

use crate::audio::{self, AudioCmd, AudioEvent, AudioShared, DeviceChoice, LOOPBACK_SESSION};
use crate::config::Config;
use crate::net::{describe_connect_error, Link, LinkEvent, LinkHandler};
use crate::proto;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Default)]
pub enum Status {
    #[default]
    Offline,
    Connecting,
    Online,
    Reconnecting(String),
    Failed(String),
}

pub enum Event {
    Status(Status),
    /// Список участников или их состояние изменились — интерфейс перечитывает `Core::users()`.
    Users,
    Speaking { session: u32, on: bool },
    Ping { ms: f32, udp: bool },
    Notice(String),
    /// Результат назначения клавиши (`None` — отменено).
    KeyCaptured(Option<u32>),
    Devices { input: String, output: String },
    /// Изменилось состояние сервера на этом компьютере — интерфейс перечитывает `Core::server_view()`.
    Server,
    /// Ход подключения («ищу сервер…»); пустая строка — убрать.
    Progress(String),
}

/// Состояние сервера на этом компьютере для интерфейса.
#[derive(Clone, Debug, Default)]
pub struct ServerView {
    pub enabled: bool,
    pub starting: bool,
    pub running: bool,
    pub port: u16,
    pub users: Vec<String>,
    pub error: Option<String>,
    /// Ошибку можно исправить системной настройкой (права администратора).
    pub fixable: bool,
    /// Код приглашения для доступа через интернет (P2P), если он включён и работает.
    pub invite: Option<String>,
    pub p2p: Option<crate::p2p::HostStatus>,
}

#[derive(Clone, Debug)]
pub struct UserView {
    pub session: u32,
    pub name: String,
    pub muted: bool,
    pub deafened: bool,
    pub speaking: bool,
    pub volume: f32,
    pub is_self: bool,
}

struct User {
    name: String,
    mute: bool,
    self_mute: bool,
    suppress: bool,
    deaf: bool,
    self_deaf: bool,
    speaking: bool,
}

#[derive(Default)]
struct Ctl {
    want: bool,
    quit: bool,
    gen: u64,
    closed: Option<String>,
    fatal: Option<String>,
    reject: Option<String>,
}

pub struct Core {
    pub cfg: Mutex<Config>,
    pub audio: Arc<AudioShared>,
    users: Mutex<HashMap<u32, User>>,
    my_session: AtomicU32,
    status: Mutex<Status>,
    ctl: Mutex<Ctl>,
    cv: Condvar,
    sink: Box<dyn Fn(Event) + Send + Sync>,
    audio_tx: Mutex<Option<Sender<AudioCmd>>>,
    devices: Arc<Mutex<DeviceChoice>>,
    ptt_key: AtomicU32,
    capture_key: AtomicBool,
    dirty: AtomicBool,
    persist: bool,
    self_talking: AtomicBool,
    test_talking: AtomicBool,
    /// Последние измерения пинга до сервера (для диагностики).
    pings: Mutex<std::collections::VecDeque<f32>>,
    online_since: Mutex<Option<std::time::Instant>>,
    last_udp_stats: Mutex<(u32, u32)>,
    /// Встроенный сервер (только если на этом компьютере включён «Сервер»).
    server: Mutex<Option<Arc<crate::server::Server>>>,
    server_error: Mutex<Option<crate::server::StartError>>,
    server_starting: AtomicBool,
    /// Номер последней команды запуска/остановки: устаревшие попытки запуска отменяются.
    server_gen: AtomicU64,
    /// Для проверок: не пользоваться UDP (голос только через TCP-туннель).
    pub no_udp: AtomicBool,
}

struct Bridge {
    core: Weak<Core>,
    audio: Arc<AudioShared>,
    gen: u64,
}

impl LinkHandler for Bridge {
    fn on_voice(&self, session: u32, seq: u64, opus: &[u8], last: bool) {
        self.audio.push_voice(session, seq, opus, last);
    }

    fn on_event(&self, ev: LinkEvent) {
        if let Some(core) = self.core.upgrade() {
            core.on_link_event(self.gen, ev);
        }
    }
}

impl Core {
    /// `persist = false` — настройки не записываются на диск (режим проверки из командной строки).
    pub fn new(cfg: Config, persist: bool, sink: Box<dyn Fn(Event) + Send + Sync>) -> Arc<Core> {
        let core = Arc::new_cyclic(|weak: &Weak<Core>| {
            let w = weak.clone();
            let audio = AudioShared::new(Box::new(move |ev| {
                if let Some(c) = w.upgrade() {
                    c.on_audio_event(ev);
                }
            }));
            audio.vad_mode.store(cfg.voice_activation, Ordering::Relaxed);
            audio.noise_mode.store(cfg.noise_mode as u32, Ordering::Relaxed);
            audio.vad_threshold.store(cfg.vad_threshold.to_bits(), Ordering::Relaxed);
            audio.bitrate.store(cfg.bitrate, Ordering::Relaxed);
            Core {
                devices: Arc::new(Mutex::new(DeviceChoice {
                    input: cfg.input_device.clone(),
                    output: cfg.output_device.clone(),
                })),
                ptt_key: AtomicU32::new(cfg.ptt_key),
                cfg: Mutex::new(cfg),
                audio,
                users: Mutex::new(HashMap::new()),
                my_session: AtomicU32::new(0),
                status: Mutex::new(Status::Offline),
                ctl: Mutex::new(Ctl::default()),
                cv: Condvar::new(),
                sink,
                audio_tx: Mutex::new(None),
                capture_key: AtomicBool::new(false),
                dirty: AtomicBool::new(false),
                persist,
                self_talking: AtomicBool::new(false),
                test_talking: AtomicBool::new(false),
                pings: Mutex::new(std::collections::VecDeque::new()),
                online_since: Mutex::new(None),
                last_udp_stats: Mutex::new((0, 0)),
                server: Mutex::new(None),
                server_error: Mutex::new(None),
                server_starting: AtomicBool::new(false),
                server_gen: AtomicU64::new(0),
                no_udp: AtomicBool::new(false),
            }
        });
        // Сервер запускает интерфейс (`apply_server_setting`): иногда сначала нужна системная настройка.

        let (tx, _handle) = audio::spawn_audio(core.audio.clone(), core.devices.clone());
        *core.audio_tx.lock().unwrap() = Some(tx);

        let c = core.clone();
        std::thread::Builder::new()
            .name("supervisor".into())
            .spawn(move || {
                crate::win::set_thread_priority(crate::win::Prio::Low);
                c.supervisor();
            })
            .expect("supervisor thread");
        let c = core.clone();
        std::thread::Builder::new()
            .name("hotkey".into())
            .spawn(move || c.hotkey_loop())
            .expect("hotkey thread");
        core
    }

    fn emit(&self, ev: Event) {
        (self.sink)(ev);
    }

    fn set_status(&self, s: Status) {
        {
            let mut cur = self.status.lock().unwrap();
            if *cur == s {
                return;
            }
            *cur = s.clone();
        }
        self.emit(Event::Status(s));
    }

    pub fn status(&self) -> Status {
        self.status.lock().unwrap().clone()
    }

    pub fn is_online(&self) -> bool {
        matches!(*self.status.lock().unwrap(), Status::Online)
    }

    pub fn my_session(&self) -> u32 {
        self.my_session.load(Ordering::Relaxed)
    }

    // --- подключение -------------------------------------------------------------------------

    pub fn connect(&self) {
        let mut c = self.ctl.lock().unwrap();
        c.want = true;
        self.cv.notify_all();
    }

    pub fn disconnect(&self) {
        let mut c = self.ctl.lock().unwrap();
        c.want = false;
        self.cv.notify_all();
    }

    pub fn wants_connection(&self) -> bool {
        self.ctl.lock().unwrap().want
    }

    /// Завершение программы: закрыть соединение и звуковые устройства.
    pub fn shutdown(&self) {
        {
            let mut c = self.ctl.lock().unwrap();
            c.want = false;
            c.quit = true;
            self.cv.notify_all();
        }
        if let Some(link) = self.audio.link.read().unwrap().as_ref() {
            link.close();
        }
        if let Some(tx) = self.audio_tx.lock().unwrap().as_ref() {
            let _ = tx.send(AudioCmd::Stop);
        }
        self.server_gen.fetch_add(1, Ordering::SeqCst);
        if let Some(s) = self.server.lock().unwrap().take() {
            s.stop();
        }
        self.flush_config();
    }

    // --- сервер на этом компьютере -----------------------------------------------------------

    /// Запускает, перенастраивает или останавливает встроенный сервер по настройкам `[host]`.
    /// `retries` — сколько раз повторить запуск, если порт ещё занят (раз в секунду).
    pub fn apply_server_setting(self: &Arc<Self>, retries: u32) {
        let host = {
            let mut cfg = self.cfg.lock().unwrap();
            // Секрет комнаты и P2P-порт появляются при первом запуске сервера с P2P.
            let created = cfg.host.as_mut().map(|h| h.enabled && h.ensure_p2p()).unwrap_or(false);
            if created {
                self.dirty.store(true, Ordering::Relaxed);
            }
            cfg.host()
        };
        if self.dirty.load(Ordering::Relaxed) {
            self.flush_config();
        }
        let gen = self.server_gen.fetch_add(1, Ordering::SeqCst) + 1;
        let current = self.server.lock().unwrap().take();
        if let Some(s) = current {
            if host.enabled && s.port() == host.port && s.p2p_port().is_some() == host.settings().p2p.is_some() {
                // Тот же порт: пароль и остальное применяются без перезапуска.
                s.update(&host.settings());
                *self.server.lock().unwrap() = Some(s);
                self.emit(Event::Server);
                return;
            }
            s.stop();
        }
        *self.server_error.lock().unwrap() = None;
        if !host.enabled {
            self.server_starting.store(false, Ordering::SeqCst);
            self.emit(Event::Server);
            return;
        }
        self.server_starting.store(true, Ordering::SeqCst);
        self.emit(Event::Server);
        let core = self.clone();
        let spawned = std::thread::Builder::new().name("server-start".into()).spawn(move || {
            let mut attempt = 0;
            loop {
                if core.server_gen.load(Ordering::SeqCst) != gen {
                    return;
                }
                let weak = Arc::downgrade(&core);
                let notify = Box::new(move || {
                    if let Some(c) = weak.upgrade() {
                        c.emit(Event::Server);
                    }
                });
                match crate::server::Server::start(host.settings(), crate::server::data_dir(), notify) {
                    Ok(s) => {
                        if core.server_gen.load(Ordering::SeqCst) != gen {
                            s.stop();
                            return;
                        }
                        clog!("сервер запущен на порту {}", s.port());
                        *core.server.lock().unwrap() = Some(s);
                        break;
                    }
                    Err(e) => {
                        let busy = matches!(e, crate::server::StartError::InUse { .. });
                        if busy && attempt < retries {
                            attempt += 1;
                            std::thread::sleep(Duration::from_secs(1));
                            continue;
                        }
                        clog!("сервер не запустился: {}", e.describe());
                        *core.server_error.lock().unwrap() = Some(e);
                        break;
                    }
                }
            }
            core.server_starting.store(false, Ordering::SeqCst);
            core.emit(Event::Server);
        });
        if spawned.is_err() {
            self.server_starting.store(false, Ordering::SeqCst);
        }
    }

    /// Новые настройки сервера: сохраняются и применяются сразу.
    pub fn set_host(self: &Arc<Self>, host: crate::config::HostConfig) {
        let (old_port, network) = {
            let cfg = self.cfg.lock().unwrap();
            (cfg.host.as_ref().map(|h| h.port), cfg.zt_network.clone())
        };
        if host.enabled && !network.is_empty() && old_port.is_some_and(|p| p != host.port) {
            // Сеть ZeroTier пропускает только порт сервера: на компьютере-контроллере правим её правила.
            let (core, port) = (self.clone(), host.port);
            std::thread::spawn(move || match crate::zt::set_server_port(&network, port) {
                Ok(true) => clog!("правила сети ZeroTier: теперь пропускают порт {port}"),
                Ok(false) => core.emit(Event::Notice(format!(
                    "сеть ZeroTier создана на другом компьютере — там нужно разрешить порт {port}"
                ))),
                Err(e) => core.emit(Event::Notice(format!("не удалось поменять правила ZeroTier: {e}"))),
            });
        }
        {
            let mut cfg = self.cfg.lock().unwrap();
            // Включили сервер, а адрес для своего клиента не задан — подключаемся к себе.
            if host.enabled && cfg.server.trim().is_empty() {
                cfg.server = if host.port == crate::config::DEFAULT_PORT {
                    "127.0.0.1".into()
                } else {
                    format!("127.0.0.1:{}", host.port)
                };
            }
            cfg.host = Some(host);
        }
        self.dirty.store(true, Ordering::Relaxed);
        self.flush_config();
        self.apply_server_setting(2);
    }

    pub fn server_view(&self) -> ServerView {
        let host = self.cfg.lock().unwrap().host();
        let server = self.server.lock().unwrap().clone();
        let error = self.server_error.lock().unwrap().clone();
        let zt_network = self.cfg.lock().unwrap().zt_network.clone();
        let invite = server.as_ref().and_then(|s| {
            let secret = host.room?;
            let p2p_port = s.p2p_port()?;
            let addrs = crate::diag::local_addresses();
            let lan = addrs
                .iter()
                .filter(|(l, _)| *l != "ZeroTier")
                .map(|(_, ip)| SocketAddr::from((*ip, p2p_port)))
                .collect();
            let zt = addrs.iter().find(|(l, _)| *l == "ZeroTier").filter(|_| !zt_network.is_empty()).map(|(_, ip)| {
                let addr = if s.port() == crate::config::DEFAULT_PORT { ip.to_string() } else { format!("{ip}:{}", s.port()) };
                format!("{zt_network}@{addr}")
            });
            Some(crate::p2p::Invite { secret, fingerprint: s.fingerprint_prefix(), lan, zt }.encode())
        });
        ServerView {
            enabled: host.enabled,
            starting: self.server_starting.load(Ordering::SeqCst),
            running: server.is_some(),
            port: server.as_ref().map(|s| s.port()).unwrap_or(host.port),
            users: server.as_ref().map(|s| s.users().into_iter().map(|u| u.name).collect()).unwrap_or_default(),
            fixable: error.as_ref().map(|e| e.fixable()).unwrap_or(false),
            error: error.map(|e| e.describe()),
            p2p: server.as_ref().and_then(|s| s.p2p_status()),
            invite,
        }
    }

    pub fn server_running(&self) -> bool {
        self.server.lock().unwrap().is_some()
    }

    // --- диагностика -------------------------------------------------------------------------

    /// Сведения о текущем соединении для проверки сети.
    pub fn diag_context(&self) -> crate::diag::Context {
        let (server_host, server_port, zt_network, runs_server, host_port, uses_p2p) = {
            let cfg = self.cfg.lock().unwrap();
            let (h, p) = cfg.host_port();
            let p2p = crate::p2p::Invite::parse(&cfg.server).is_some();
            (h, p, cfg.zt_network.clone(), cfg.hosting(), cfg.host().port, p2p)
        };
        let server_error = self.server_error.lock().unwrap().as_ref().map(|e| (e.describe(), e.fixable()));
        let (avg, jitter) = {
            let p = self.pings.lock().unwrap();
            if p.len() >= 3 {
                let avg = p.iter().sum::<f32>() / p.len() as f32;
                let dev = p.iter().map(|v| (v - avg).abs()).sum::<f32>() / p.len() as f32;
                (Some(avg), Some(dev))
            } else {
                (None, None)
            }
        };
        let link = self.audio.link.read().unwrap().clone();
        let mut loss = None;
        if let Some(l) = link.as_ref() {
            let (good, _, lost) = l.udp_stats();
            let mut last = self.last_udp_stats.lock().unwrap();
            let dg = good.wrapping_sub(last.0);
            let dl = lost.wrapping_sub(last.1);
            // Потери считаем только при достаточном числе пакетов и без переполнений счётчика.
            if dg > 200 && dl < 100_000 {
                loss = Some(100.0 * dl as f32 / (dg + dl) as f32);
            }
            *last = (good, lost);
        }
        crate::diag::Context {
            online: self.is_online(),
            udp_active: link.as_ref().map(|l| l.udp_active()).unwrap_or(false),
            online_secs: self.online_since.lock().unwrap().map(|t| t.elapsed().as_secs()).unwrap_or(0),
            server_host,
            server_port,
            zt_network,
            ping_avg: avg,
            ping_jitter: jitter,
            loss_percent: loss,
            runs_server,
            server_running: self.server_running(),
            server_error,
            host_port,
            status: self.status(),
            force: false,
            uses_p2p,
            p2p_host: self.server.lock().unwrap().as_ref().and_then(|s| s.p2p_status()),
        }
    }

    /// Сохраняет данные подключения и, если нужно, переподключается с ними.
    pub fn set_connection(&self, server: &str, username: &str, password: &str, autoconnect: bool) {
        {
            let mut cfg = self.cfg.lock().unwrap();
            cfg.server = server.trim().to_string();
            cfg.username = username.trim().to_string();
            cfg.password = password.to_string();
            cfg.autoconnect = autoconnect;
        }
        self.dirty.store(true, Ordering::Relaxed);
        self.flush_config();
        // Если соединение уже есть — пересоздаём его с новыми данными.
        if let Some(link) = self.audio.link.read().unwrap().as_ref() {
            link.close();
        }
        self.connect();
    }

    fn supervisor(self: Arc<Self>) {
        // Паузы между попытками, секунды. Подобраны так, чтобы за 2 минуты выходило не больше
        // 10 попыток: при большем числе сервер Mumble может временно заблокировать адрес.
        const BACKOFF: [u64; 6] = [1, 2, 4, 8, 15, 20];
        let mut attempt = 0usize;
        loop {
            let gen = {
                let mut c = self.ctl.lock().unwrap();
                while !c.want && !c.quit {
                    c = self.cv.wait(c).unwrap();
                }
                if c.quit {
                    return;
                }
                c.gen += 1;
                c.closed = None;
                c.fatal = None;
                c.reject = None;
                c.gen
            };
            if attempt == 0 {
                self.set_status(Status::Connecting);
            }

            let bridge = Arc::new(Bridge { core: Arc::downgrade(&self), audio: self.audio.clone(), gen });
            let mut was_online = false;
            let reason = match self.open_link(bridge) {
                Ok(link) => {
                    if self.no_udp.load(Ordering::Relaxed) {
                        link.set_udp_disabled(true);
                    }
                    *self.audio.link.write().unwrap() = Some(link.clone());
                    let closed = {
                        let mut c = self.ctl.lock().unwrap();
                        while c.closed.is_none() && c.want && !c.quit {
                            c = self.cv.wait(c).unwrap();
                        }
                        c.closed.take()
                    };
                    was_online = self.is_online();
                    link.close();
                    *self.audio.link.write().unwrap() = None;
                    let reason = closed.unwrap_or_default();
                    clog!("соединение закрыто: {reason}");
                    reason
                }
                Err(reason) => {
                    clog!("не удалось подключиться: {reason}");
                    reason
                }
            };

            self.my_session.store(0, Ordering::SeqCst);
            *self.online_since.lock().unwrap() = None;
            self.users.lock().unwrap().clear();
            self.audio.clear_rx();
            self.audio.ptt_down.store(false, Ordering::Relaxed);
            self.emit(Event::Users);

            let mut c = self.ctl.lock().unwrap();
            if c.quit {
                return;
            }
            if let Some(f) = c.fatal.take() {
                c.want = false;
                drop(c);
                attempt = 0;
                clog!("подключение остановлено: {f}");
                self.set_status(Status::Failed(f));
                continue;
            }
            if !c.want {
                drop(c);
                attempt = 0;
                self.set_status(Status::Offline);
                continue;
            }
            let reason = c.reject.take().unwrap_or(reason);
            drop(c);

            if was_online {
                attempt = 0;
            }
            let delay = BACKOFF[attempt.min(BACKOFF.len() - 1)];
            attempt += 1;
            self.set_status(Status::Reconnecting(reason));
            let c = self.ctl.lock().unwrap();
            let _ = self
                .cv
                .wait_timeout_while(c, Duration::from_secs(delay), |c| c.want && !c.quit)
                .unwrap();
        }
    }

    /// Открывает соединение: по обычному адресу (TCP + UDP) или по коду приглашения v2 (P2P,
    /// а если не вышло и подключена ZeroTier — через неё).
    fn open_link(&self, bridge: Arc<Bridge>) -> Result<Arc<Link>, String> {
        let (server, username, password, last) = {
            let cfg = self.cfg.lock().unwrap();
            (cfg.server.clone(), cfg.username.clone(), cfg.password.clone(), cfg.p2p_last.parse::<SocketAddr>().ok())
        };
        let tcp = |host: &str, port: u16| {
            clog!("подключение к {host}:{port} как «{username}»");
            Link::connect(host, port, &username, &password, bridge.clone()).map_err(|e| {
                let reason = describe_connect_error(&e);
                clog!("  {e}");
                reason
            })
        };
        let Some(inv) = crate::p2p::Invite::parse(&server) else {
            let (host, port) = self.cfg.lock().unwrap().host_port();
            return tcp(&host, port);
        };
        clog!("подключение через P2P как «{username}»");
        let mut hints = inv.lan.clone();
        if let Some(l) = last {
            hints.insert(0, l);
        }
        let progress = |stage: crate::p2p::Stage| {
            let text = match stage {
                crate::p2p::Stage::Searching => "ищу сервер…",
                crate::p2p::Stage::Punching => "устанавливаю прямое соединение…",
            };
            self.emit(Event::Progress(text.into()));
        };
        let room = crate::p2p::Room::new(inv.secret);
        let dialed = crate::p2p::dial(&room, &hints, true, Duration::from_secs(20), &progress);
        self.emit(Event::Progress(String::new()));
        match dialed {
            Ok(conn) => {
                let peer = conn.peer().to_string();
                {
                    let mut cfg = self.cfg.lock().unwrap();
                    if cfg.p2p_last != peer {
                        cfg.p2p_last = peer;
                        self.dirty.store(true, Ordering::Relaxed);
                    }
                }
                Link::connect_p2p(Arc::new(conn), inv.fingerprint, &username, &password, bridge.clone())
                    .map_err(|e| describe_connect_error(&e))
            }
            Err(e) => {
                // Запасной путь — ZeroTier, если сеть уже подключена на этом компьютере.
                if let Some(zt) = &inv.zt {
                    let joined = crate::diag::local_addresses().iter().any(|(l, _)| *l == "ZeroTier");
                    if let (true, Some((h, p))) = (joined, crate::config::parse_address(zt)) {
                        clog!("P2P не удалось ({e}) — подключаюсь через ZeroTier");
                        return tcp(&h, p);
                    }
                    return Err(format!("{e}. Запасной путь — ZeroTier: «Сеть» → «Исправить»"));
                }
                Err(e.to_string())
            }
        }
    }

    fn on_link_event(&self, gen: u64, ev: LinkEvent) {
        if self.ctl.lock().unwrap().gen != gen {
            return;
        }
        match ev {
            LinkEvent::Synced { session, .. } => {
                clog!("на связи, сессия {session}");
                self.my_session.store(session, Ordering::SeqCst);
                *self.online_since.lock().unwrap() = Some(std::time::Instant::now());
                self.pings.lock().unwrap().clear();
                *self.last_udp_stats.lock().unwrap() = (0, 0);
                self.set_status(Status::Online);
                self.push_self_state();
                self.emit(Event::Users);
            }
            LinkEvent::UserState(u) => self.on_user_state(u),
            LinkEvent::UserRemove { session, reason } => {
                self.users.lock().unwrap().remove(&session);
                self.audio.remove_user(session);
                if session == self.my_session() && session != 0 {
                    let msg = if reason.is_empty() {
                        "вас отключили от сервера".to_string()
                    } else {
                        format!("вас отключили от сервера: {reason}")
                    };
                    self.ctl.lock().unwrap().fatal = Some(msg);
                }
                self.emit(Event::Users);
            }
            LinkEvent::Rejected { kind, reason } => {
                let mut c = self.ctl.lock().unwrap();
                match kind {
                    proto::REJECT_WRONG_SERVER_PW | proto::REJECT_WRONG_USER_PW => {
                        c.fatal = Some("неверный пароль".into());
                    }
                    proto::REJECT_INVALID_USERNAME => {
                        c.fatal = Some("недопустимое имя".into());
                    }
                    proto::REJECT_USERNAME_IN_USE => c.reject = Some("это имя уже занято".into()),
                    proto::REJECT_SERVER_FULL => c.reject = Some("сервер заполнен".into()),
                    _ => c.reject = Some(if reason.is_empty() { "сервер отклонил вход".into() } else { reason }),
                }
            }
            LinkEvent::Denied(reason) => {
                if !reason.is_empty() {
                    self.emit(Event::Notice(reason));
                }
            }
            LinkEvent::Ping { ms, udp } => {
                let udp_active = self
                    .audio
                    .link
                    .read()
                    .unwrap()
                    .as_ref()
                    .map(|l| l.udp_active())
                    .unwrap_or(false);
                // Показываем задержку того канала, по которому сейчас идёт голос.
                if udp == udp_active {
                    {
                        let mut p = self.pings.lock().unwrap();
                        p.push_back(ms);
                        if p.len() > 30 {
                            p.pop_front();
                        }
                    }
                    self.emit(Event::Ping { ms, udp });
                }
            }
            LinkEvent::UdpState(_) => {}
            LinkEvent::Closed(reason) => {
                let mut c = self.ctl.lock().unwrap();
                c.closed = Some(reason);
                self.cv.notify_all();
            }
        }
    }

    fn on_user_state(&self, u: proto::UserState) {
        let Some(session) = u.session else { return };
        let volume;
        {
            let mut users = self.users.lock().unwrap();
            let e = users.entry(session).or_insert_with(|| User {
                name: String::new(),
                mute: false,
                self_mute: false,
                suppress: false,
                deaf: false,
                self_deaf: false,
                speaking: false,
            });
            if let Some(n) = u.name {
                e.name = n;
            }
            if let Some(v) = u.mute {
                e.mute = v;
            }
            if let Some(v) = u.self_mute {
                e.self_mute = v;
            }
            if let Some(v) = u.suppress {
                e.suppress = v;
            }
            if let Some(v) = u.deaf {
                e.deaf = v;
            }
            if let Some(v) = u.self_deaf {
                e.self_deaf = v;
            }
            volume = self.cfg.lock().unwrap().volumes.get(&e.name).copied().unwrap_or(1.0);
        }
        self.audio.set_volume(session, volume);
        self.emit(Event::Users);
    }

    fn on_audio_event(&self, ev: AudioEvent) {
        match ev {
            AudioEvent::Speaking { session, on } => {
                if session == LOOPBACK_SESSION {
                    self.test_talking.store(on, Ordering::Relaxed);
                    self.emit_self_speaking();
                    return;
                }
                if let Some(u) = self.users.lock().unwrap().get_mut(&session) {
                    u.speaking = on;
                }
                self.emit(Event::Speaking { session, on });
            }
            AudioEvent::SelfTalking(on) => {
                self.self_talking.store(on, Ordering::Relaxed);
                self.emit_self_speaking();
            }
            AudioEvent::DeviceError(e) => self.emit(Event::Notice(e)),
            AudioEvent::Devices { input, output } => self.emit(Event::Devices { input, output }),
        }
    }

    fn emit_self_speaking(&self) {
        let on = self.self_talking.load(Ordering::Relaxed) || self.test_talking.load(Ordering::Relaxed);
        self.emit(Event::Speaking { session: self.my_session(), on });
    }

    pub fn self_speaking(&self) -> bool {
        self.self_talking.load(Ordering::Relaxed) || self.test_talking.load(Ordering::Relaxed)
    }

    pub fn users(&self) -> Vec<UserView> {
        let me = self.my_session();
        // Порядок блокировок везде один: сначала участники, потом настройки.
        let users = self.users.lock().unwrap();
        let cfg = self.cfg.lock().unwrap();
        let mut v: Vec<UserView> = users
            .iter()
            .filter(|(_, u)| !u.name.is_empty())
            .map(|(&session, u)| UserView {
                session,
                name: u.name.clone(),
                muted: u.mute || u.self_mute || u.suppress,
                deafened: u.deaf || u.self_deaf,
                speaking: if session == me { self.self_speaking() } else { u.speaking },
                volume: cfg.volumes.get(&u.name).copied().unwrap_or(1.0),
                is_self: session == me,
            })
            .collect();
        v.sort_by(|a, b| b.is_self.cmp(&a.is_self).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        v
    }

    // --- микрофон и звук ---------------------------------------------------------------------

    fn push_self_state(&self) {
        let deaf = self.audio.deafened.load(Ordering::Relaxed);
        let mute = self.audio.muted.load(Ordering::Relaxed) || deaf;
        if let Some(link) = self.audio.link.read().unwrap().as_ref() {
            link.send_self_state(mute, deaf);
        }
    }

    pub fn set_muted(&self, on: bool) {
        self.audio.muted.store(on, Ordering::Relaxed);
        self.push_self_state();
    }

    pub fn set_deafened(&self, on: bool) {
        self.audio.deafened.store(on, Ordering::Relaxed);
        self.push_self_state();
    }

    pub fn is_muted(&self) -> bool {
        self.audio.muted.load(Ordering::Relaxed)
    }

    pub fn is_deafened(&self) -> bool {
        self.audio.deafened.load(Ordering::Relaxed)
    }

    /// Проверка своего голоса: звук с микрофона идёт в собственные наушники и никому не передаётся.
    pub fn set_mic_test(&self, on: bool) {
        self.audio.mic_test.store(on, Ordering::Relaxed);
    }

    pub fn mic_test(&self) -> bool {
        self.audio.mic_test.load(Ordering::Relaxed)
    }

    /// Текущий уровень микрофона (пик, 0..1) — для индикатора в настройках.
    pub fn mic_level(&self) -> f32 {
        f32::from_bits(self.audio.mic_peak.load(Ordering::Relaxed))
    }

    pub fn set_user_volume(&self, session: u32, volume: f32) {
        let volume = volume.clamp(0.0, 2.0);
        self.audio.set_volume(session, volume);
        let name = self.users.lock().unwrap().get(&session).map(|u| u.name.clone());
        if let Some(name) = name {
            let mut cfg = self.cfg.lock().unwrap();
            if (volume - 1.0).abs() < 0.005 {
                cfg.volumes.remove(&name);
            } else {
                cfg.volumes.insert(name, volume);
            }
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    pub fn set_voice_activation(&self, on: bool) {
        self.audio.vad_mode.store(on, Ordering::Relaxed);
        self.cfg.lock().unwrap().voice_activation = on;
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub fn set_vad_threshold(&self, thr: f32) {
        let thr = thr.clamp(0.001, 0.5);
        self.audio.vad_threshold.store(thr.to_bits(), Ordering::Relaxed);
        self.cfg.lock().unwrap().vad_threshold = thr;
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Шумоподавление: 0 — выключено, 1 — лёгкое, 2 — сильное.
    pub fn set_noise_mode(&self, mode: u8) {
        let mode = mode.min(2);
        self.audio.noise_mode.store(mode as u32, Ordering::Relaxed);
        self.cfg.lock().unwrap().noise_mode = mode;
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub fn set_devices(&self, input: &str, output: &str) {
        {
            let mut d = self.devices.lock().unwrap();
            d.input = input.to_string();
            d.output = output.to_string();
            let mut cfg = self.cfg.lock().unwrap();
            cfg.input_device = input.to_string();
            cfg.output_device = output.to_string();
        }
        self.dirty.store(true, Ordering::Relaxed);
        if let Some(tx) = self.audio_tx.lock().unwrap().as_ref() {
            let _ = tx.send(AudioCmd::Restart);
        }
    }

    // --- клавиша «говорить» ------------------------------------------------------------------

    pub fn ptt_key(&self) -> u32 {
        self.ptt_key.load(Ordering::Relaxed)
    }

    pub fn set_ptt_key(&self, vk: u32) {
        self.ptt_key.store(vk, Ordering::Relaxed);
        self.cfg.lock().unwrap().ptt_key = vk;
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Ждёт следующее нажатие любой клавиши и назначает её (Esc — отмена).
    pub fn begin_key_capture(&self) {
        self.capture_key.store(true, Ordering::SeqCst);
    }

    pub fn cancel_key_capture(&self) {
        self.capture_key.store(false, Ordering::SeqCst);
    }

    fn hotkey_loop(self: Arc<Self>) {
        let timer = crate::win::PreciseTimer::new();
        let mut last = false;
        let mut idle_ticks = 0u32;
        let mut capturing = false;
        let mut prev = [false; 256];
        loop {
            if self.ctl.lock().unwrap().quit {
                return;
            }

            if self.capture_key.load(Ordering::Relaxed) {
                if !capturing {
                    // Запоминаем уже зажатые клавиши, чтобы поймать именно новое нажатие.
                    for vk in crate::win::bindable_keys() {
                        prev[vk as usize] = crate::win::key_down(vk);
                    }
                    capturing = true;
                }
                if crate::win::key_down(0x1B) {
                    self.capture_key.store(false, Ordering::SeqCst);
                    capturing = false;
                    self.emit(Event::KeyCaptured(None));
                } else {
                    for vk in crate::win::bindable_keys() {
                        let down = crate::win::key_down(vk);
                        if down && !prev[vk as usize] {
                            self.capture_key.store(false, Ordering::SeqCst);
                            capturing = false;
                            self.set_ptt_key(vk);
                            self.emit(Event::KeyCaptured(Some(vk)));
                            break;
                        }
                        prev[vk as usize] = down;
                    }
                }
                timer.sleep_ms(15);
                continue;
            }
            capturing = false;

            // Клавишу опрашиваем только когда она нужна: на связи и в режиме «по кнопке».
            let need = self.my_session() != 0 && !self.audio.vad_mode.load(Ordering::Relaxed);
            if !need {
                if last {
                    last = false;
                    self.audio.ptt_down.store(false, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(100));
                idle_ticks += 20;
            } else {
                let vk = self.ptt_key.load(Ordering::Relaxed);
                let down = vk != 0 && crate::win::key_down(vk);
                if down != last {
                    last = down;
                    self.audio.ptt_down.store(down, Ordering::Relaxed);
                }
                timer.sleep_ms(5);
                idle_ticks += 1;
            }

            // Раз в ~2 секунды записываем изменённые настройки на диск.
            if idle_ticks >= 400 {
                idle_ticks = 0;
                self.flush_config();
            }
        }
    }

    pub fn flush_config(&self) {
        if self.persist && self.dirty.swap(false, Ordering::Relaxed) {
            self.cfg.lock().unwrap().save();
        }
    }

    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Relaxed);
    }
}
