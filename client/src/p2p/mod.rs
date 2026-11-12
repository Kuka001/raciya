//! Свой P2P: соединение с сервером за NAT без ZeroTier, без драйвера и без прав администратора.
//!
//! Как это работает:
//! 1. Сервер публикует свой внешний адрес в BitTorrent DHT под ключом, выведенным из секрета
//!    комнаты (`room.rs`), и раз в несколько секунд смотрит, кто «стучится» под другим ключом.
//! 2. Клиент по коду приглашения находит адрес сервера и публикует свой.
//! 3. Обе стороны шлют UDP навстречу друг другу — NAT с обеих сторон пропускает ответы (hole punching).
//! 4. Дальше один UDP-маршрут: надёжный поток для TLS (`flow.rs`) и голосовые датаграммы.
//!
//! Рукопожатие подписано HMAC от секрета комнаты: без кода приглашения сервер не отвечает.
//! Пакеты на общем сокете различаются по первому байту: `d` — DHT, `0x00–0x3F` — STUN,
//! `0xA1–0xA8` — наши.

pub mod bencode;
pub mod dht;
pub mod flow;
pub mod room;
pub mod stun;

use flow::Flow;
use ring::rand::{SecureRandom, SystemRandom};
pub use room::{Invite, Room};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const T_HELLO: u8 = 0xA1;
const T_HELLO_ACK: u8 = 0xA2;
const T_PUNCH: u8 = 0xA3;
const VERSION: u8 = 1;

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    SystemRandom::new().fill(&mut b).expect("random");
    b
}

/// Стадии подключения для интерфейса.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Stage {
    Searching,
    Punching,
}

struct Dial {
    conn_id: u64,
    nonce: [u8; 16],
    candidates: Vec<SocketAddr>,
    /// Адреса из DHT, которые сообщил только один узел (могут быть подложными): HELLO — раз в секунду.
    weak: Vec<SocketAddr>,
    done: Option<Arc<Flow>>,
    /// Соединение уже установлено: запоздавшие дубли ответа сервера не должны создать второй поток.
    established: bool,
}

enum Role {
    Client(Mutex<Dial>, Condvar),
    Server {
        on_flow: Box<dyn Fn(Arc<Flow>) + Send + Sync>,
        seen: Mutex<HashMap<[u8; 16], Instant>>,
        last_flow: AtomicU64,
    },
}

pub struct Endpoint {
    sock: Arc<UdpSocket>,
    clock: Instant,
    room: Room,
    role: Role,
    flows: Mutex<HashMap<u64, Arc<Flow>>>,
    pub dht: dht::Dht,
    stun: Mutex<HashMap<[u8; 12], SyncSender<SocketAddr>>>,
    stop: AtomicBool,
}

impl Endpoint {
    fn bind(port: u16, room: Room, role: Role) -> io::Result<Arc<Endpoint>> {
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))?;
        sock.set_read_timeout(Some(Duration::from_millis(200)))?;
        crate::win::mark_voice_socket(&sock);
        crate::win::disable_udp_connreset(&sock);
        let sock = Arc::new(sock);
        let ep = Arc::new(Endpoint {
            dht: dht::Dht::new(sock.clone()),
            sock,
            clock: Instant::now(),
            room,
            role,
            flows: Mutex::new(HashMap::new()),
            stun: Mutex::new(HashMap::new()),
            stop: AtomicBool::new(false),
        });
        let e = ep.clone();
        std::thread::Builder::new().name("p2p-rx".into()).spawn(move || {
            crate::win::set_thread_priority(crate::win::Prio::High);
            e.recv_loop();
        })?;
        let e = ep.clone();
        std::thread::Builder::new().name("p2p-timer".into()).spawn(move || {
            crate::win::set_thread_priority(crate::win::Prio::Low);
            e.timer_loop();
        })?;
        Ok(ep)
    }

    pub fn local_port(&self) -> u16 {
        self.sock.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Клиент уже соединился — фоновые поиски в DHT больше не нужны.
    fn established(&self) -> bool {
        match &self.role {
            Role::Client(d, _) => d.lock().unwrap().established,
            Role::Server { .. } => false,
        }
    }

    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        for f in self.flows.lock().unwrap().drain().map(|(_, f)| f) {
            f.shutdown();
        }
    }

    fn recv_loop(&self) {
        let mut buf = [0u8; 2048];
        while !self.stopped() {
            match self.sock.recv_from(&mut buf) {
                Ok((n, from)) => self.on_packet(&buf[..n], from),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    fn timer_loop(&self) {
        while !self.stopped() {
            let flows: Vec<Arc<Flow>> = self.flows.lock().unwrap().values().cloned().collect();
            let busy = flows.iter().any(|f| f.has_unacked());
            for f in &flows {
                if !f.tick() {
                    self.flows.lock().unwrap().remove(&f.conn_id);
                }
            }
            // Пока есть неподтверждённые данные — часто, иначе редко (лёгкий простой).
            std::thread::sleep(Duration::from_millis(if busy { 20 } else { 200 }));
        }
    }

    fn on_packet(&self, p: &[u8], from: SocketAddr) {
        let Some(&ty) = p.first() else { return };
        match ty {
            b'd' => self.dht.on_packet(from, p),
            0x00..=0x3F if stun::is_stun(p) => {
                if let (Some(tid), Some(addr)) = (stun::transaction(p), stun::mapped(p)) {
                    if let Some(tx) = self.stun.lock().unwrap().remove(&tid) {
                        let _ = tx.try_send(addr);
                    }
                }
            }
            T_HELLO => self.on_hello(p, from),
            T_HELLO_ACK => self.on_hello_ack(p, from),
            T_PUNCH => self.on_punch(p, from),
            flow::T_DATA..=flow::T_CLOSE if p.len() >= 9 => {
                let conn_id = u64::from_be_bytes(p[1..9].try_into().unwrap());
                let f = self.flows.lock().unwrap().get(&conn_id).cloned();
                if let Some(f) = f {
                    if f.peer == from {
                        f.on_packet(ty, &p[9..]);
                    }
                }
            }
            _ => {}
        }
    }

    fn hello(&self, conn_id: u64, nonce: &[u8; 16]) -> Vec<u8> {
        let mut p = vec![T_HELLO, VERSION];
        p.extend_from_slice(&conn_id.to_be_bytes());
        p.extend_from_slice(nonce);
        let mac = self.room.mac(&p);
        p.extend_from_slice(&mac);
        p
    }

    fn hello_ack(&self, conn_id: u64, nonce: &[u8]) -> Vec<u8> {
        let mut p = vec![T_HELLO_ACK, VERSION];
        p.extend_from_slice(&conn_id.to_be_bytes());
        p.extend_from_slice(nonce);
        let mac = self.room.mac(&p);
        p.extend_from_slice(&mac);
        p
    }

    fn punch(&self) -> Vec<u8> {
        let mut p = vec![T_PUNCH, VERSION];
        p.extend_from_slice(&random::<16>());
        let mac = self.room.mac(&p);
        p.extend_from_slice(&mac);
        p
    }

    /// Сервер: клиент с кодом приглашения просит соединения.
    fn on_hello(&self, p: &[u8], from: SocketAddr) {
        let Role::Server { on_flow, seen, last_flow } = &self.role else { return };
        if p.len() != 42 || p[1] != VERSION || !self.room.check(&p[..26], &p[26..]) {
            return;
        }
        let conn_id = u64::from_be_bytes(p[2..10].try_into().unwrap());
        let nonce: [u8; 16] = p[10..26].try_into().unwrap();
        let existing = self.flows.lock().unwrap().get(&conn_id).cloned();
        if let Some(f) = existing {
            // Повтор HELLO (наш ответ потерялся) — отвечаем ещё раз.
            if f.peer == from {
                let _ = self.sock.send_to(&self.hello_ack(conn_id, &nonce), from);
            }
            return;
        }
        {
            let mut s = seen.lock().unwrap();
            let now = Instant::now();
            s.retain(|_, at| now.duration_since(*at) < Duration::from_secs(600));
            if s.insert(nonce, now).is_some() {
                return; // повтор старого пакета
            }
        }
        let f = Flow::new(conn_id, from, self.sock.clone(), self.clock);
        self.flows.lock().unwrap().insert(conn_id, f.clone());
        last_flow.store(self.clock.elapsed().as_secs(), Ordering::Relaxed);
        let ack = self.hello_ack(conn_id, &nonce);
        let _ = self.sock.send_to(&ack, from);
        let _ = self.sock.send_to(&ack, from);
        on_flow(f);
    }

    /// Клиент: сервер ответил — соединение установлено (побеждает первый ответ).
    fn on_hello_ack(&self, p: &[u8], from: SocketAddr) {
        let Role::Client(dial, cv) = &self.role else { return };
        if p.len() != 42 || p[1] != VERSION || !self.room.check(&p[..26], &p[26..]) {
            return;
        }
        let mut d = dial.lock().unwrap();
        if d.established || p[2..10] != d.conn_id.to_be_bytes() || p[10..26] != d.nonce {
            return;
        }
        let f = Flow::new(d.conn_id, from, self.sock.clone(), self.clock);
        self.flows.lock().unwrap().insert(d.conn_id, f.clone());
        d.established = true;
        d.done = Some(f);
        cv.notify_all();
    }

    /// Клиент: сервер «постучался» с этого адреса — отвечаем HELLO туда же.
    fn on_punch(&self, p: &[u8], from: SocketAddr) {
        let Role::Client(dial, _) = &self.role else { return };
        if p.len() != 34 || p[1] != VERSION || !self.room.check(&p[..18], &p[18..]) {
            return;
        }
        let (conn_id, nonce) = {
            let mut d = dial.lock().unwrap();
            if d.established {
                return;
            }
            if !d.candidates.contains(&from) {
                d.candidates.push(from);
            }
            (d.conn_id, d.nonce)
        };
        let _ = self.sock.send_to(&self.hello(conn_id, &nonce), from);
    }

    /// Адреса сервера из DHT: подтверждённые несколькими узлами — в основной список,
    /// остальные (не больше трёх) — в «слабый», с редкими попытками.
    fn add_candidates(&self, peers: &[(SocketAddr, usize)]) -> usize {
        let Role::Client(dial, _) = &self.role else { return 0 };
        let mut d = dial.lock().unwrap();
        for &(a, n) in peers {
            if d.candidates.contains(&a) || d.weak.contains(&a) {
                continue;
            }
            if n >= 2 {
                d.candidates.push(a);
            } else if d.weak.len() < 3 {
                d.weak.push(a);
            }
        }
        d.candidates.len() + d.weak.len()
    }

    /// Внешний адрес нашего сокета по данным STUN-сервера.
    pub fn stun(&self, server: &str, timeout: Duration) -> Option<SocketAddr> {
        let addr = server.to_socket_addrs().ok()?.find(|a| a.is_ipv4())?;
        let tid: [u8; 12] = random();
        let (tx, rx) = sync_channel(1);
        self.stun.lock().unwrap().insert(tid, tx);
        let _ = self.sock.send_to(&stun::request(&tid), addr);
        let r = rx.recv_timeout(timeout).ok();
        self.stun.lock().unwrap().remove(&tid);
        r
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Готовое P2P-соединение клиента: поток для TLS и датаграммы для голоса.
pub struct Conn {
    ep: Arc<Endpoint>,
    pub flow: Arc<Flow>,
}

impl Conn {
    pub fn peer(&self) -> SocketAddr {
        self.flow.peer
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.flow.shutdown();
        self.ep.shutdown();
    }
}

impl crate::transport::Stream for Conn {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        crate::transport::Stream::recv(self.flow.as_ref(), buf)
    }

    fn send_all(&self, buf: &[u8]) -> io::Result<()> {
        self.flow.send_all(buf)
    }

    fn set_timeout(&self, t: Duration) {
        self.flow.set_timeout(t)
    }

    fn close(&self) {
        self.flow.shutdown()
    }
}

impl crate::transport::Datagrams for Conn {
    fn send(&self, buf: &[u8]) -> io::Result<()> {
        crate::transport::Datagrams::send(self.flow.as_ref(), buf)
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        crate::transport::Datagrams::recv(self.flow.as_ref(), buf)
    }
}

/// Подключение к серверу комнаты. `hints` — адреса, которые стоит попробовать сразу
/// (локальная сеть из кода приглашения, последний удачный адрес); `use_dht` — искать через DHT.
pub fn dial(
    room: &Room,
    hints: &[SocketAddr],
    use_dht: bool,
    timeout: Duration,
    progress: &(dyn Fn(Stage) + Sync),
) -> io::Result<Conn> {
    let conn_id = u64::from_be_bytes(random());
    let nonce: [u8; 16] = random();
    let dial = Dial { conn_id, nonce, candidates: hints.to_vec(), weak: Vec::new(), done: None, established: false };
    let ep = Endpoint::bind(0, room.clone(), Role::Client(Mutex::new(dial), Condvar::new()))?;
    progress(Stage::Searching);
    let found = Arc::new(AtomicUsize::new(0));
    if use_dht {
        let e = ep.clone();
        let target = room.ih_srv;
        let f = found.clone();
        let deadline = Instant::now() + timeout;
        let _ = std::thread::Builder::new().name("p2p-find".into()).spawn(move || {
            // Поиск в DHT не всегда сходится с первого раза — повторяем, пока есть время
            // (второй поиск начинается с уже найденных хороших узлов и идёт быстрее).
            while !e.stopped() && !e.established() && Instant::now() + Duration::from_secs(3) < deadline {
                let left = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(10));
                let l = e.dht.lookup(&target, left);
                clog!("P2P: DHT ответили {} узлов, адресов сервера: {}", l.responded, l.peers.len());
                e.dht.save_nodes();
                if !l.peers.is_empty() {
                    f.store(e.add_candidates(&l.peers), Ordering::SeqCst);
                    break;
                }
            }
        });
        let e = ep.clone();
        let target = room.ih_cli;
        let _ = std::thread::Builder::new().name("p2p-knock".into()).spawn(move || {
            // Сообщаем свой адрес: сервер увидит его и «постучится» навстречу.
            let l = e.dht.lookup(&target, Duration::from_secs(10));
            if e.established() {
                return;
            }
            let ok = e.dht.announce(&target, &l.closest, e.local_port());
            clog!("P2P: свой адрес опубликован у {ok} узлов");
        });
    }
    let started = Instant::now();
    let Role::Client(dial, cv) = &ep.role else { unreachable!() };
    let mut punching = false;
    let mut round = 0u32;
    loop {
        let (targets, weak) = {
            let d = dial.lock().unwrap();
            (d.candidates.clone(), d.weak.clone())
        };
        if !punching && targets.len() + weak.len() > hints.len() {
            punching = true;
            progress(Stage::Punching);
        }
        let hello = ep.hello(conn_id, &nonce);
        for t in &targets {
            let _ = ep.sock.send_to(&hello, t);
        }
        if round % 5 == 0 {
            for t in &weak {
                let _ = ep.sock.send_to(&hello, t);
            }
        }
        round += 1;
        let d = dial.lock().unwrap();
        let (mut d, _) = cv.wait_timeout_while(d, Duration::from_millis(200), |d| d.done.is_none()).unwrap();
        if let Some(flow) = d.done.take() {
            drop(d);
            clog!("P2P: соединение с {} за {} мс", flow.peer, started.elapsed().as_millis());
            return Ok(Conn { ep, flow });
        }
        drop(d);
        if started.elapsed() >= timeout {
            ep.shutdown();
            let msg = if !use_dht || found.load(Ordering::SeqCst) > 0 || !targets.is_empty() {
                "сервер не ответил: прямое соединение не установилось"
            } else {
                "сервер не найден в сети: компьютер с сервером выключен или ещё не опубликовал адрес"
            };
            return Err(io::Error::new(io::ErrorKind::TimedOut, msg));
        }
    }
}

/// Состояние сервера в P2P для интерфейса и диагностики.
#[derive(Clone, Debug, Default)]
pub struct HostStatus {
    /// Внешний адрес сервера (по ответам DHT).
    pub external: Option<SocketAddr>,
    /// Узлы DHT подтвердили публикацию адреса.
    pub announced: usize,
    /// Внешний порт одинаковый для разных узлов (NAT пробиваемый); `None` — ещё не известно.
    pub stable_port: Option<bool>,
    /// Первая попытка публикации уже была (можно судить об `announced`).
    pub attempted: bool,
}

/// Сервер в P2P: принимает соединения по коду приглашения и держит адрес в DHT.
pub struct Host {
    ep: Arc<Endpoint>,
    status: Arc<Mutex<HostStatus>>,
}

type Notify = Arc<dyn Fn() + Send + Sync>;

impl Host {
    /// `on_flow` получает каждое новое соединение. `use_dht = false` — только локально (проверки).
    pub fn start(
        room: Room,
        port: u16,
        use_dht: bool,
        on_flow: Box<dyn Fn(Arc<Flow>) + Send + Sync>,
    ) -> io::Result<Arc<Host>> {
        Self::start_with(room, port, use_dht, on_flow, Arc::new(|| {}))
    }

    /// То же, а `on_status` вызывается, когда меняется состояние в DHT (для интерфейса).
    pub fn start_with(
        room: Room,
        port: u16,
        use_dht: bool,
        on_flow: Box<dyn Fn(Arc<Flow>) + Send + Sync>,
        on_status: Notify,
    ) -> io::Result<Arc<Host>> {
        let role = Role::Server { on_flow, seen: Mutex::new(HashMap::new()), last_flow: AtomicU64::new(0) };
        let ep = Endpoint::bind(port, room, role)?;
        let status = Arc::new(Mutex::new(HostStatus::default()));
        if use_dht {
            let (e, st) = (ep.clone(), status.clone());
            std::thread::Builder::new().name("p2p-announce".into()).spawn(move || {
                crate::win::set_thread_priority(crate::win::Prio::Low);
                announcer(e, st, on_status);
            })?;
        }
        Ok(Arc::new(Host { ep, status }))
    }

    pub fn port(&self) -> u16 {
        self.ep.local_port()
    }

    pub fn status(&self) -> HostStatus {
        self.status.lock().unwrap().clone()
    }

    pub fn stop(&self) {
        self.ep.shutdown();
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.ep.shutdown();
    }
}

/// Фоновая работа сервера в DHT: публикация адреса и «стук» навстречу новым клиентам.
fn announcer(ep: Arc<Endpoint>, status: Arc<Mutex<HostStatus>>, on_status: Notify) {
    let Role::Server { last_flow, .. } = &ep.role else { return };
    let room = ep.room.clone();
    let port = ep.local_port();
    let mut next_full = Instant::now();
    let mut next_clients = Instant::now();
    let mut clients_nodes: Vec<(dht::Node, Vec<u8>)> = Vec::new();
    let mut knocked: HashMap<SocketAddr, Knock> = HashMap::new();
    let started = Instant::now();
    while !ep.stopped() {
        // Ближайшие узлы для ключа клиентов пересматриваем чаще: клиент мог опубликовать адрес
        // у немного других узлов.
        if Instant::now() >= next_clients && Instant::now() < next_full {
            let lc = ep.dht.lookup(&room.ih_cli, Duration::from_secs(10));
            if !lc.closest.is_empty() {
                clients_nodes = lc.closest;
            }
            next_clients = Instant::now() + Duration::from_secs(if clients_nodes.is_empty() { 60 } else { 120 });
            knock(&ep, lc.reports.clone(), &mut knocked);
        }
        if Instant::now() >= next_full {
            let l = ep.dht.lookup(&room.ih_srv, Duration::from_secs(10));
            let announced = ep.dht.announce(&room.ih_srv, &l.closest, port);
            let lc = ep.dht.lookup(&room.ih_cli, Duration::from_secs(10));
            clients_nodes = lc.closest;
            next_clients = Instant::now() + Duration::from_secs(120);
            ep.dht.save_nodes();
            {
                let mut st = status.lock().unwrap();
                st.attempted = true;
                st.announced = announced;
                st.external = l.external.first().copied().or(st.external);
                let ports: Vec<u16> = l.external.iter().map(|a| a.port()).collect();
                if ports.len() >= 2 {
                    st.stable_port = Some(ports.iter().all(|&p| p == ports[0]));
                }
            }
            slog!(
                "P2P: адрес опубликован у {announced} узлов DHT (ответили {}), внешний адрес {:?}",
                l.responded,
                l.external.first()
            );
            on_status();
            // Если DHT недоступна — пробуем снова через минуту, иначе раз в 10 минут.
            next_full = Instant::now() + Duration::from_secs(if announced > 0 { 600 } else { 60 });
            knock(&ep, lc.reports.clone(), &mut knocked);
        }
        // Пока недавно кто-то подключался (или сервер только что запущен) — опрашиваем чаще.
        let since_flow = ep.clock.elapsed().as_secs().saturating_sub(last_flow.load(Ordering::Relaxed));
        let active = started.elapsed() < Duration::from_secs(600) || since_flow < 600;
        let pause = if active { 3 } else { 8 };
        for _ in 0..pause * 5 {
            if ep.stopped() {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        if !clients_nodes.is_empty() {
            let peers = ep.dht.poll(&room.ih_cli, &clients_nodes);
            knock(&ep, peers, &mut knocked);
        }
    }
}

/// Что известно об адресе, который появился под ключом клиентов.
struct Knock {
    first: Instant,
    last: Option<Instant>,
    /// Узлы DHT, которые сообщили этот адрес.
    reporters: std::collections::HashSet<SocketAddr>,
}

/// «Стук» навстречу клиентам: несколько пакетов открывают наш NAT для их адресов.
/// Только по адресам, которые подтвердили хотя бы два узла DHT (бывают узлы, отвечающие
/// подложными адресами — слать пакеты наугад чужим компьютерам нельзя), каждому — не чаще
/// раза в 30 с и только первые 3 минуты после появления, не больше 4 новых адресов за раз.
fn knock(ep: &Endpoint, reports: Vec<(SocketAddr, SocketAddr)>, knocked: &mut HashMap<SocketAddr, Knock>) {
    let now = Instant::now();
    knocked.retain(|_, k| now.duration_since(k.first) < Duration::from_secs(1800));
    for (p, node) in reports {
        knocked
            .entry(p)
            .or_insert_with(|| Knock { first: now, last: None, reporters: Default::default() })
            .reporters
            .insert(node);
    }
    let mut new_ones = 0;
    for (p, k) in knocked.iter_mut() {
        let fresh = now.duration_since(k.first) < Duration::from_secs(180);
        let due = k.last.map(|t| now.duration_since(t) > Duration::from_secs(30)).unwrap_or(true);
        if !fresh || !due || k.reporters.len() < 2 {
            continue;
        }
        if k.last.is_none() {
            if new_ones >= 4 {
                continue;
            }
            new_ones += 1;
            slog!("P2P: клиент {p} ищет сервер — стучусь навстречу");
        }
        k.last = Some(now);
        for _ in 0..3 {
            let _ = ep.sock.send_to(&ep.punch(), *p);
        }
    }
}

/// Проверка NAT: внешний адрес по двум STUN-серверам. Один и тот же порт — NAT пробиваемый.
pub fn nat_check() -> Option<(SocketAddr, Option<SocketAddr>)> {
    let room = Room::new([0; 16]);
    let ep = Endpoint::bind(0, room, Role::Client(Mutex::new(Dial { conn_id: 0, nonce: [0; 16], candidates: vec![], weak: vec![], done: None, established: false }), Condvar::new())).ok()?;
    let a = stun::SERVERS.iter().find_map(|s| ep.stun(s, Duration::from_millis(1500)))?;
    let b = stun::SERVERS.iter().rev().find_map(|s| ep.stun(s, Duration::from_millis(1500)));
    ep.shutdown();
    Some((a, b))
}

/// `raciya.exe --p2p-selftest`: проверка DHT и NAT на этом компьютере.
pub fn selftest() {
    println!("p2p selftest");
    match nat_check() {
        Some((a, Some(b))) => println!(
            "  STUN: внешний адрес {a} и {b} — {}",
            if a.port() == b.port() { "порт одинаковый, NAT пробиваемый" } else { "порты разные: симметричный NAT" }
        ),
        Some((a, None)) => println!("  STUN: внешний адрес {a} (второй сервер не ответил)"),
        None => println!("  STUN: нет ответа (UDP наружу закрыт?)"),
    }
    let room = Room::new(Room::generate());
    let host = match Host::start(room.clone(), 0, false, Box::new(|_| {})) {
        Ok(h) => h,
        Err(e) => {
            println!("  сокет: {e}");
            return;
        }
    };
    let t0 = Instant::now();
    let l = host.ep.dht.lookup(&room.ih_srv, Duration::from_secs(10));
    println!(
        "  DHT: ответили {} узлов за {} мс, ближайших с токеном: {}, внешний адрес по DHT: {:?}",
        l.responded,
        t0.elapsed().as_millis(),
        l.closest.len(),
        l.external.first()
    );
    let ok = host.ep.dht.announce(&room.ih_srv, &l.closest, host.port());
    println!("  DHT: адрес опубликован у {ok} узлов");
    std::thread::sleep(Duration::from_secs(2));
    // Второй сокет ищет опубликованный адрес — так же, как это сделает друг.
    let probe = Host::start(Room::new(Room::generate()), 0, false, Box::new(|_| {})).expect("socket");
    let t1 = Instant::now();
    let found = probe.ep.dht.lookup(&room.ih_srv, Duration::from_secs(10));
    let found_addrs: Vec<String> = found.peers.iter().map(|(a, n)| format!("{a} (узлов: {n})")).collect();
    println!(
        "  DHT: поиск комнаты {} мс, ответили {} узлов, найдено адресов: {} {:?}",
        t1.elapsed().as_millis(),
        found.responded,
        found.peers.len(),
        found_addrs
    );
    let same = found.closest.iter().filter(|(n, _)| l.closest.iter().any(|(m, _)| m.addr == n.addr)).count();
    println!("  DHT: общих ближайших узлов у двух поисков: {same} из {}", l.closest.len());
    // Прямой вопрос тем самым узлам, у которых опубликован адрес.
    let direct = probe.ep.dht.poll(&room.ih_srv, &l.closest);
    println!("  DHT: узлы, где опубликован адрес, отвечают: {direct:?}");
    host.ep.dht.save_nodes();
}

#[cfg(test)]
mod tests;
