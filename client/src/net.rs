//! Соединение с сервером: управляющий канал TLS/TCP и голосовой канал UDP (OCB2-AES128).
//! Если UDP недоступен, голос идёт через TCP-туннель (запасной путь).
//!
//! Запись в TLS делает отдельный поток из очереди: звуковой поток и интерфейс никогда
//! не ждут сеть. Голос через туннель при переполнении очереди просто отбрасывается.

use crate::framing::{frame, frame_msg, Deframer};
use crate::ocb2::CryptState;
use crate::proto::*;
use crate::transport::{Datagrams, Stream, StreamWriter};
use crate::varint::{read_varint, write_varint};
use prost::Message;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConnection, DigitallySignedStruct, SignatureScheme};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub enum LinkEvent {
    Synced { session: u32, welcome: String },
    UserState(UserState),
    UserRemove { session: u32, reason: String },
    Rejected { kind: i32, reason: String },
    Denied(String),
    Ping { ms: f32, udp: bool },
    UdpState(bool),
    Closed(String),
}

pub trait LinkHandler: Send + Sync + 'static {
    fn on_voice(&self, session: u32, seq: u64, opus: &[u8], last: bool);
    fn on_event(&self, ev: LinkEvent);
}

#[derive(Debug)]
struct ServerCert {
    provider: Arc<CryptoProvider>,
    /// Начало SHA-256 сертификата из кода приглашения: сервер должен быть именно тот.
    expect: Option<[u8; 16]>,
}

/// Сервер использует самоподписанный сертификат, поэтому цепочка доверия не проверяется.
/// Если адрес пришёл из кода приглашения v2, сертификат сверяется с отпечатком из кода —
/// подменить сервер нельзя. Подписи рукопожатия проверяются как обычно.
impl ServerCertVerifier for ServerCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(expect) = self.expect {
            let d = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
            if d.as_ref()[..16] != expect {
                return Err(rustls::Error::General("сертификат сервера не совпадает с кодом приглашения".into()));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub struct Link {
    tls: Mutex<ClientConnection>,
    /// Управляющий канал: TCP или P2P-поток.
    stream: Arc<dyn Stream>,
    /// Голос: UDP-сокет или датаграммы P2P-потока.
    dgram: Arc<dyn Datagrams>,
    /// Кадры для потока записи.
    tx: SyncSender<Vec<u8>>,
    crypt: Mutex<Option<CryptState>>,
    handler: Arc<dyn LinkHandler>,
    alive: AtomicBool,
    closed_sent: AtomicBool,
    udp_ok: AtomicBool,
    /// Для проверок: не пользоваться UDP вообще (как при закрытом брандмауэре).
    udp_disabled: AtomicBool,
    last_udp_rx_ms: AtomicU64,
    last_resync_ms: AtomicU64,
    bad_udp: AtomicU32,
    session: AtomicU32,
    start: Instant,
    pub server_addr: SocketAddr,
    pub dscp_marked: AtomicBool,
}

fn other(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.into())
}

fn resolve(host: &str, port: u16) -> io::Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| other(format!("адрес «{host}» не найден")))?
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| other(format!("адрес «{host}» не найден")))
}

impl Link {
    /// Устанавливает TCP-соединение, начинает TLS-рукопожатие и запускает рабочие потоки.
    /// Об успешном входе сообщит событие `Synced`, о любом разрыве — `Closed`.
    pub fn connect(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        handler: Arc<dyn LinkHandler>,
    ) -> io::Result<Arc<Link>> {
        let addr = resolve(host, port)?;
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(6))?;
        tcp.set_nodelay(true)?;
        // Сервер отвечает на ping каждые несколько секунд; тишина дольше 20 с означает обрыв.
        tcp.set_read_timeout(Some(Duration::from_secs(20)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(10)))?;

        let bind: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let udp = UdpSocket::bind(bind)?;
        udp.connect(addr)?;
        udp.set_read_timeout(Some(Duration::from_millis(500)))?;
        let dscp = crate::win::mark_voice_socket(&udp);

        Link::start(Arc::new(tcp), Arc::new(udp), host, addr, None, dscp, username, password, handler)
    }

    /// Соединение через P2P (код приглашения v2): TLS и голос внутри одного UDP-потока.
    pub fn connect_p2p(
        conn: Arc<crate::p2p::Conn>,
        fingerprint: [u8; 16],
        username: &str,
        password: &str,
        handler: Arc<dyn LinkHandler>,
    ) -> io::Result<Arc<Link>> {
        let addr = conn.peer();
        Stream::set_timeout(conn.as_ref(), Duration::from_secs(20));
        Link::start(conn.clone(), conn, "mumble.invalid", addr, Some(fingerprint), false, username, password, handler)
    }

    #[allow(clippy::too_many_arguments)]
    fn start(
        stream: Arc<dyn Stream>,
        dgram: Arc<dyn Datagrams>,
        host: &str,
        addr: SocketAddr,
        expect: Option<[u8; 16]>,
        dscp: bool,
        username: &str,
        password: &str,
        handler: Arc<dyn LinkHandler>,
    ) -> io::Result<Arc<Link>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| other(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerCert { provider, expect }))
            .with_no_client_auth();
        let name = ServerName::try_from(host.to_string())
            .or_else(|_| ServerName::try_from("mumble.invalid".to_string()))
            .map_err(|e| other(e.to_string()))?;
        let conn = ClientConnection::new(Arc::new(cfg), name).map_err(|e| other(e.to_string()))?;

        let (tx, rx) = sync_channel::<Vec<u8>>(256);
        let link = Arc::new(Link {
            tls: Mutex::new(conn),
            stream,
            dgram,
            tx,
            crypt: Mutex::new(None),
            handler,
            alive: AtomicBool::new(true),
            closed_sent: AtomicBool::new(false),
            udp_ok: AtomicBool::new(false),
            udp_disabled: AtomicBool::new(false),
            last_udp_rx_ms: AtomicU64::new(0),
            last_resync_ms: AtomicU64::new(0),
            bad_udp: AtomicU32::new(0),
            session: AtomicU32::new(0),
            start: Instant::now(),
            server_addr: addr,
            dscp_marked: AtomicBool::new(dscp),
        });

        // Сообщения ставятся в очередь TLS и уйдут сразу после рукопожатия.
        link.write_now(&frame_msg(
            T_VERSION,
            &Version {
                version_v1: Some(PROTOCOL_VERSION),
                release: Some(format!("Raciya {}", env!("CARGO_PKG_VERSION"))),
                os: Some("Windows".into()),
                os_version: None,
                version_v2: None,
            },
        ))?;
        link.write_now(&frame_msg(
            T_AUTHENTICATE,
            &Authenticate {
                username: Some(username.to_string()),
                password: if password.is_empty() { None } else { Some(password.to_string()) },
                opus: Some(true),
            },
        ))?;

        let l = link.clone();
        std::thread::Builder::new()
            .name("net-tcp".into())
            .spawn(move || {
                crate::win::set_thread_priority(crate::win::Prio::Low);
                let reason = match l.tcp_loop() {
                    Ok(()) => "соединение закрыто".to_string(),
                    Err(e) => describe_io(&e),
                };
                l.shutdown(reason);
            })?;
        let l = link.clone();
        std::thread::Builder::new()
            .name("net-tx".into())
            .spawn(move || {
                crate::win::set_thread_priority(crate::win::Prio::Low);
                l.writer_loop(rx);
            })?;
        let l = link.clone();
        std::thread::Builder::new()
            .name("net-udp".into())
            .spawn(move || {
                crate::win::set_thread_priority(crate::win::Prio::High);
                l.udp_loop();
            })?;
        let l = link.clone();
        std::thread::Builder::new()
            .name("net-tick".into())
            .spawn(move || {
                crate::win::set_thread_priority(crate::win::Prio::Low);
                l.ticker();
            })?;
        Ok(link)
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    pub fn udp_active(&self) -> bool {
        self.udp_ok.load(Ordering::Relaxed)
    }

    pub fn session(&self) -> u32 {
        self.session.load(Ordering::Relaxed)
    }

    /// Для проверок: отключить UDP и пользоваться только TCP-туннелем.
    pub fn set_udp_disabled(&self, on: bool) {
        self.udp_disabled.store(on, Ordering::SeqCst);
        if on {
            self.udp_ok.store(false, Ordering::SeqCst);
        }
    }

    /// Счётчики принятых голосовых пакетов: (принято, опоздало, потеряно).
    pub fn udp_stats(&self) -> (u32, u32, u32) {
        let c = self.crypt.lock().unwrap();
        c.as_ref().map(|c| (c.good, c.late, c.lost)).unwrap_or((0, 0, 0))
    }

    /// Закрывает соединение (по желанию пользователя).
    pub fn close(&self) {
        self.shutdown("отключено".into());
    }

    fn shutdown(&self, reason: String) {
        self.alive.store(false, Ordering::SeqCst);
        self.stream.close();
        if !self.closed_sent.swap(true, Ordering::SeqCst) {
            self.handler.on_event(LinkEvent::Closed(reason));
        }
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn now_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    fn flush_locked(&self, tls: &mut ClientConnection) -> io::Result<()> {
        let mut w = StreamWriter(self.stream.as_ref());
        while tls.wants_write() {
            tls.write_tls(&mut w)?;
        }
        Ok(())
    }

    /// Запись прямо из вызывающего потока — только до запуска рабочих потоков.
    fn write_now(&self, data: &[u8]) -> io::Result<()> {
        let mut tls = self.tls.lock().unwrap();
        tls.writer().write_all(data)?;
        self.flush_locked(&mut tls)
    }

    fn writer_loop(&self, rx: Receiver<Vec<u8>>) {
        while self.is_alive() {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(f) => {
                    let r = {
                        let mut tls = self.tls.lock().unwrap();
                        tls.writer().write_all(&f).and_then(|_| self.flush_locked(&mut tls))
                    };
                    if let Err(e) = r {
                        self.shutdown(describe_io(&e));
                        return;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    /// Управляющее сообщение. Если очередь переполнена, сервер давно не принимает данные —
    /// соединение считается оборванным (программа переподключится сама).
    fn send_frame(&self, f: Vec<u8>) {
        if let Err(TrySendError::Full(_)) = self.tx.try_send(f) {
            self.shutdown("сервер не принимает данные".into());
        }
    }

    fn send_msg<M: Message>(&self, ty: u16, msg: &M) {
        self.send_frame(frame_msg(ty, msg));
    }

    /// Отправляет голосовой пакет (в открытом виде, классический формат):
    /// по UDP с шифрованием, а если UDP недоступен — через TCP-туннель.
    pub fn send_voice(&self, plain: &[u8]) {
        if !self.is_alive() || plain.len() > 1400 {
            return;
        }
        if self.udp_ok.load(Ordering::Relaxed) && !self.udp_disabled.load(Ordering::Relaxed) {
            let mut out = [0u8; 1408];
            let n = {
                let mut c = self.crypt.lock().unwrap();
                match c.as_mut() {
                    Some(c) => c.encrypt(plain, &mut out),
                    None => 0,
                }
            };
            if n > 0 {
                let r = self.dgram.send(&out[..n]);
                if crate::win::trace_level() > 0 && (out[0] <= 1 || out[0] == 255 || r.is_err()) {
                    eprintln!("udp: sent ivbyte={} plain_head={:02x?} result={:?}", out[0], &plain[..plain.len().min(4)], r);
                }
                return;
            }
        }
        // Туннель: при переполнении очереди пакет отбрасывается — голос не ждёт.
        let _ = self.tx.try_send(frame(T_UDPTUNNEL, plain));
    }

    /// Сообщает серверу состояние «микрофон выключен / звук выключен».
    pub fn send_self_state(&self, self_mute: bool, self_deaf: bool) {
        let session = self.session();
        if session == 0 {
            return;
        }
        self.send_msg(
            T_USERSTATE,
            &UserState {
                session: Some(session),
                self_mute: Some(self_mute),
                self_deaf: Some(self_deaf),
                ..Default::default()
            },
        );
    }

    fn tcp_loop(self: &Arc<Self>) -> io::Result<()> {
        let mut raw = vec![0u8; 16 * 1024];
        let mut frames = Deframer::new(8 * 1024 * 1024);
        let mut tmp = [0u8; 4096];
        {
            let mut tls = self.tls.lock().unwrap();
            self.flush_locked(&mut tls)?;
        }
        while self.is_alive() {
            let n = self.stream.recv(&mut raw)?;
            if n == 0 {
                return Err(other("сервер закрыл соединение"));
            }
            let mut rd = &raw[..n];
            {
                let mut tls = self.tls.lock().unwrap();
                while !rd.is_empty() {
                    tls.read_tls(&mut rd)?;
                    tls.process_new_packets()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    loop {
                        match tls.reader().read(&mut tmp) {
                            Ok(0) => return Err(other("сервер закрыл соединение")),
                            Ok(k) => frames.push(&tmp[..k]),
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => return Err(e),
                        }
                    }
                }
                self.flush_locked(&mut tls)?;
            }
            loop {
                match frames.next() {
                    Ok(Some((ty, body))) => self.handle_msg(ty, body),
                    Ok(None) => break,
                    Err(_) => return Err(other("слишком большое сообщение от сервера")),
                }
            }
        }
        Ok(())
    }

    fn handle_msg(self: &Arc<Self>, ty: u16, body: &[u8]) {
        match ty {
            T_UDPTUNNEL => self.handle_voice_plain(body, false),
            T_PING => {
                if let Ok(p) = Ping::decode(body) {
                    if let Some(ts) = p.timestamp {
                        let rtt = self.now_us().saturating_sub(ts) as f32 / 1000.0;
                        self.handler.on_event(LinkEvent::Ping { ms: rtt, udp: false });
                    }
                }
            }
            T_REJECT => {
                if let Ok(r) = Reject::decode(body) {
                    self.handler.on_event(LinkEvent::Rejected {
                        kind: r.kind.unwrap_or(0),
                        reason: r.reason.unwrap_or_default(),
                    });
                }
            }
            T_SERVERSYNC => {
                if let Ok(s) = ServerSync::decode(body) {
                    let session = s.session.unwrap_or(0);
                    self.session.store(session, Ordering::SeqCst);
                    self.handler.on_event(LinkEvent::Synced {
                        session,
                        welcome: s.welcome_text.unwrap_or_default(),
                    });
                }
            }
            T_USERSTATE => {
                if let Ok(u) = UserState::decode(body) {
                    self.handler.on_event(LinkEvent::UserState(u));
                }
            }
            T_USERREMOVE => {
                if let Ok(u) = UserRemove::decode(body) {
                    self.handler.on_event(LinkEvent::UserRemove {
                        session: u.session,
                        reason: u.reason.unwrap_or_default(),
                    });
                }
            }
            T_CRYPTSETUP => {
                if let Ok(c) = CryptSetup::decode(body) {
                    self.handle_crypt(c);
                }
            }
            T_PERMISSIONDENIED => {
                if let Ok(d) = PermissionDenied::decode(body) {
                    self.handler.on_event(LinkEvent::Denied(d.reason.unwrap_or_default()));
                }
            }
            _ => {}
        }
    }

    fn handle_crypt(self: &Arc<Self>, c: CryptSetup) {
        match (c.key, c.client_nonce, c.server_nonce) {
            (Some(key), Some(cn), Some(sn)) => {
                if let Some(cs) = CryptState::new(&key, &cn, &sn) {
                    *self.crypt.lock().unwrap() = Some(cs);
                    self.send_udp_ping();
                }
            }
            (None, None, Some(sn)) => {
                // Сервер прислал свой счётчик заново (ответ на наш запрос ресинхронизации).
                if let Some(cs) = self.crypt.lock().unwrap().as_mut() {
                    cs.set_decrypt_iv(&sn);
                }
            }
            _ => {
                // Сервер просит наш счётчик.
                let iv = self.crypt.lock().unwrap().as_ref().map(|c| c.encrypt_iv());
                if let Some(iv) = iv {
                    self.send_msg(
                        T_CRYPTSETUP,
                        &CryptSetup { key: None, client_nonce: Some(iv.to_vec()), server_nonce: None },
                    );
                }
            }
        }
    }

    fn udp_loop(self: &Arc<Self>) {
        let mut buf = [0u8; 2048];
        let mut plain = [0u8; 2048];
        while self.is_alive() {
            match self.dgram.recv(&mut buf) {
                Ok(n) if n > 4 => {
                    if self.udp_disabled.load(Ordering::Relaxed) {
                        continue;
                    }
                    let ok = {
                        let mut c = self.crypt.lock().unwrap();
                        match c.as_mut() {
                            Some(c) => c.decrypt(&buf[..n], &mut plain[..n - 4]),
                            None => false,
                        }
                    };
                    if ok {
                        if crate::win::trace_level() >= 2 {
                            eprintln!("udp: rx ok ivbyte={} head={:02x?}", buf[0], &plain[..(n - 4).min(5)]);
                        }
                        self.bad_udp.store(0, Ordering::Relaxed);
                        self.last_udp_rx_ms.store(self.now_ms(), Ordering::Relaxed);
                        if !self.udp_ok.swap(true, Ordering::SeqCst) {
                            self.handler.on_event(LinkEvent::UdpState(true));
                        }
                        self.handle_voice_plain(&plain[..n - 4], true);
                    } else {
                        // Много подряд нерасшифрованных пакетов — счётчики разошлись, просим сервер прислать свой.
                        let bad = self.bad_udp.fetch_add(1, Ordering::Relaxed) + 1;
                        if crate::win::trace_level() > 0 {
                            eprintln!("udp: decrypt failed, len={n} ivbyte={}", buf[0]);
                        }
                        let now = self.now_ms();
                        if bad >= 20 && now.saturating_sub(self.last_resync_ms.load(Ordering::Relaxed)) > 5000 {
                            self.last_resync_ms.store(now, Ordering::Relaxed);
                            self.bad_udp.store(0, Ordering::Relaxed);
                            self.send_msg(T_CRYPTSETUP, &CryptSetup::default());
                        }
                    }
                }
                Ok(_) => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                Err(_) => {
                    // Например, ICMP «порт недоступен»: не крутим цикл вхолостую.
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    /// Разбирает расшифрованный голосовой пакет (или пакет из TCP-туннеля).
    fn handle_voice_plain(self: &Arc<Self>, p: &[u8], via_udp: bool) {
        if p.is_empty() {
            return;
        }
        let ty = p[0] >> 5;
        let mut pos = 1usize;
        match ty {
            // UDP ping: сервер возвращает наш пакет без изменений.
            1 => {
                if via_udp {
                    if let Some(ts) = read_varint(p, &mut pos) {
                        let rtt = self.now_us().saturating_sub(ts) as f32 / 1000.0;
                        self.handler.on_event(LinkEvent::Ping { ms: rtt, udp: true });
                    }
                }
            }
            // Opus
            4 => {
                let Some(session) = read_varint(p, &mut pos) else { return };
                let Some(seq) = read_varint(p, &mut pos) else { return };
                let Some(hdr) = read_varint(p, &mut pos) else { return };
                let len = (hdr & 0x1FFF) as usize;
                let last = hdr & 0x2000 != 0;
                let Some(data) = p.get(pos..pos + len) else { return };
                self.handler.on_voice(session as u32, seq, data, last);
            }
            _ => {}
        }
    }

    fn send_udp_ping(&self) {
        if self.udp_disabled.load(Ordering::Relaxed) {
            return;
        }
        let mut pkt = Vec::with_capacity(12);
        pkt.push(1u8 << 5);
        write_varint(&mut pkt, self.now_us());
        let mut out = [0u8; 32];
        let n = {
            let mut c = self.crypt.lock().unwrap();
            match c.as_mut() {
                Some(c) => c.encrypt(&pkt, &mut out),
                None => 0,
            }
        };
        if n > 0 {
            let _ = self.dgram.send(&out[..n]);
        }
    }

    fn ticker(self: &Arc<Self>) {
        let mut tick = 0u32;
        while self.is_alive() {
            for _ in 0..4 {
                std::thread::sleep(Duration::from_millis(250));
                if !self.is_alive() {
                    return;
                }
            }
            tick += 1;
            let udp_ok = self.udp_ok.load(Ordering::Relaxed);

            // UDP ping: пока канал не установлен — каждую секунду, потом раз в 2 секунды.
            if !udp_ok || tick % 2 == 0 {
                self.send_udp_ping();
            }
            // TCP ping: раз в 5 секунд (и чаще, пока по нему измеряется задержка).
            if tick % 5 == 0 || (!udp_ok && tick % 2 == 0) {
                let (good, late, lost) = self.udp_stats();
                self.send_msg(
                    T_PING,
                    &Ping {
                        timestamp: Some(self.now_us()),
                        good: Some(good),
                        late: Some(late),
                        lost: Some(lost),
                        resync: Some(0),
                    },
                );
            }
            // UDP молчит дольше 7 секунд — переходим на TCP-туннель, продолжая пробовать UDP.
            if udp_ok && self.now_ms().saturating_sub(self.last_udp_rx_ms.load(Ordering::Relaxed)) > 7000 {
                self.udp_ok.store(false, Ordering::SeqCst);
                self.handler.on_event(LinkEvent::UdpState(false));
            }
        }
    }
}

fn describe_io(e: &io::Error) -> String {
    // Коды Windows Sockets: так точнее, чем по io::ErrorKind.
    match e.raw_os_error() {
        Some(10060) => return "сервер не отвечает — ПК с сервером выключен или порт закрыт брандмауэром".into(),
        Some(10061) => return "на этом адресе сервер не запущен".into(),
        Some(10051) | Some(10065) => return "нет пути до сервера — проверьте интернет (или ZeroTier)".into(),
        Some(10054) | Some(10053) => return "соединение разорвано".into(),
        _ => {}
    }
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "сервер не отвечает".into(),
        io::ErrorKind::ConnectionRefused => "на этом адресе сервер не запущен".into(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe => {
            "соединение разорвано".into()
        }
        io::ErrorKind::InvalidData => format!("ошибка защищённого соединения: {e}"),
        _ => e.to_string(),
    }
}

pub fn describe_connect_error(e: &io::Error) -> String {
    describe_io(e)
}

/// Собирает голосовой пакет клиента: заголовок, номер кадра, длина (+ признак конца фразы), данные Opus.
pub fn build_voice_packet(out: &mut Vec<u8>, seq: u64, opus: &[u8], last: bool) {
    out.clear();
    out.push(4u8 << 5);
    write_varint(out, seq);
    let mut hdr = opus.len() as u64 & 0x1FFF;
    if last {
        hdr |= 0x2000;
    }
    write_varint(out, hdr);
    out.extend_from_slice(opus);
}
