//! P2P-поток: один UDP-маршрут через пробитый NAT, внутри — надёжный упорядоченный поток
//! (для TLS и управляющих сообщений) и датаграммы (голос, без повторов и задержек).
//!
//! Пакеты: `[тип][conn_id: 8][...]`
//! - DATA `[seq: 4][данные]` — сегмент потока;
//! - ACK `[ack: 4][sack: 4]` — получено всё до `ack` (не включая), бит i — получен `ack + 1 + i`;
//! - VOICE `[данные]` — голосовой пакет (уже зашифрован OCB2);
//! - KEEPALIVE — держит NAT открытым; CLOSE — закрытие.
//!
//! Управляющих данных мало (килобайты), поэтому без управления перегрузкой:
//! окно 64 сегмента, повтор по таймеру (RTO по RFC 6298) с удвоением.

use crate::transport::{Datagrams, Stream};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub const T_DATA: u8 = 0xA4;
pub const T_ACK: u8 = 0xA5;
pub const T_VOICE: u8 = 0xA6;
pub const T_KEEPALIVE: u8 = 0xA7;
pub const T_CLOSE: u8 = 0xA8;

/// Данных в одном сегменте: пакет целиком не больше ~1150 байт (без фрагментации на любых линиях).
pub const MSS: usize = 1100;
const WINDOW: usize = 64;
const MAX_RETRIES: u32 = 14;
/// Тишина дольше — соединение потеряно.
const DEAD_MS: u64 = 30_000;
const KEEPALIVE_MS: u64 = 4_000;
const VOICE_QUEUE: usize = 64;
/// Сколько несчитанных данных держим для читателя.
const READY_LIMIT: usize = 1 << 20;

type VoiceHandler = Arc<dyn Fn(&[u8]) + Send + Sync>;

struct Seg {
    packet: Vec<u8>,
    sent: u64,
    retries: u32,
}

struct State {
    next_seq: u32,
    unacked: BTreeMap<u32, Seg>,
    srtt: f64,
    rttvar: f64,
    rto: u64,
    have_rtt: bool,
    expected: u32,
    ooo: BTreeMap<u32, Vec<u8>>,
    ready: VecDeque<u8>,
}

pub struct Flow {
    pub conn_id: u64,
    pub peer: SocketAddr,
    sock: Arc<UdpSocket>,
    clock: Instant,
    st: Mutex<State>,
    cv: Condvar,
    voice: Mutex<VecDeque<Vec<u8>>>,
    voice_cv: Condvar,
    voice_handler: Mutex<Option<VoiceHandler>>,
    closed: AtomicBool,
    read_timeout_ms: AtomicU64,
    last_rx: AtomicU64,
    last_tx: AtomicU64,
}

impl Flow {
    pub fn new(conn_id: u64, peer: SocketAddr, sock: Arc<UdpSocket>, clock: Instant) -> Arc<Flow> {
        let now = clock.elapsed().as_millis() as u64;
        Arc::new(Flow {
            conn_id,
            peer,
            sock,
            clock,
            st: Mutex::new(State {
                next_seq: 0,
                unacked: BTreeMap::new(),
                srtt: 0.0,
                rttvar: 0.0,
                rto: 500,
                have_rtt: false,
                expected: 0,
                ooo: BTreeMap::new(),
                ready: VecDeque::new(),
            }),
            cv: Condvar::new(),
            voice: Mutex::new(VecDeque::new()),
            voice_cv: Condvar::new(),
            voice_handler: Mutex::new(None),
            closed: AtomicBool::new(false),
            read_timeout_ms: AtomicU64::new(30_000),
            last_rx: AtomicU64::new(now),
            last_tx: AtomicU64::new(now),
        })
    }

    fn now(&self) -> u64 {
        self.clock.elapsed().as_millis() as u64
    }

    fn header(&self, ty: u8, extra: usize) -> Vec<u8> {
        let mut p = Vec::with_capacity(9 + extra);
        p.push(ty);
        p.extend_from_slice(&self.conn_id.to_be_bytes());
        p
    }

    fn raw_send(&self, p: &[u8]) {
        let _ = self.sock.send_to(p, self.peer);
        self.last_tx.store(self.now(), Ordering::Relaxed);
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Сервер: голос из этого потока сразу уходит обработчику (без очереди).
    pub fn set_voice_handler(&self, h: Option<VoiceHandler>) {
        *self.voice_handler.lock().unwrap() = h;
    }

    /// Пакет этого потока от собеседника (тип и всё после conn_id).
    pub fn on_packet(&self, ty: u8, body: &[u8]) {
        self.last_rx.store(self.now(), Ordering::Relaxed);
        match ty {
            T_DATA if body.len() >= 4 => {
                let seq = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                self.on_data(seq, &body[4..]);
            }
            T_ACK if body.len() >= 8 => {
                let ack = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let sack = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                self.on_ack(ack, sack);
            }
            T_VOICE => {
                let handler = self.voice_handler.lock().unwrap().clone();
                match handler {
                    Some(h) => h(body),
                    None => {
                        let mut q = self.voice.lock().unwrap();
                        if q.len() >= VOICE_QUEUE {
                            q.pop_front();
                        }
                        q.push_back(body.to_vec());
                        self.voice_cv.notify_one();
                    }
                }
            }
            T_CLOSE => self.mark_closed(),
            _ => {}
        }
    }

    fn on_data(&self, seq: u32, payload: &[u8]) {
        let (ack, sack) = {
            let mut st = self.st.lock().unwrap();
            if st.ready.len() > READY_LIMIT {
                // Читатель не успевает: не подтверждаем — отправитель повторит позже.
                return;
            }
            if seq == st.expected {
                st.ready.extend(payload);
                st.expected += 1;
                loop {
                    let next = st.expected;
                    let Some(p) = st.ooo.remove(&next) else { break };
                    st.ready.extend(p);
                    st.expected += 1;
                }
            } else if seq > st.expected && seq - st.expected < 4096 && st.ooo.len() < 1024 {
                st.ooo.entry(seq).or_insert_with(|| payload.to_vec());
            }
            let ack = st.expected;
            let mut sack = 0u32;
            for i in 0..32 {
                if st.ooo.contains_key(&(ack + 1 + i)) {
                    sack |= 1 << i;
                }
            }
            (ack, sack)
        };
        self.cv.notify_all();
        let mut p = self.header(T_ACK, 8);
        p.extend_from_slice(&ack.to_be_bytes());
        p.extend_from_slice(&sack.to_be_bytes());
        self.raw_send(&p);
    }

    fn on_ack(&self, ack: u32, sack: u32) {
        let now = self.now();
        {
            let mut st = self.st.lock().unwrap();
            let mut done: Vec<u32> = st.unacked.range(..ack).map(|(&s, _)| s).collect();
            for i in 0..32 {
                if sack & (1 << i) != 0 {
                    done.push(ack.wrapping_add(1 + i));
                }
            }
            for s in done {
                let Some(seg) = st.unacked.remove(&s) else { continue };
                // RTT только по сегментам без повторов (алгоритм Карна).
                if seg.retries == 0 {
                    let r = now.saturating_sub(seg.sent) as f64;
                    if st.have_rtt {
                        st.rttvar = 0.75 * st.rttvar + 0.25 * (st.srtt - r).abs();
                        st.srtt = 0.875 * st.srtt + 0.125 * r;
                    } else {
                        st.srtt = r;
                        st.rttvar = r / 2.0;
                        st.have_rtt = true;
                    }
                    st.rto = (st.srtt + (4.0 * st.rttvar).max(10.0)).clamp(150.0, 3000.0) as u64;
                }
            }
        }
        self.cv.notify_all();
    }

    /// Таймер (вызывается часто): повторы, keepalive, обнаружение обрыва. `false` — поток мёртв.
    pub fn tick(&self) -> bool {
        if self.is_closed() {
            return false;
        }
        let now = self.now();
        if now.saturating_sub(self.last_rx.load(Ordering::Relaxed)) > DEAD_MS {
            self.mark_closed();
            return false;
        }
        let mut resend = Vec::new();
        let mut dead = false;
        {
            let mut st = self.st.lock().unwrap();
            let rto = st.rto;
            for seg in st.unacked.values_mut() {
                if now.saturating_sub(seg.sent) >= rto << seg.retries.min(4) {
                    if seg.retries >= MAX_RETRIES {
                        dead = true;
                        break;
                    }
                    seg.retries += 1;
                    seg.sent = now;
                    resend.push(seg.packet.clone());
                    if resend.len() >= 16 {
                        break;
                    }
                }
            }
        }
        if dead {
            self.mark_closed();
            return false;
        }
        for p in &resend {
            self.raw_send(p);
        }
        if now.saturating_sub(self.last_tx.load(Ordering::Relaxed)) > KEEPALIVE_MS {
            let p = self.header(T_KEEPALIVE, 0);
            self.raw_send(&p);
        }
        true
    }

    pub fn has_unacked(&self) -> bool {
        !self.st.lock().unwrap().unacked.is_empty()
    }

    fn mark_closed(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.cv.notify_all();
        self.voice_cv.notify_all();
    }

    /// Закрыть с нашей стороны (собеседнику уходит CLOSE).
    pub fn shutdown(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let p = self.header(T_CLOSE, 0);
            self.raw_send(&p);
            self.raw_send(&p);
        }
        self.set_voice_handler(None);
        self.cv.notify_all();
        self.voice_cv.notify_all();
    }
}

impl Stream for Flow {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let deadline = Instant::now() + Duration::from_millis(self.read_timeout_ms.load(Ordering::Relaxed));
        let mut st = self.st.lock().unwrap();
        loop {
            if !st.ready.is_empty() {
                let n = buf.len().min(st.ready.len());
                for (o, b) in buf.iter_mut().zip(st.ready.drain(..n)) {
                    *o = b;
                }
                return Ok(n);
            }
            if self.is_closed() {
                return Ok(0);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "нет данных"));
            }
            st = self.cv.wait_timeout(st, left.min(Duration::from_millis(500))).unwrap().0;
        }
    }

    fn send_all(&self, buf: &[u8]) -> io::Result<()> {
        for chunk in buf.chunks(MSS) {
            let started = Instant::now();
            let packet = {
                let mut st = self.st.lock().unwrap();
                loop {
                    if self.is_closed() {
                        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "соединение закрыто"));
                    }
                    if st.unacked.len() < WINDOW {
                        break;
                    }
                    if started.elapsed() > Duration::from_secs(15) {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "собеседник не подтверждает данные"));
                    }
                    st = self.cv.wait_timeout(st, Duration::from_millis(200)).unwrap().0;
                }
                let seq = st.next_seq;
                st.next_seq += 1;
                let mut p = self.header(T_DATA, 4 + chunk.len());
                p.extend_from_slice(&seq.to_be_bytes());
                p.extend_from_slice(chunk);
                st.unacked.insert(seq, Seg { packet: p.clone(), sent: self.now(), retries: 0 });
                p
            };
            self.raw_send(&packet);
        }
        Ok(())
    }

    fn set_timeout(&self, t: Duration) {
        self.read_timeout_ms.store(t.as_millis() as u64, Ordering::Relaxed);
    }

    fn close(&self) {
        self.shutdown();
    }
}

impl Datagrams for Flow {
    fn send(&self, buf: &[u8]) -> io::Result<()> {
        if self.is_closed() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "соединение закрыто"));
        }
        let mut p = self.header(T_VOICE, buf.len());
        p.extend_from_slice(buf);
        self.raw_send(&p);
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut q = self.voice.lock().unwrap();
        if q.is_empty() && !self.is_closed() {
            q = self.voice_cv.wait_timeout(q, Duration::from_millis(500)).unwrap().0;
        }
        match q.pop_front() {
            Some(p) => {
                let n = p.len().min(buf.len());
                buf[..n].copy_from_slice(&p[..n]);
                Ok(n)
            }
            None if self.is_closed() => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "соединение закрыто")),
            None => Err(io::Error::new(io::ErrorKind::TimedOut, "нет пакетов")),
        }
    }
}
