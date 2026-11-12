//! Клиент BitTorrent Mainline DHT (BEP 5) в режиме «только чтение» (BEP 43): мы задаём вопросы,
//! но сами не храним чужие данные и не отвечаем на запросы — это легче и незаметнее.
//!
//! Нужны три операции:
//! - `lookup` — итеративный поиск узлов, ближайших к ключу, и адресов, опубликованных под ним;
//! - `announce` — опубликовать свой адрес под ключом (`implied_port`: узел запишет тот порт,
//!   с которого пришёл пакет, — то есть внешний порт нашего NAT);
//! - `poll` — быстро спросить уже известные ближайшие узлы, не появилось ли новых адресов.
//!
//! Ответы приходят на общий UDP-сокет; поток приёма передаёт сюда пакеты, начинающиеся с `d`.

use super::bencode::{decode, B};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const K: usize = 8;
const ALPHA: usize = 8;
const QUERY_TIMEOUT: Duration = Duration::from_millis(1000);

const BOOTSTRAP: [&str; 5] = [
    "router.bittorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "router.utorrent.com:6881",
    "dht.libtorrent.org:25401",
    "dht.aelitis.com:6881",
];

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Node {
    pub id: [u8; 20],
    pub addr: SocketAddr,
}

#[derive(Debug, Default)]
pub struct Reply {
    pub from: Option<SocketAddr>,
    pub id: Option<[u8; 20]>,
    pub token: Option<Vec<u8>>,
    pub nodes: Vec<Node>,
    pub values: Vec<SocketAddr>,
    /// Наш внешний адрес, как его видит узел (BEP 42).
    pub ip: Option<SocketAddr>,
    /// Изменяемая запись (BEP 44), если узел её хранит.
    pub item: Option<Item>,
}

/// Изменяемая запись BEP 44 в том виде, как её вернул узел (подпись проверяет вызывающий).
#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    pub k: Vec<u8>,
    pub sig: Vec<u8>,
    pub seq: i64,
    /// Значение в bencode (ровно те байты, что подписаны).
    pub v: Vec<u8>,
}

/// Что ищем: адреса под ключом (`get_peers`) или запись BEP 44 (`get`).
#[derive(Clone, Copy, PartialEq)]
pub enum Query {
    Peers,
    Item,
}

#[derive(Debug, Default)]
pub struct Lookup {
    /// Адреса под ключом и сколько разных узлов их сообщили. В DHT встречаются узлы,
    /// которые отвечают подложными адресами, поэтому доверять стоит подтверждённым (≥ 2).
    pub peers: Vec<(SocketAddr, usize)>,
    /// Ближайшие ответившие узлы с токенами (для `announce` и `poll`).
    pub closest: Vec<(Node, Vec<u8>)>,
    /// Наш внешний адрес по ответам узлов (если узлы его сообщили).
    pub external: Vec<SocketAddr>,
    pub responded: usize,
    /// Записи BEP 44, которые вернули узлы (без проверки подписи).
    pub items: Vec<Item>,
}

impl Lookup {
    /// Самый частый внешний адрес по ответам узлов.
    pub fn my_address(&self) -> Option<SocketAddr> {
        let mut counts: HashMap<SocketAddr, usize> = HashMap::new();
        for a in &self.external {
            *counts.entry(*a).or_insert(0) += 1;
        }
        counts.into_iter().max_by_key(|(_, n)| *n).map(|(a, _)| a)
    }
}

pub struct Dht {
    sock: Arc<UdpSocket>,
    id: [u8; 20],
    tid: AtomicU32,
    pending: Mutex<HashMap<u16, (Sender<Reply>, Instant)>>,
    good: Mutex<Vec<SocketAddr>>,
}

pub fn compact_addr(b: &[u8]) -> Option<SocketAddr> {
    if b.len() != 6 {
        return None;
    }
    let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    let port = u16::from_be_bytes([b[4], b[5]]);
    (port != 0 && !ip.is_unspecified()).then(|| SocketAddr::new(IpAddr::V4(ip), port))
}

fn parse_nodes(b: &[u8]) -> Vec<Node> {
    b.chunks_exact(26)
        .filter_map(|c| {
            let mut id = [0u8; 20];
            id.copy_from_slice(&c[..20]);
            compact_addr(&c[20..]).map(|addr| Node { id, addr })
        })
        .collect()
}

pub fn distance(a: &[u8; 20], b: &[u8; 20]) -> [u8; 20] {
    let mut d = [0u8; 20];
    for i in 0..20 {
        d[i] = a[i] ^ b[i];
    }
    d
}

fn cache_path() -> PathBuf {
    crate::system::user_dir().join("dht-nodes.txt")
}

fn bootstrap_addrs() -> &'static [SocketAddr] {
    static ADDRS: OnceLock<Vec<SocketAddr>> = OnceLock::new();
    ADDRS.get_or_init(|| {
        BOOTSTRAP
            .iter()
            .filter_map(|h| h.to_socket_addrs().ok())
            .flat_map(|it| it.filter(|a| a.is_ipv4()).take(2))
            .collect()
    })
}

impl Dht {
    pub fn new(sock: Arc<UdpSocket>) -> Dht {
        let mut id = [0u8; 20];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id).expect("random");
        Dht { sock, id, tid: AtomicU32::new(1), pending: Mutex::new(HashMap::new()), good: Mutex::new(Vec::new()) }
    }

    /// Узлы для начала поиска: сохранённые с прошлого раза и публичные точки входа.
    pub fn bootstrap(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = self.good.lock().unwrap().clone();
        if out.len() < 8 {
            if let Ok(text) = std::fs::read_to_string(cache_path()) {
                out.extend(text.lines().filter_map(|l| l.trim().parse::<SocketAddr>().ok()));
            }
        }
        out.extend_from_slice(bootstrap_addrs());
        let mut seen = HashSet::new();
        out.retain(|a| seen.insert(*a));
        out
    }

    /// Запоминает отвечающие узлы, чтобы в следующий раз начинать с них.
    pub fn save_nodes(&self) {
        let good = self.good.lock().unwrap();
        if good.len() >= 8 {
            let text: String = good.iter().take(64).map(|a| format!("{a}\n")).collect();
            let _ = std::fs::write(cache_path(), text);
        }
    }

    /// Пакет от DHT (первый байт `d`).
    pub fn on_packet(&self, from: SocketAddr, data: &[u8]) {
        let Some(v) = decode(data) else { return };
        let Some(t) = v.get("t").and_then(|t| t.as_bytes()) else { return };
        if t.len() != 2 {
            return;
        }
        let tid = u16::from_be_bytes([t[0], t[1]]);
        let Some((tx, _)) = self.pending.lock().unwrap().remove(&tid) else { return };
        let mut reply = Reply { from: Some(from), ..Default::default() };
        reply.ip = v.get("ip").and_then(|x| x.as_bytes()).and_then(compact_addr);
        if let Some(r) = v.get("r") {
            reply.id = r.get("id").and_then(|x| x.as_bytes()).and_then(|b| b.try_into().ok());
            reply.token = r.get("token").and_then(|x| x.as_bytes()).map(|b| b.to_vec());
            if let Some(n) = r.get("nodes").and_then(|x| x.as_bytes()) {
                reply.nodes = parse_nodes(n);
            }
            if let Some(vals) = r.get("values").and_then(|x| x.as_list()) {
                reply.values = vals.iter().filter_map(|x| x.as_bytes().and_then(compact_addr)).collect();
            }
            if let (Some(v), Some(k), Some(sig), Some(seq)) = (
                r.get("v"),
                r.get("k").and_then(|x| x.as_bytes()),
                r.get("sig").and_then(|x| x.as_bytes()),
                r.get("seq").and_then(|x| x.as_int()),
            ) {
                // Узлы хранят значение в каноническом bencode — повторное кодирование даёт те же байты.
                reply.item = Some(Item { k: k.to_vec(), sig: sig.to_vec(), seq, v: v.encode() });
            }
            let mut good = self.good.lock().unwrap();
            if !good.contains(&from) {
                good.insert(0, from);
                good.truncate(64);
            }
        }
        let _ = tx.send(reply);
    }

    fn query(&self, to: SocketAddr, q: &str, args: Vec<(&str, B)>, tx: &Sender<Reply>) {
        let tid = (self.tid.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
        let mut a = args;
        a.push(("id", B::bytes(self.id)));
        let msg = B::dict(vec![
            ("t", B::bytes(tid.to_be_bytes())),
            ("y", B::bytes("q")),
            ("q", B::bytes(q)),
            ("a", B::dict(a)),
            ("ro", B::Int(1)),
        ]);
        {
            let mut p = self.pending.lock().unwrap();
            let now = Instant::now();
            p.retain(|_, (_, at)| now.duration_since(*at) < Duration::from_secs(15));
            p.insert(tid, (tx.clone(), now));
        }
        let _ = self.sock.send_to(&msg.encode(), to);
    }

    fn get_peers(&self, to: SocketAddr, target: &[u8; 20], tx: &Sender<Reply>) {
        self.query(to, "get_peers", vec![("info_hash", B::bytes(*target))], tx);
    }

    fn get_item(&self, to: SocketAddr, target: &[u8; 20], tx: &Sender<Reply>) {
        self.query(to, "get", vec![("target", B::bytes(*target))], tx);
    }

    fn ask(&self, kind: Query, to: SocketAddr, target: &[u8; 20], tx: &Sender<Reply>) {
        match kind {
            Query::Peers => self.get_peers(to, target, tx),
            Query::Item => self.get_item(to, target, tx),
        }
    }

    /// Итеративный поиск адресов под ключом.
    pub fn lookup(&self, target: &[u8; 20], timeout: Duration) -> Lookup {
        self.lookup_with(Query::Peers, target, timeout)
    }

    /// Итеративный поиск: спрашиваем всё более близкие к ключу узлы, пока ближайшие K не ответят.
    pub fn lookup_with(&self, kind: Query, target: &[u8; 20], timeout: Duration) -> Lookup {
        #[derive(PartialEq)]
        enum St {
            Fresh,
            Asked(Instant),
            Done,
            Failed,
        }
        struct C {
            addr: SocketAddr,
            id: Option<[u8; 20]>,
            st: St,
            token: Option<Vec<u8>>,
        }
        let deadline = Instant::now() + timeout;
        let (tx, rx): (Sender<Reply>, Receiver<Reply>) = channel();
        let mut cands: Vec<C> =
            self.bootstrap().into_iter().map(|addr| C { addr, id: None, st: St::Fresh, token: None }).collect();
        let mut peers: HashMap<SocketAddr, HashSet<SocketAddr>> = HashMap::new();
        let mut external = Vec::new();
        let mut items: Vec<Item> = Vec::new();
        let mut responded = 0usize;
        let mut inflight = 0usize;
        let key = |c: &C| c.id.map(|id| distance(&id, target)).unwrap_or([0xFF; 20]);
        loop {
            cands.sort_by_key(|c| key(c));
            // Готово, когда среди K ближайших известных узлов нет неопрошенных, а ответили хотя бы K-2
            // (часть узлов DHT просто молчит — ждать их до конца незачем).
            let top: Vec<&C> = cands.iter().filter(|c| c.st != St::Failed && c.id.is_some()).take(K).collect();
            let done = top.iter().filter(|c| c.st == St::Done).count();
            if top.len() >= K && done >= K - 2 && !top.iter().any(|c| c.st == St::Fresh) {
                break;
            }
            for c in cands.iter_mut().filter(|c| c.st == St::Fresh) {
                if inflight >= ALPHA {
                    break;
                }
                self.ask(kind, c.addr, target, &tx);
                c.st = St::Asked(Instant::now());
                inflight += 1;
            }
            if inflight == 0 || Instant::now() >= deadline {
                break;
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(r) => {
                    let Some(from) = r.from else { continue };
                    let Some(c) = cands.iter_mut().find(|c| c.addr == from) else { continue };
                    if matches!(c.st, St::Asked(_)) {
                        inflight -= 1;
                    }
                    c.st = St::Done;
                    c.id = r.id.or(c.id);
                    c.token = r.token;
                    responded += 1;
                    if let Some(ip) = r.ip {
                        external.push(ip);
                    }
                    if let Some(it) = r.item {
                        if !items.contains(&it) {
                            items.push(it);
                        }
                    }
                    for v in r.values {
                        peers.entry(v).or_default().insert(from);
                    }
                    for n in r.nodes {
                        if cands.len() < 300 && !cands.iter().any(|c| c.addr == n.addr) {
                            cands.push(C { addr: n.addr, id: Some(n.id), st: St::Fresh, token: None });
                        }
                    }
                }
                Err(_) => {}
            }
            // Не ответившие вовремя освобождают место для следующих запросов — на каждом шаге,
            // а не только когда ответы перестали приходить.
            for c in cands.iter_mut() {
                if let St::Asked(at) = c.st {
                    if at.elapsed() > QUERY_TIMEOUT {
                        c.st = St::Failed;
                        inflight -= 1;
                    }
                }
            }
        }
        cands.sort_by_key(|c| key(c));
        if crate::win::trace_level() > 0 {
            let count = |f: &dyn Fn(&St) -> bool| cands.iter().filter(|c| f(&c.st)).count();
            let top: Vec<String> = cands
                .iter()
                .filter(|c| c.id.is_some() && c.st != St::Failed)
                .take(K)
                .map(|c| match c.st {
                    St::Fresh => "F",
                    St::Asked(_) => "A",
                    St::Done => "D",
                    St::Failed => "X",
                }.to_string())
                .collect();
            eprintln!(
                "dht lookup: cands={} fresh={} asked={} done={} failed={} inflight={inflight} top={}",
                cands.len(),
                count(&|s| *s == St::Fresh),
                count(&|s| matches!(s, St::Asked(_))),
                count(&|s| *s == St::Done),
                count(&|s| *s == St::Failed),
                top.join("")
            );
        }
        let closest = cands
            .iter()
            .filter(|c| c.st == St::Done)
            .filter_map(|c| Some((Node { id: c.id?, addr: c.addr }, c.token.clone()?)))
            .take(K)
            .collect();
        let mut peers: Vec<(SocketAddr, usize)> = peers.into_iter().map(|(a, s)| (a, s.len())).collect();
        peers.sort_by(|a, b| b.1.cmp(&a.1));
        Lookup { peers, closest, external, responded, items }
    }

    /// Публикует наш адрес под ключом у ближайших узлов. Возвращает, сколько узлов подтвердили.
    pub fn announce(&self, target: &[u8; 20], closest: &[(Node, Vec<u8>)], port: u16) -> usize {
        let (tx, rx) = channel();
        for (n, token) in closest {
            self.query(
                n.addr,
                "announce_peer",
                vec![
                    ("info_hash", B::bytes(*target)),
                    ("port", B::Int(port.max(1) as i64)),
                    ("implied_port", B::Int(1)),
                    ("token", B::bytes(token.clone())),
                ],
                &tx,
            );
        }
        let deadline = Instant::now() + QUERY_TIMEOUT;
        let mut ok = 0;
        while ok < closest.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(r) if r.id.is_some() => ok += 1,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        ok
    }

    /// Сохраняет подписанную запись BEP 44 у ближайших узлов (токены — из ответов на `get`).
    /// Возвращает, сколько узлов приняли запись.
    pub fn put_item(&self, closest: &[(Node, Vec<u8>)], k: &[u8; 32], salt: &[u8], seq: i64, v: &B, sig: &[u8; 64]) -> usize {
        let (tx, rx) = channel();
        for (n, token) in closest {
            self.query(
                n.addr,
                "put",
                vec![
                    ("token", B::bytes(token.clone())),
                    ("v", v.clone()),
                    ("k", B::bytes(*k)),
                    ("sig", B::bytes(*sig)),
                    ("seq", B::Int(seq)),
                    ("salt", B::bytes(salt)),
                ],
                &tx,
            );
        }
        let deadline = Instant::now() + QUERY_TIMEOUT;
        let mut ok = 0;
        let mut answered = 0;
        while answered < closest.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(r) => {
                    answered += 1;
                    if r.id.is_some() {
                        ok += 1;
                    }
                }
                Err(_) => break,
            }
        }
        ok
    }

    /// Быстрый опрос известных узлов: какие записи BEP 44 у них сейчас лежат под ключом.
    pub fn poll_items(&self, target: &[u8; 20], nodes: &[(Node, Vec<u8>)]) -> Vec<Item> {
        let (tx, rx) = channel();
        for (n, _) in nodes {
            self.get_item(n.addr, target, &tx);
        }
        let deadline = Instant::now() + Duration::from_millis(1200);
        let (mut got, mut out) = (0, Vec::new());
        while got < nodes.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(r) => {
                    got += 1;
                    if let Some(it) = r.item {
                        if !out.contains(&it) {
                            out.push(it);
                        }
                    }
                }
                Err(_) => break,
            }
        }
        out
    }

    /// Быстрый опрос известных ближайших узлов: какие адреса сейчас записаны под ключом
    /// (пары «адрес, узел, который его сообщил»).
    pub fn poll(&self, target: &[u8; 20], nodes: &[(Node, Vec<u8>)]) -> Vec<(SocketAddr, SocketAddr)> {
        let (tx, rx) = channel();
        for (n, _) in nodes {
            self.get_peers(n.addr, target, &tx);
        }
        let deadline = Instant::now() + Duration::from_millis(1200);
        let mut got = 0;
        let mut out = Vec::new();
        while got < nodes.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(r) => {
                    got += 1;
                    let Some(from) = r.from else { continue };
                    for v in r.values {
                        out.push((v, from));
                    }
                }
                Err(_) => break,
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_formats() {
        assert_eq!(compact_addr(&[10, 77, 64, 1, 0xFC, 0xE2]), Some("10.77.64.1:64738".parse().unwrap()));
        assert_eq!(compact_addr(&[0, 0, 0, 0, 1, 1]), None);
        assert_eq!(compact_addr(&[1, 2, 3]), None);
        let mut b = vec![7u8; 20];
        b.extend_from_slice(&[1, 2, 3, 4, 0x1A, 0xE1]);
        let n = parse_nodes(&b);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].addr, "1.2.3.4:6881".parse().unwrap());
        assert_eq!(distance(&[1; 20], &[3; 20]), [2; 20]);
    }

    /// Ответ узла (как в BEP 5) доходит до ожидающего запроса.
    #[test]
    fn reply_routing() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let dht = Dht::new(sock);
        let (tx, rx) = channel();
        dht.pending.lock().unwrap().insert(0x6161, (tx, Instant::now()));
        let mut nodes = vec![9u8; 20];
        nodes.extend_from_slice(&[5, 6, 7, 8, 0x1A, 0xE1]);
        let msg = B::dict(vec![
            ("t", B::bytes("aa")),
            ("y", B::bytes("r")),
            ("ip", B::bytes(vec![82, 115, 59, 120, 0xEC, 0xDB])),
            (
                "r",
                B::dict(vec![
                    ("id", B::bytes([1u8; 20])),
                    ("token", B::bytes("tok")),
                    ("nodes", B::bytes(nodes)),
                    ("values", B::List(vec![B::bytes(vec![10, 0, 0, 1, 0x1F, 0x90])])),
                ]),
            ),
        ]);
        dht.on_packet("1.1.1.1:6881".parse().unwrap(), &msg.encode());
        let r = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(r.id, Some([1u8; 20]));
        assert_eq!(r.token.as_deref(), Some(&b"tok"[..]));
        assert_eq!(r.values, vec!["10.0.0.1:8080".parse::<SocketAddr>().unwrap()]);
        assert_eq!(r.nodes[0].addr, "5.6.7.8:6881".parse().unwrap());
        assert_eq!(r.ip, Some("82.115.59.120:60635".parse().unwrap()));
    }
}
