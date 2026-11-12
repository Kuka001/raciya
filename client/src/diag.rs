//! Диагностика сети: ищет то, что мешает связи и повышает пинг (VPN, прокси, Wi-Fi,
//! ретранслятор, занятый канал, плохая связь с роутером), и объясняет, что с этим делать.

use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GetBestInterface, GetIfEntry2, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
    GAA_FLAG_INCLUDE_GATEWAYS, ICMP_ECHO_REPLY, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_IN};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Severity {
    /// Заметно мешает связи.
    Problem,
    /// Может мешать.
    Warning,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Fix {
    None,
    DisableWarp,
    /// Подключить виртуальную сеть ZeroTier заново (права администратора).
    JoinZeroTier,
    /// Настроить компьютер-сервер: брандмауэр и закрепление порта (права администратора).
    ServerSetup,
    /// Разрешить порт сервера в правилах сети ZeroTier (на компьютере-контроллере).
    ZeroTierRules,
}

#[derive(Clone, Debug)]
pub struct Issue {
    pub severity: Severity,
    pub title: String,
    pub advice: String,
    pub fix: Fix,
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub issues: Vec<Issue>,
    /// Короткие строки с измерениями («Роутер: 1 мс» и т.п.).
    pub facts: Vec<String>,
}

/// То, что знает о соединении само приложение.
#[derive(Clone, Debug, Default)]
pub struct Context {
    pub online: bool,
    pub udp_active: bool,
    pub online_secs: u64,
    pub server_host: String,
    pub server_port: u16,
    pub zt_network: String,
    pub ping_avg: Option<f32>,
    pub ping_jitter: Option<f32>,
    pub loss_percent: Option<f32>,
    /// На этом компьютере включён сервер.
    pub runs_server: bool,
    pub server_running: bool,
    /// Почему сервер не запустился (текст, можно ли исправить настройкой).
    pub server_error: Option<(String, bool)>,
    /// Порт своего сервера.
    pub host_port: u16,
    pub status: crate::core::Status,
    /// Проверку запросил пользователь: медленные проверки выполняются заново, без кэша.
    pub force: bool,
    /// Клиент подключается по коду приглашения v2 (P2P).
    pub uses_p2p: bool,
    /// Состояние P2P своего сервера.
    pub p2p_host: Option<crate::p2p::HostStatus>,
}

struct Adapter {
    index: u32,
    name: String,
    description: String,
    if_type: u32,
    up: bool,
    gateway: Option<Ipv4Addr>,
    ipv4: Vec<Ipv4Addr>,
}

fn pwstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

fn adapters() -> Vec<Adapter> {
    let mut out = Vec::new();
    let mut size = 32 * 1024u32;
    let mut buf: Vec<u64> = vec![0; size as usize / 8];
    unsafe {
        let mut r = GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_GATEWAYS,
            std::ptr::null(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut size,
        );
        if r == 111 {
            // ERROR_BUFFER_OVERFLOW: размер уже записан в `size`.
            buf = vec![0; size as usize / 8 + 1];
            r = GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_INCLUDE_GATEWAYS,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            );
        }
        if r != 0 {
            return out;
        }
        let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !p.is_null() {
            let a = &*p;
            let mut ipv4 = Vec::new();
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                let sa = (*u).Address.lpSockaddr;
                if !sa.is_null() && (*sa).sa_family == AF_INET {
                    let sin = &*(sa as *const SOCKADDR_IN);
                    ipv4.push(Ipv4Addr::from(u32::from_be(sin.sin_addr.S_un.S_addr)));
                }
                u = (*u).Next;
            }
            let mut gateway = None;
            let mut g = a.FirstGatewayAddress;
            while !g.is_null() {
                let sa = (*g).Address.lpSockaddr;
                if !sa.is_null() && (*sa).sa_family == AF_INET {
                    let sin = &*(sa as *const SOCKADDR_IN);
                    gateway = Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.S_un.S_addr)));
                    break;
                }
                g = (*g).Next;
            }
            out.push(Adapter {
                index: a.Anonymous1.Anonymous.IfIndex,
                name: pwstr(a.FriendlyName),
                description: pwstr(a.Description),
                if_type: a.IfType,
                up: a.OperStatus == 1,
                gateway,
                ipv4,
            });
            p = a.Next;
        }
    }
    out
}

/// Адреса этого компьютера, по которым к нему могут подключиться друзья:
/// («Локальная сеть» | «ZeroTier», адрес). Виртуальные адаптеры Hyper-V не показываются.
pub fn local_addresses() -> Vec<(&'static str, Ipv4Addr)> {
    let mut out = Vec::new();
    for a in adapters().iter().filter(|a| a.up) {
        let d = format!("{} {}", a.name, a.description).to_lowercase();
        let label = if d.contains("zerotier") {
            "ZeroTier"
        } else if matches!(a.if_type, 6 | 71) && !d.contains("hyper-v") && !d.contains("vethernet") && !vpn_like(a) {
            "Локальная сеть"
        } else {
            continue;
        };
        for ip in &a.ipv4 {
            if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() {
                out.push((label, *ip));
            }
        }
    }
    // ZeroTier — первым: по нему подключаются друзья из интернета.
    out.sort_by_key(|(l, _)| if *l == "ZeroTier" { 0 } else { 1 });
    out
}

/// Через какой адаптер Windows отправляет трафик в интернет.
fn default_route_index() -> Option<u32> {
    let dest = u32::from(Ipv4Addr::new(1, 1, 1, 1)).to_be();
    let mut idx = 0u32;
    unsafe { (GetBestInterface(dest, &mut idx) == 0).then_some(idx) }
}

/// Похоже ли название адаптера на VPN. ZeroTier — наша собственная сеть, её не считаем.
fn vpn_like(a: &Adapter) -> bool {
    let s = format!("{} {}", a.name, a.description).to_lowercase();
    if s.contains("zerotier") || s.contains("loopback") || s.contains("teredo") || s.contains("6to4") {
        return false;
    }
    const WORDS: [&str; 22] = [
        "warp", "wireguard", "wintun", "openvpn", "tap-windows", "tap-win", "nordlynx", "nordvpn", "proton",
        "amnezia", "outline", "vpn", "tunnel", "fortinet", "anyconnect", "expressvpn", "surfshark", "windscribe",
        "psiphon", "hiddify", "v2ray", "sing-box",
    ];
    WORDS.iter().any(|w| s.contains(w))
}

fn is_warp(a: &Adapter) -> bool {
    format!("{} {}", a.name, a.description).to_lowercase().contains("warp")
}

/// Несколько ICMP-запросов. Возвращает (средняя задержка, мс; число ответов).
fn icmp_ping(addr: Ipv4Addr, count: u32) -> (Option<f32>, u32) {
    unsafe {
        let h = IcmpCreateFile();
        if h.is_null() || h as isize == -1 {
            return (None, 0);
        }
        let payload = [0x52u8; 16];
        // Буфер из u64, чтобы структура ответа была выровнена по 8 байт.
        let mut reply = [0u64; (std::mem::size_of::<ICMP_ECHO_REPLY>() + 16 + 8) / 8 + 1];
        let mut sum = 0u32;
        let mut ok = 0u32;
        for _ in 0..count {
            let n = IcmpSendEcho(
                h,
                u32::from(addr).to_be(),
                payload.as_ptr() as _,
                payload.len() as u16,
                std::ptr::null(),
                reply.as_mut_ptr() as _,
                (reply.len() * 8) as u32,
                800,
            );
            if n > 0 {
                let r = &*(reply.as_ptr() as *const ICMP_ECHO_REPLY);
                if r.Status == 0 {
                    sum += r.RoundTripTime;
                    ok += 1;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(120));
        }
        IcmpCloseHandle(h);
        (if ok > 0 { Some(sum as f32 / ok as f32) } else { None }, ok)
    }
}

fn if_octets(index: u32) -> Option<(u64, u64)> {
    unsafe {
        let mut row: MIB_IF_ROW2 = std::mem::zeroed();
        row.InterfaceIndex = index;
        (GetIfEntry2(&mut row) == 0).then_some((row.InOctets, row.OutOctets))
    }
}

/// Как ZeroTier связан с сервером: напрямую или через ретранслятор.
enum ZtLink {
    Direct(i64),
    Relay,
    Unknown,
}

fn zt_link(ctx: &Context) -> ZtLink {
    if ctx.zt_network.len() < 10 {
        return ZtLink::Unknown;
    }
    // Номер сети начинается с адреса узла-контроллера (это и есть компьютер с сервером).
    match crate::zt::peer_link(&ctx.zt_network[..10]) {
        Some(Some(ms)) => ZtLink::Direct(ms),
        Some(None) => ZtLink::Relay,
        None => ZtLink::Unknown,
    }
}

fn proxy_enabled() -> Option<String> {
    use crate::win::{reg_get_string, reg_get_u32, HKEY_CURRENT_USER};
    let key = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    if reg_get_u32(HKEY_CURRENT_USER, key, "ProxyEnable").unwrap_or(0) == 0 {
        return None;
    }
    Some(reg_get_string(HKEY_CURRENT_USER, key, "ProxyServer").unwrap_or_default())
}

fn issue(severity: Severity, title: impl Into<String>, advice: impl Into<String>, fix: Fix) -> Issue {
    Issue { severity, title: title.into(), advice: advice.into(), fix }
}

/// Полная проверка. Занимает 2–3 секунды (пинги), поэтому вызывается из фонового потока.
pub fn run(ctx: &Context) -> Report {
    let mut rep = Report::default();
    let list = adapters();
    let default_idx = default_route_index();
    let default = default_idx.and_then(|i| list.iter().find(|a| a.index == i));

    // --- VPN ---
    let mut vpn_on_route = false;
    if let Some(a) = default {
        // 6 — Ethernet, 71 — Wi-Fi. Всё остальное на маршруте по умолчанию — туннель.
        if vpn_like(a) || !matches!(a.if_type, 6 | 71) {
            vpn_on_route = true;
            let warp = is_warp(a);
            rep.issues.push(issue(
                Severity::Problem,
                format!("Весь интернет идёт через VPN: {}", a.name),
                if warp {
                    "Из-за Cloudflare WARP пинг в играх выше, а голос может идти в обход. Отключите его на время игры."
                } else {
                    "Через VPN пинг в играх выше, а соединение с друзьями может пойти через ретранслятор. Отключите VPN на время игры."
                },
                if warp { Fix::DisableWarp } else { Fix::None },
            ));
        }
    }
    if !vpn_on_route {
        for a in list.iter().filter(|a| a.up && vpn_like(a)) {
            rep.issues.push(issue(
                Severity::Warning,
                format!("Включён VPN: {}", a.name),
                "Сейчас интернет идёт мимо него, но часть программ может работать через VPN. Если пинг скачет — отключите его.",
                if is_warp(a) { Fix::DisableWarp } else { Fix::None },
            ));
        }
    }

    // --- прокси ---
    if let Some(p) = proxy_enabled() {
        rep.issues.push(issue(
            Severity::Warning,
            format!("В Windows включён прокси-сервер{}", if p.is_empty() { String::new() } else { format!(": {p}") }),
            "Прокси замедляет программы, которые его используют. Выключить: Параметры → Сеть и Интернет → Прокси-сервер.",
            Fix::None,
        ));
    }

    // --- тип подключения, роутер, интернет ---
    if let Some(a) = default {
        if a.if_type == 71 {
            rep.issues.push(issue(
                Severity::Warning,
                "Компьютер подключён по Wi-Fi",
                "По Wi-Fi пинг скачет и пакеты теряются чаще. По кабелю связь стабильнее.",
                Fix::None,
            ));
        }
        if !vpn_on_route {
            if let Some(gw) = a.gateway {
                let (avg, ok) = icmp_ping(gw, 5);
                match avg {
                    Some(ms) => {
                        rep.facts.push(format!("Роутер: {ms:.0} мс"));
                        if ok < 5 || ms > 15.0 {
                            rep.issues.push(issue(
                                Severity::Problem,
                                format!("Плохая связь с роутером: {ms:.0} мс, ответов {ok} из 5"),
                                "Проблема внутри вашей сети: слабый сигнал Wi-Fi, плохой кабель или роутер перегружен. Перезагрузите роутер, сядьте ближе или подключитесь кабелем.",
                                Fix::None,
                            ));
                        }
                    }
                    None => rep.facts.push("Роутер: не отвечает на ping".into()),
                }
            }
        }
        let (avg, ok) = icmp_ping(Ipv4Addr::new(1, 1, 1, 1), 5);
        match avg {
            Some(ms) => {
                rep.facts.push(format!("Интернет: {ms:.0} мс"));
                if ok < 4 {
                    rep.issues.push(issue(
                        Severity::Problem,
                        format!("Теряются пакеты до интернета: ответов {ok} из 5"),
                        "Связь с провайдером нестабильна. Если проблема не в Wi-Fi, остаётся ждать или звонить провайдеру.",
                        Fix::None,
                    ));
                } else if ms > 120.0 {
                    rep.issues.push(issue(
                        Severity::Warning,
                        format!("Высокая задержка до интернета: {ms:.0} мс"),
                        "Канал перегружен или провайдер ведёт трафик длинным путём. Проверьте, не качает ли что-то в фоне.",
                        Fix::None,
                    ));
                }
            }
            None => rep.issues.push(issue(
                Severity::Problem,
                "Интернет не отвечает",
                "Проверьте кабель, роутер и баланс у провайдера.",
                Fix::None,
            )),
        }

        // --- занят ли канал ---
        if let Some((in0, out0)) = if_octets(a.index) {
            std::thread::sleep(std::time::Duration::from_millis(1000));
            if let Some((in1, out1)) = if_octets(a.index) {
                let down = (in1.saturating_sub(in0)) as f32 * 8.0 / 1_000_000.0;
                let up = (out1.saturating_sub(out0)) as f32 * 8.0 / 1_000_000.0;
                if down > 4.0 || up > 1.5 {
                    rep.facts.push(format!("Трафик: ↓{down:.1} ↑{up:.1} Мбит/с"));
                    rep.issues.push(issue(
                        Severity::Warning,
                        format!("Канал занят: загрузка {down:.1} Мбит/с, отдача {up:.1} Мбит/с"),
                        "Что-то качает в фоне (Steam, обновления Windows, торрент, видео). На время игры поставьте загрузки на паузу или включите «Ограничить фоновые загрузки» в настройках.",
                        Fix::None,
                    ));
                }
            }
        }
    } else {
        rep.issues.push(issue(
            Severity::Problem,
            "Нет подключения к сети",
            "Windows не видит выхода в интернет. Проверьте кабель или Wi-Fi.",
            Fix::None,
        ));
    }

    // --- виртуальная сеть ---
    let local_server = matches!(ctx.server_host.as_str(), "127.0.0.1" | "localhost" | "");
    let zt_adapter_up = list.iter().any(|a| a.up && a.description.to_lowercase().contains("zerotier"));
    if !ctx.zt_network.is_empty() {
        if !zt_adapter_up {
            rep.issues.push(issue(
                Severity::Problem,
                "Виртуальная сеть ZeroTier не подключена",
                "Без неё не добраться до сервера. Нажмите «Исправить» — программа заново подключит сеть (нужны права администратора).",
                Fix::JoinZeroTier,
            ));
        } else if !local_server {
            match zt_link(ctx) {
                ZtLink::Direct(ms) => rep.facts.push(if ms >= 0 {
                    format!("Сервер: напрямую, {ms} мс")
                } else {
                    "Сервер: напрямую".into()
                }),
                ZtLink::Relay => rep.issues.push(issue(
                    Severity::Problem,
                    "Связь с сервером идёт через ретранслятор",
                    "Прямое соединение не установилось, поэтому задержка выше. Отключите VPN у себя и на компьютере с сервером; если не помогло — включите UPnP в роутере.",
                    Fix::None,
                )),
                ZtLink::Unknown => {}
            }
        }
    }

    // --- соединение с сервером ---
    if ctx.online {
        if !ctx.udp_active && ctx.online_secs > 12 {
            rep.issues.push(issue(
                Severity::Problem,
                "Голос идёт через запасной канал (TCP)",
                "Быстрый канал UDP не проходит — его блокирует VPN, антивирус или брандмауэр. Задержка голоса из-за этого выше.",
                Fix::None,
            ));
        }
        if let Some(avg) = ctx.ping_avg {
            rep.facts.push(format!("Пинг до сервера: {avg:.0} мс"));
            if avg > 100.0 {
                rep.issues.push(issue(
                    Severity::Warning,
                    format!("Высокий пинг до сервера: {avg:.0} мс"),
                    "Голос будет заметно запаздывать. Обычно виноват VPN, ретранслятор или занятый канал.",
                    Fix::None,
                ));
            }
        }
        if let Some(j) = ctx.ping_jitter {
            if j > 20.0 {
                rep.issues.push(issue(
                    Severity::Warning,
                    format!("Пинг до сервера скачет (разброс {j:.0} мс)"),
                    "Связь нестабильна: Wi-Fi, занятый канал или проблемы у провайдера. Голос может прерываться.",
                    Fix::None,
                ));
            }
        }
        if let Some(l) = ctx.loss_percent {
            if l > 3.0 {
                rep.issues.push(issue(
                    Severity::Warning,
                    format!("Теряются голосовые пакеты: {l:.0} %"),
                    "Часть звука приходится восстанавливать. Причины те же: Wi-Fi, занятый канал, провайдер.",
                    Fix::None,
                ));
            }
        }
    } else if matches!(ctx.status, crate::core::Status::Reconnecting(_)) && ctx.uses_p2p {
        p2p_client_checks(ctx, &mut rep);
    } else if matches!(ctx.status, crate::core::Status::Reconnecting(_)) && !local_server {
        if let Some(i) = reachability(&ctx.server_host, ctx.server_port) {
            rep.issues.push(i);
        }
    }

    // --- сервер на этом компьютере ---
    if ctx.runs_server {
        server_checks(ctx, &mut rep);
    }

    rep
}

/// Тип NAT по двум STUN-серверам (кэш на 30 минут): (внешний адрес, порт одинаковый).
fn nat_type(force: bool) -> Option<(SocketAddr, Option<bool>)> {
    static CACHE: Mutex<Option<(Instant, Option<(SocketAddr, Option<bool>)>)>> = Mutex::new(None);
    let mut c = CACHE.lock().unwrap();
    if let Some((at, v)) = c.as_ref() {
        if !force && at.elapsed() < Duration::from_secs(1800) {
            return *v;
        }
    }
    let v = crate::p2p::nat_check().map(|(a, b)| (a, b.map(|b| b.port() == a.port())));
    *c = Some((Instant::now(), v));
    v
}

/// Клиент с кодом приглашения не может подключиться: смотрим, пропускает ли NAT прямые соединения.
fn p2p_client_checks(ctx: &Context, rep: &mut Report) {
    let zt_fix = if ctx.zt_network.is_empty() { Fix::None } else { Fix::JoinZeroTier };
    match nat_type(ctx.force) {
        None => rep.issues.push(issue(
            Severity::Problem,
            "UDP в интернет не проходит",
            "Прямое соединение невозможно: UDP закрывает брандмауэр, антивирус или провайдер. Попробуйте другую сеть или запасной путь через ZeroTier.",
            zt_fix,
        )),
        Some((addr, Some(false))) => rep.issues.push(issue(
            Severity::Problem,
            "Ваш NAT не даёт прямых соединений",
            format!("Внешний адрес {} меняется для разных серверов (симметричный NAT — так бывает у мобильного интернета). Подключитесь через другую сеть или включите запасной путь ZeroTier.", addr.ip()),
            zt_fix,
        )),
        Some((addr, _)) => rep.facts.push(format!("NAT: пробиваемый, {}", addr.ip())),
    }
}

/// Почему не удаётся подключиться: сначала ping до компьютера, потом попытка открыть порт.
fn reachability(host: &str, port: u16) -> Option<Issue> {
    let addr: SocketAddr = (host, port).to_socket_addrs().ok()?.find(|a| a.is_ipv4())?;
    let std::net::IpAddr::V4(ip) = addr.ip() else { return None };
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(3));
    let refused = matches!(&tcp, Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused);
    if tcp.is_ok() {
        return None;
    }
    let (_, answered) = icmp_ping(ip, 3);
    Some(if refused {
        issue(
            Severity::Problem,
            "На компьютере с сервером не запущен сервер",
            format!("Компьютер {ip} в сети, но порт {port} никто не слушает. Попросите владельца запустить «Рацию» с включённым сервером."),
            Fix::None,
        )
    } else if answered > 0 {
        issue(
            Severity::Problem,
            "Порт сервера закрыт",
            format!("Компьютер {ip} отвечает, но порт {port} не открывается — его закрывает брандмауэр на компьютере с сервером. Владельцу: «Сервер» → «Исправить»."),
            Fix::None,
        )
    } else {
        issue(
            Severity::Problem,
            "Компьютер с сервером не отвечает",
            format!("{ip} не отвечает: компьютер с сервером выключен, без интернета, или (для ZeroTier) не в виртуальной сети. Программа подключится сама, как только он появится."),
            Fix::None,
        )
    })
}

/// Медленные проверки (netsh, PowerShell) выполняются не чаще раза в 30 минут, если не попросили.
struct SlowCache {
    at: Option<Instant>,
    port: u16,
    port_state: Option<crate::server::ports::PortState>,
    firewall: Option<Firewall>,
}

static SLOW: Mutex<SlowCache> = Mutex::new(SlowCache { at: None, port: 0, port_state: None, firewall: None });

#[derive(Clone, Copy, Debug)]
struct Firewall {
    enabled: bool,
    allows_port: bool,
    blocks_app: bool,
}

fn firewall_state(port: u16) -> Option<Firewall> {
    let script = format!(
        "$ErrorActionPreference = 'SilentlyContinue'\n\
         $on = ((Get-Service mpssvc).Status -eq 'Running') -and [bool](Get-NetFirewallProfile | Where-Object {{ $_.Enabled -eq 'True' }})\n\
         $allow = $false; $block = $false\n\
         if ($on) {{\n\
           foreach ($f in (Get-NetFirewallPortFilter -Protocol TCP | Where-Object {{ $_.LocalPort -eq '{port}' }})) {{\n\
             $r = $f | Get-NetFirewallRule\n\
             if ($r.Enabled -eq 'True' -and $r.Direction -eq 'Inbound' -and $r.Action -eq 'Allow') {{ $allow = $true }}\n\
           }}\n\
           foreach ($f in (Get-NetFirewallApplicationFilter | Where-Object {{ $_.Program -like '*\\raciya.exe' }})) {{\n\
             $r = $f | Get-NetFirewallRule\n\
             if ($r.Enabled -eq 'True' -and $r.Direction -eq 'Inbound') {{ if ($r.Action -eq 'Block') {{ $block = $true }} else {{ $allow = $true }} }}\n\
           }}\n\
         }}\n\
         \"fw=$on allow=$allow block=$block\"\n"
    );
    let (_, out) = crate::win::run_powershell(&script);
    let flag = |name: &str| out.contains(&format!("{name}=True"));
    out.contains("fw=").then(|| Firewall { enabled: flag("fw"), allows_port: flag("allow"), blocks_app: flag("block") })
}

fn server_checks(ctx: &Context, rep: &mut Report) {
    if let Some((text, fixable)) = &ctx.server_error {
        rep.issues.push(issue(
            Severity::Problem,
            "Сервер на этом компьютере не запущен",
            capitalize(text),
            if *fixable { Fix::ServerSetup } else { Fix::None },
        ));
        return;
    }
    if !ctx.server_running {
        return;
    }
    let port = ctx.host_port;
    if let Some(p) = &ctx.p2p_host {
        if p.attempted && p.announced == 0 {
            rep.issues.push(issue(
                Severity::Warning,
                "Сервер не смог опубликовать адрес для интернета",
                "Сеть DHT не ответила — UDP наружу закрыт или временно нет интернета. Друзья в локальной сети и через ZeroTier подключатся, по коду приглашения — пока нет. Программа повторит попытку сама.",
                Fix::None,
            ));
        }
        if p.stable_port == Some(false) {
            rep.issues.push(issue(
                Severity::Warning,
                "NAT этого компьютера не даёт прямых соединений",
                "Внешний порт меняется для разных адресатов (симметричный NAT). Друзьям через интернет понадобится запасной путь ZeroTier.",
                Fix::None,
            ));
        }
        if let Some(a) = p.external {
            rep.facts.push(format!("Сервер в интернете: {}", a.ip()));
        }
    }
    // Правила сети ZeroTier (если сеть создана на этом компьютере) должны пропускать порт сервера.
    if !ctx.zt_network.is_empty() {
        if let Some(net) = crate::zt::get(&format!("/controller/network/{}", ctx.zt_network)) {
            if !crate::zt::rules_allow_port(&net["rules"], port) {
                rep.issues.push(issue(
                    Severity::Problem,
                    format!("Сеть ZeroTier не пропускает порт сервера {port}"),
                    "Друзья через ZeroTier не подключатся. Нажмите «Исправить» — программа поменяет правила сети.",
                    Fix::ZeroTierRules,
                ));
            }
        }
    }
    let (port_state, firewall) = {
        let mut c = SLOW.lock().unwrap();
        let stale = ctx.force || c.port != port || c.at.map(|t| t.elapsed() > Duration::from_secs(1800)).unwrap_or(true);
        if stale {
            c.port = port;
            c.port_state = Some(crate::server::ports::state(port));
            c.firewall = firewall_state(port);
            c.at = Some(Instant::now());
        }
        (c.port_state.clone(), c.firewall)
    };
    if let Some(fw) = firewall.filter(|f| f.enabled) {
        if fw.blocks_app {
            rep.issues.push(issue(
                Severity::Problem,
                "Брандмауэр Windows блокирует «Рацию»",
                "Друзья не смогут подключиться к серверу. Нажмите «Исправить» — блокировка снимется (нужны права администратора).",
                Fix::ServerSetup,
            ));
        } else if !fw.allows_port {
            rep.issues.push(issue(
                Severity::Problem,
                format!("Брандмауэр не пропускает порт сервера {port}"),
                "Друзья не смогут подключиться. Нажмите «Исправить» — программа добавит правило брандмауэра (нужны права администратора).",
                Fix::ServerSetup,
            ));
        }
    }
    if let Some(ps) = port_state {
        if ps.at_risk() {
            rep.issues.push(issue(
                Severity::Warning,
                format!("Порт сервера {port} может пропасть после перезагрузки"),
                "Hyper-V, WSL или Docker при каждом старте Windows занимают случайные порты из этого диапазона. Нажмите «Исправить» — порт закрепится за «Рацией» (нужны права администратора).",
                Fix::ServerSetup,
            ));
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Сбрасывает кэш медленных проверок (после системной настройки).
pub fn invalidate_cache() {
    SLOW.lock().unwrap().at = None;
}

