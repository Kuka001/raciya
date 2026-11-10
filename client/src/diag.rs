//! Диагностика сети: ищет то, что мешает связи и повышает пинг (VPN, прокси, Wi-Fi,
//! ретранслятор, занятый канал, плохая связь с роутером), и объясняет, что с этим делать.

use std::net::Ipv4Addr;
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
    ApplyTweaks,
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
    pub zt_network: String,
    pub ping_avg: Option<f32>,
    pub ping_jitter: Option<f32>,
    pub loss_percent: Option<f32>,
    pub tweaks_applied: bool,
    pub runs_server: bool,
    pub server_running: bool,
    pub user_dir: std::path::PathBuf,
}

struct Adapter {
    index: u32,
    name: String,
    description: String,
    if_type: u32,
    up: bool,
    gateway: Option<Ipv4Addr>,
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
            });
            p = a.Next;
        }
    }
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
    let server_node = &ctx.zt_network[..10];
    let token = std::fs::read_to_string(ctx.user_dir.join("zt.token")).unwrap_or_default();
    let token = token.trim();
    if token.is_empty() {
        return ZtLink::Unknown;
    }
    let port = std::fs::read_to_string(ctx.user_dir.join("zt.port"))
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .unwrap_or(9993);
    let resp = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .get(&format!("http://127.0.0.1:{port}/peer/{server_node}"))
        .set("X-ZT1-Auth", token)
        .call();
    let Ok(resp) = resp else { return ZtLink::Unknown };
    let Ok(body) = resp.into_string() else { return ZtLink::Unknown };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else { return ZtLink::Unknown };
    let direct = v["paths"]
        .as_array()
        .map(|p| p.iter().any(|x| x["active"].as_bool().unwrap_or(false)))
        .unwrap_or(false);
    if direct {
        ZtLink::Direct(v["latency"].as_i64().unwrap_or(-1))
    } else {
        ZtLink::Relay
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
                "Без неё не добраться до сервера. Нажмите «Исправить» — программа заново подключит сеть.",
                Fix::ApplyTweaks,
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
    }
    if ctx.runs_server && !ctx.server_running {
        rep.issues.push(issue(
            Severity::Problem,
            "Сервер на этом компьютере не запущен",
            "Друзья не смогут подключиться. Проверьте, что Mumble Server установлен, и перезапустите «Рацию».",
            Fix::None,
        ));
    }

    // --- системные настройки ---
    if !ctx.tweaks_applied {
        rep.issues.push(issue(
            Severity::Warning,
            "Сетевые настройки Windows не применены",
            "Приоритет голосового трафика и остальные настройки одинаковы у всех участников. Нажмите «Исправить» (потребуется разрешение администратора).",
            Fix::ApplyTweaks,
        ));
    }

    rep
}
