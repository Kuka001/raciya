//! Небольшие обёртки над Win32: приоритеты потоков, пометка трафика, защита пароля, клавиши.

use std::net::UdpSocket;
use std::os::windows::io::AsRawSocket;
use windows_sys::Win32::Foundation::{LocalFree, HANDLE};
use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IP_TOS};
use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB};
use windows_sys::Win32::System::Threading::{
    AvSetMmThreadCharacteristicsW, CreateWaitableTimerExW, GetCurrentThread, SetThreadPriority, SetWaitableTimer,
    WaitForSingleObject, INFINITE, THREAD_PRIORITY_BELOW_NORMAL, THREAD_PRIORITY_HIGHEST,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, GetKeyNameTextW, MapVirtualKeyW};

/// Уровень отладочной трассировки из переменной окружения RACIYA_TRACE (0 — выключена).
pub fn trace_level() -> u8 {
    static LEVEL: std::sync::OnceLock<u8> = std::sync::OnceLock::new();
    *LEVEL.get_or_init(|| std::env::var("RACIYA_TRACE").ok().and_then(|v| v.parse().ok()).unwrap_or(0))
}

/// Идентификатор приложения Windows: по нему система объединяет окна и процессы программы.
pub const APP_ID: &str = "Raciya.VoiceChat";

pub fn set_app_id() {
    use windows_sys::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
    unsafe {
        SetCurrentProcessExplicitAppUserModelID(wide(APP_ID).as_ptr());
    }
}

pub enum Prio {
    Low,
    High,
}

pub fn set_thread_priority(p: Prio) {
    let v = match p {
        Prio::Low => THREAD_PRIORITY_BELOW_NORMAL,
        Prio::High => THREAD_PRIORITY_HIGHEST,
    };
    unsafe {
        SetThreadPriority(GetCurrentThread(), v);
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Переводит текущий поток в класс «Pro Audio» планировщика мультимедиа Windows (MMCSS).
/// Звуковой поток почти не тратит процессор, но должен просыпаться вовремя.
pub fn boost_audio_thread() {
    let name = wide("Pro Audio");
    let mut idx = 0u32;
    unsafe {
        let h = AvSetMmThreadCharacteristicsW(name.as_ptr(), &mut idx);
        if h.is_null() {
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
        }
    }
}

/// Просит пометить исходящие голосовые пакеты как DSCP EF (46).
/// Windows учитывает это значение только вместе с QoS-политикой (см. tools\07-qos.ps1),
/// поэтому результат здесь — лишь признак того, что запрос принят.
pub fn mark_voice_socket(sock: &UdpSocket) -> bool {
    let tos: u32 = 46 << 2;
    unsafe {
        setsockopt(
            sock.as_raw_socket() as usize,
            IPPROTO_IP,
            IP_TOS,
            &tos as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        ) == 0
    }
}

/// Windows по умолчанию сообщает в `recv_from` об ICMP «порт недоступен» от прошлых отправок
/// (WSAECONNRESET). Для сервера это шум: участник просто ушёл. Отключаем.
pub fn disable_udp_connreset(sock: &UdpSocket) {
    use windows_sys::Win32::Networking::WinSock::WSAIoctl;
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    let flag: u32 = 0;
    let mut returned = 0u32;
    unsafe {
        WSAIoctl(
            sock.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            &flag as *const u32 as *const std::ffi::c_void,
            4,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            None,
        );
    }
}

/// Шифрует данные средствами Windows (DPAPI): расшифровать может только тот же пользователь Windows.
pub fn protect_bytes(data: &[u8]) -> Option<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    unsafe {
        let ok = CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut out,
        );
        if ok == 0 || out.pbData.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        Some(bytes)
    }
}

pub fn unprotect_bytes(data: &[u8]) -> Option<Vec<u8>> {
    let mut data = data.to_vec();
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_mut_ptr() };
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    unsafe {
        let ok = CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut out,
        );
        if ok == 0 || out.pbData.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        Some(bytes)
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()).collect()
}

/// Строка, зашифрованная DPAPI, в виде hex (так пароли лежат в config.toml).
pub fn protect(secret: &str) -> String {
    if secret.is_empty() {
        return String::new();
    }
    protect_bytes(secret.as_bytes()).map(|b| to_hex(&b)).unwrap_or_default()
}

pub fn unprotect(hex: &str) -> String {
    if hex.is_empty() {
        return String::new();
    }
    from_hex(hex)
        .and_then(|d| unprotect_bytes(&d))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// Нажата ли сейчас клавиша или кнопка мыши (работает и когда окно игры в фокусе).
#[inline]
pub fn key_down(vk: u32) -> bool {
    unsafe { (GetAsyncKeyState(vk as i32) as u16) & 0x8000 != 0 }
}

/// Название клавиши для интерфейса.
pub fn key_name(vk: u32) -> String {
    match vk {
        0 => "не задана".into(),
        0x04 => "Mouse 3".into(),
        0x05 => "Mouse 4".into(),
        0x06 => "Mouse 5".into(),
        0x14 => "Caps Lock".into(),
        0x20 => "Пробел".into(),
        0xA0 => "Левый Shift".into(),
        0xA1 => "Правый Shift".into(),
        0xA2 => "Левый Ctrl".into(),
        0xA3 => "Правый Ctrl".into(),
        0xA4 => "Левый Alt".into(),
        0xA5 => "Правый Alt".into(),
        0x70..=0x87 => format!("F{}", vk - 0x6F),
        0x60..=0x69 => format!("Num {}", vk - 0x60),
        _ => unsafe {
            let sc = MapVirtualKeyW(vk, 0);
            if sc == 0 {
                return format!("Клавиша {vk}");
            }
            // Клавиши навигации и стрелки — «расширенные» (бит 24).
            let ext = matches!(vk, 0x21..=0x28 | 0x2D | 0x2E | 0x5B | 0x5C | 0x5D | 0x6F | 0x90);
            let lparam = ((sc << 16) | if ext { 1 << 24 } else { 0 }) as i32;
            let mut buf = [0u16; 64];
            let n = GetKeyNameTextW(lparam, buf.as_mut_ptr(), buf.len() as i32);
            if n > 0 {
                String::from_utf16_lossy(&buf[..n as usize])
            } else {
                format!("Клавиша {vk}")
            }
        },
    }
}

/// Клавиши, которые можно назначить на «говорить» (левая и правая кнопки мыши исключены).
pub fn bindable_keys() -> impl Iterator<Item = u32> {
    (0x04u32..=0xFE).filter(|vk| {
        !matches!(
            vk,
            // Обобщённые Shift/Ctrl/Alt дублируют левые/правые варианты; Esc отменяет назначение.
            0x10 | 0x11 | 0x12 | 0x1B | 0x07 | 0x0A | 0x0B | 0xFF
        )
    })
}

/// Таймер высокого разрешения для опроса клавиши без «прожигания» процессора.
pub struct PreciseTimer(HANDLE);

unsafe impl Send for PreciseTimer {}

impl PreciseTimer {
    pub fn new() -> Self {
        const CREATE_WAITABLE_TIMER_HIGH_RESOLUTION: u32 = 0x2;
        const TIMER_ALL_ACCESS: u32 = 0x1F0003;
        unsafe {
            let mut h = CreateWaitableTimerExW(
                std::ptr::null(),
                std::ptr::null(),
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                TIMER_ALL_ACCESS,
            );
            if h.is_null() {
                h = CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 0, TIMER_ALL_ACCESS);
            }
            PreciseTimer(h)
        }
    }

    pub fn sleep_ms(&self, ms: u32) {
        if self.0.is_null() {
            std::thread::sleep(std::time::Duration::from_millis(ms as u64));
            return;
        }
        let due: i64 = -(ms as i64) * 10_000;
        unsafe {
            if SetWaitableTimer(self.0, &due, 0, None, std::ptr::null(), 0) != 0 {
                WaitForSingleObject(self.0, INFINITE);
            } else {
                std::thread::sleep(std::time::Duration::from_millis(ms as u64));
            }
        }
    }
}

/// Запускает консольную программу без окна и не ждёт её завершения.
pub fn run_hidden(exe: &std::path::Path, args: &[&str]) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    std::process::Command::new(exe)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

// ---------------------------------------------------------------------------------------------
// Реестр

pub use windows_sys::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

pub fn reg_get_u32(root: HKEY, sub: &str, name: &str) -> Option<u32> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, RRF_RT_REG_DWORD};
    let mut v = 0u32;
    let mut size = 4u32;
    let r = unsafe {
        RegGetValueW(
            root,
            wide(sub).as_ptr(),
            wide(name).as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            &mut v as *mut u32 as _,
            &mut size,
        )
    };
    (r == 0).then_some(v)
}

pub fn reg_get_string(root: HKEY, sub: &str, name: &str) -> Option<String> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, RRF_RT_REG_SZ};
    let mut buf = [0u16; 1024];
    let mut size = (buf.len() * 2) as u32;
    let r = unsafe {
        RegGetValueW(
            root,
            wide(sub).as_ptr(),
            wide(name).as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as _,
            &mut size,
        )
    };
    if r != 0 {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..len]))
}

pub fn reg_set_string(root: HKEY, sub: &str, name: &str, value: &str) -> bool {
    use windows_sys::Win32::System::Registry::{RegSetKeyValueW, REG_SZ};
    let data = wide(value);
    unsafe {
        RegSetKeyValueW(
            root,
            wide(sub).as_ptr(),
            wide(name).as_ptr(),
            REG_SZ,
            data.as_ptr() as _,
            (data.len() * 2) as u32,
        ) == 0
    }
}

pub fn reg_set_u32(root: HKEY, sub: &str, name: &str, value: u32) -> bool {
    use windows_sys::Win32::System::Registry::{RegSetKeyValueW, REG_DWORD};
    unsafe {
        RegSetKeyValueW(root, wide(sub).as_ptr(), wide(name).as_ptr(), REG_DWORD, &value as *const u32 as _, 4) == 0
    }
}

pub fn reg_delete_value(root: HKEY, sub: &str, name: &str) {
    use windows_sys::Win32::System::Registry::RegDeleteKeyValueW;
    unsafe {
        RegDeleteKeyValueW(root, wide(sub).as_ptr(), wide(name).as_ptr());
    }
}

pub fn reg_delete_tree(root: HKEY, sub: &str) {
    use windows_sys::Win32::System::Registry::RegDeleteTreeW;
    unsafe {
        RegDeleteTreeW(root, wide(sub).as_ptr());
    }
}

pub fn reg_subkeys(root: HKEY, sub: &str) -> Vec<String> {
    use windows_sys::Win32::System::Registry::{RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, KEY_READ};
    let mut out = Vec::new();
    unsafe {
        let mut key: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(root, wide(sub).as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return out;
        }
        let mut i = 0u32;
        loop {
            let mut name = [0u16; 256];
            let mut len = name.len() as u32;
            let r = RegEnumKeyExW(
                key,
                i,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if r != 0 {
                break;
            }
            out.push(String::from_utf16_lossy(&name[..len as usize]));
            i += 1;
        }
        RegCloseKey(key);
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Процессы, права администратора, PowerShell

/// Запускает программу с правами администратора (Windows покажет запрос подтверждения)
/// и ждёт её завершения. `None` — пользователь отказался или запуск не удался.
pub fn run_elevated_wait(exe: &std::path::Path, params: &str) -> Option<u32> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::GetExitCodeProcess;
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let args = wide(params);
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = args.as_ptr();
        info.nShow = 0;
        if ShellExecuteExW(&mut info) == 0 || info.hProcess.is_null() {
            return None;
        }
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 1u32;
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
        Some(code)
    }
}

/// Выполняет сценарий PowerShell без окна. Возвращает код завершения и вывод.
/// Сценарий записывается во временный файл в UTF-8 с BOM, чтобы кириллица читалась правильно.
pub fn run_powershell(script: &str) -> (i32, String) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let path = std::env::temp_dir().join(format!("raciya-{}-{}.ps1", std::process::id(), unique_id()));
    let mut data = vec![0xEFu8, 0xBB, 0xBF];
    data.extend_from_slice(script.as_bytes());
    if std::fs::write(&path, data).is_err() {
        return (-1, "не удалось записать временный файл".into());
    }
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&path)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .output();
    let _ = std::fs::remove_file(&path);
    match out {
        Ok(o) => (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned()),
        Err(e) => (-1, e.to_string()),
    }
}

fn unique_id() -> u64 {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

pub fn message_box(text: &str, title: &str, question: bool) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, IDYES, MB_ICONINFORMATION, MB_ICONQUESTION, MB_YESNO};
    let flags = if question { MB_YESNO | MB_ICONQUESTION } else { MB_ICONINFORMATION };
    unsafe { MessageBoxW(std::ptr::null_mut(), wide(text).as_ptr(), wide(title).as_ptr(), flags) == IDYES }
}

pub fn copy_to_clipboard(text: &str) -> bool {
    use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData};
    use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    let data = wide(text);
    unsafe {
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return false;
        }
        EmptyClipboard();
        let h = GlobalAlloc(GMEM_MOVEABLE, data.len() * 2);
        let mut ok = false;
        if !h.is_null() {
            let p = GlobalLock(h) as *mut u16;
            if !p.is_null() {
                std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
                GlobalUnlock(h);
                // 13 = CF_UNICODETEXT
                ok = !SetClipboardData(13, h as _).is_null();
            }
        }
        CloseClipboard();
        ok
    }
}

/// Выполняет консольную программу без окна и возвращает её вывод (для `netsh` и т.п.).
pub fn run_capture(exe: &str, args: &[&str]) -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(exe)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Имя файла программы по номеру процесса (`mumble-server.exe` и т.п.).
pub fn process_name(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    if pid == 0 {
        return None;
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        Some(path.rsplit('\\').next().unwrap_or(&path).to_string())
    }
}

/// Какая программа слушает этот порт (TCP или UDP, IPv4). `None` — никто или не удалось узнать.
pub fn port_owner(port: u16, udp: bool) -> Option<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
        TCP_TABLE_OWNER_PID_LISTENER, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    let mut size = 0u32;
    let mut buf: Vec<u64> = Vec::new();
    let mut ok = false;
    for _ in 0..3 {
        let r = unsafe {
            if udp {
                GetExtendedUdpTable(buf.as_mut_ptr() as _, &mut size, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
            } else {
                GetExtendedTcpTable(buf.as_mut_ptr() as _, &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_LISTENER, 0)
            }
        };
        if r == 0 {
            ok = !buf.is_empty();
            break;
        }
        if r != 122 {
            // Не ERROR_INSUFFICIENT_BUFFER.
            return None;
        }
        buf = vec![0u64; size as usize / 8 + 1];
    }
    if !ok {
        return None;
    }
    let base = buf.as_ptr() as *const u8;
    let count = unsafe { *(base as *const u32) } as usize;
    // Таблица: dwNumEntries, затем строки (выравнивание по 4 байта).
    let rows = unsafe { base.add(4) };
    for i in 0..count {
        let (local_port, pid) = unsafe {
            if udp {
                let r = &*(rows as *const MIB_UDPROW_OWNER_PID).add(i);
                (r.dwLocalPort, r.dwOwningPid)
            } else {
                let r = &*(rows as *const MIB_TCPROW_OWNER_PID).add(i);
                (r.dwLocalPort, r.dwOwningPid)
            }
        };
        // Порт хранится в сетевом порядке в младших 16 битах.
        if u16::from_be(local_port as u16) == port {
            return process_name(pid).or_else(|| Some(format!("процесс {pid}")));
        }
    }
    None
}

/// Отключает Cloudflare WARP, если он установлен: через него друзья не могут подключиться напрямую,
/// а игровой трафик идёт в обход.
pub fn disconnect_warp() -> bool {
    let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
    let cli = std::path::Path::new(&pf).join("Cloudflare").join("Cloudflare WARP").join("warp-cli.exe");
    if cli.exists() {
        run_hidden(&cli, &["disconnect"])
    } else {
        false
    }
}
