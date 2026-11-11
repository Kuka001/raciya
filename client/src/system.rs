//! Установка программы и системные настройки.
//!
//! Права администратора нужны только для того, без чего связь не работает, и только тогда,
//! когда это действительно нужно:
//! - `client` — ZeroTier, если в коде приглашения есть виртуальная сеть;
//! - `server` — правила брандмауэра и закрепление порта на компьютере с сервером;
//! - `qos-on/off`, `gamemode-on/off` — по кнопке в настройках;
//! - `remove` — при удалении программы, если что-то из этого применялось.
//!
//! Всё это делает один сценарий `scripts/system-setup.ps1`, встроенный в программу.
//! Программа запускает саму себя с ключом `--system-setup` и запросом прав администратора.

use crate::config::Config;
use crate::win::{self, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use std::path::{Path, PathBuf};

const APP_KEY: &str = "SOFTWARE\\Raciya";
const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const UNINSTALL_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Raciya";
const SETUP_SCRIPT: &str = include_str!("../scripts/system-setup.ps1");

pub const QUIT_EVENT: &str = "RaciyaVoiceChat.Quit";

fn local_appdata() -> PathBuf {
    std::env::var("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."))
}

/// Куда устанавливается программа: `%LOCALAPPDATA%\Programs\Raciya`.
/// Папка принадлежит пользователю, поэтому обновления не требуют прав администратора.
pub fn install_dir() -> PathBuf {
    local_appdata().join("Programs").join("Raciya")
}

pub fn installed_exe() -> PathBuf {
    install_dir().join("raciya.exe")
}

/// Служебные файлы пользователя: журнал, журнал настройки, ключ доступа к локальной службе ZeroTier.
pub fn user_dir() -> PathBuf {
    local_appdata().join("Raciya")
}

pub fn current_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("raciya.exe"))
}

/// Программа, которую видит брандмауэр: установленная копия, а если её нет — запущенная.
pub fn app_exe() -> PathBuf {
    if is_installed() {
        installed_exe()
    } else {
        current_exe()
    }
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
}

pub fn is_installed_location() -> bool {
    same_path(&current_exe(), &installed_exe())
}

/// Переносной режим: рядом с программой лежит `raciya.toml`.
pub fn is_portable() -> bool {
    current_exe().parent().map(|p| p.join("raciya.toml").exists()).unwrap_or(false)
}

pub fn is_installed() -> bool {
    installed_exe().exists()
}

// --- состояние системных настроек ------------------------------------------------------------

/// Приоритет голосового трафика (QoS) включён. Отметка общая с версией 0.2.
pub fn qos_applied() -> bool {
    win::reg_get_u32(HKEY_LOCAL_MACHINE, APP_KEY, "TweaksVersion").unwrap_or(0) >= 1
}

pub fn game_mode() -> bool {
    win::reg_get_u32(HKEY_LOCAL_MACHINE, APP_KEY, "GameMode").unwrap_or(0) == 1
}

/// Для какого порта выполнена настройка сервера (брандмауэр и закрепление порта).
pub fn server_setup_port() -> Option<u16> {
    win::reg_get_u32(HKEY_LOCAL_MACHINE, APP_KEY, "ServerPort").and_then(|p| u16::try_from(p).ok())
}

/// Применялось ли хоть что-то от имени администратора (тогда удаление должно это откатить).
fn anything_applied() -> bool {
    ["TweaksVersion", "GameMode", "ServerPort"]
        .iter()
        .any(|n| win::reg_get_u32(HKEY_LOCAL_MACHINE, APP_KEY, n).is_some())
        || ["PinnedPorts", "ZeroTierNetwork"]
            .iter()
            .any(|n| win::reg_get_string(HKEY_LOCAL_MACHINE, APP_KEY, n).is_some())
}

pub fn autostart_enabled() -> bool {
    win::reg_get_string(HKEY_CURRENT_USER, RUN_KEY, "Raciya").is_some()
}

pub fn set_autostart(on: bool) {
    if on {
        win::reg_set_string(HKEY_CURRENT_USER, RUN_KEY, "Raciya", &format!("\"{}\" --autostart", app_exe().display()));
    } else {
        win::reg_delete_value(HKEY_CURRENT_USER, RUN_KEY, "Raciya");
    }
}

// --- приглашение -----------------------------------------------------------------------------

/// Что можно вставить в поле «Адрес сервера» или в установщик:
/// - обычный адрес: `192.168.0.15`, `myhost.example:40000`;
/// - код с виртуальной сетью ZeroTier: `номер_сети@адрес[:порт]`, например `0123456789abcdef@10.77.64.1`.
#[derive(Clone, Debug, PartialEq)]
pub struct Invite {
    /// Номер сети ZeroTier (16 hex-символов), если сервер доступен только через неё.
    pub network: Option<String>,
    /// Адрес сервера в том виде, как его хранит `Config::server`.
    pub server: String,
}

pub fn parse_invite(text: &str) -> Option<Invite> {
    let t = text.trim().trim_start_matches('\u{feff}');
    let (network, server) = match t.split_once('@') {
        Some((net, server)) => {
            let net = net.trim().to_lowercase();
            if net.len() != 16 || !net.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            (Some(net), server.trim())
        }
        None => (None, t),
    };
    if server.is_empty() || !server.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']')) {
        return None;
    }
    crate::config::parse_address(server)?;
    Some(Invite { network, server: server.to_string() })
}

pub fn make_invite(network: Option<&str>, server: &str) -> String {
    match network {
        Some(n) if !n.is_empty() => format!("{n}@{server}"),
        _ => server.to_string(),
    }
}

/// Приглашение из файла `invite.txt` рядом с установщиком (если владелец сервера его приложил).
pub fn invite_from_file() -> Option<String> {
    let path = current_exe().parent()?.join("invite.txt");
    let text = std::fs::read_to_string(path).ok()?;
    let line = text.lines().map(|l| l.trim().trim_start_matches('\u{feff}')).find(|l| !l.is_empty())?;
    parse_invite(line).map(|i| make_invite(i.network.as_deref(), &i.server))
}

// --- системная настройка (права администратора) ----------------------------------------------

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

const MODES: [&str; 7] = ["client", "server", "qos-on", "qos-off", "gamemode-on", "gamemode-off", "remove"];

/// Параметры системной настройки.
#[derive(Clone, Debug, Default)]
pub struct SetupArgs {
    pub network: String,
    pub port: Option<u16>,
}

/// Точка входа процесса с правами администратора: `raciya.exe --system-setup <режим> ...`.
pub fn system_setup_worker(args: &[String]) -> i32 {
    let value = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let mode = value("--system-setup").unwrap_or_default();
    let network = value("--network").unwrap_or_default();
    let port = value("--port").unwrap_or_default();
    let dir = value("--user-dir").map(PathBuf::from).unwrap_or_else(user_dir);
    if !MODES.contains(&mode.as_str()) {
        return 2;
    }
    if !network.is_empty() && !(network.len() == 16 && network.chars().all(|c| c.is_ascii_hexdigit())) {
        return 2;
    }
    if !port.is_empty() && port.parse::<u16>().map(|p| p == 0).unwrap_or(true) {
        return 2;
    }
    // Правило брандмауэра — для той программы, которая запросила настройку (этой же).
    let exe = current_exe();
    let _ = std::fs::create_dir_all(&dir);
    let log = dir.join("setup.log");
    let script = format!(
        "$Mode = {}\n$Network = {}\n$Port = {}\n$Exe = {}\n$UserDir = {}\n$Log = {}\n{}",
        ps_quote(&mode),
        ps_quote(&network),
        ps_quote(&port),
        ps_quote(&exe.to_string_lossy()),
        ps_quote(&dir.to_string_lossy()),
        ps_quote(&log.to_string_lossy()),
        SETUP_SCRIPT
    );
    win::run_powershell(&script).0
}

/// Итог системной настройки: строки журнала этого запуска.
pub struct SetupResult {
    pub ok: bool,
    pub code: u32,
    pub lines: Vec<String>,
}

impl SetupResult {
    /// Короткое описание неудачных шагов для показа пользователю.
    pub fn failures(&self) -> String {
        let f: Vec<String> = self
            .lines
            .iter()
            .filter(|l| l.contains("FAIL "))
            .map(|l| l.split_once("FAIL ").map(|x| x.1).unwrap_or(l).to_string())
            .collect();
        if f.is_empty() {
            format!("настройка не выполнена (код {})", self.code)
        } else {
            f.join("; ")
        }
    }
}

/// Запрашивает права администратора и выполняет системную настройку в указанном режиме.
/// `Err` — пользователь не дал разрешения.
pub fn request_system_setup(mode: &str, args: &SetupArgs) -> Result<SetupResult, String> {
    let dir = user_dir();
    let _ = std::fs::create_dir_all(&dir);
    let mut params = format!("--system-setup {mode} --user-dir \"{}\"", dir.display());
    if !args.network.is_empty() {
        params.push_str(&format!(" --network {}", args.network));
    }
    if let Some(p) = args.port {
        params.push_str(&format!(" --port {p}"));
    }
    clog!("системная настройка: {mode}");
    let log = dir.join("setup.log");
    let before = std::fs::metadata(&log).map(|m| m.len()).unwrap_or(0);
    // Настройку выполняет этот же файл программы: версия сценария всегда совпадает с версией окна
    // (установленная копия может быть старше, например при первом запуске новой версии).
    let code = win::run_elevated_wait(&current_exe(), &params)
        .ok_or_else(|| "нужно разрешение администратора — настройка не выполнена".to_string())?;
    // Берём только то, что дописал этот запуск.
    let bytes = std::fs::read(&log).unwrap_or_default();
    let fresh = bytes.get(before as usize..).unwrap_or_default();
    let text = String::from_utf8_lossy(fresh);
    let lines: Vec<String> = text
        .lines()
        .map(|l| l.trim_start_matches('\u{feff}'))
        .filter(|l| !l.trim().is_empty() && !l.starts_with("--- "))
        .map(|l| l.to_string())
        .collect();
    clog!("  код завершения {code}");
    for l in &lines {
        clog!("  {l}");
    }
    Ok(SetupResult { ok: code == 0, code, lines })
}

// --- установка -------------------------------------------------------------------------------

fn signal_quit() {
    use windows_sys::Win32::System::Threading::{OpenEventW, SetEvent};
    let name: Vec<u16> = QUIT_EVENT.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let ev = OpenEventW(0x0002, 0, name.as_ptr());
        if !ev.is_null() {
            SetEvent(ev);
            windows_sys::Win32::Foundation::CloseHandle(ev);
        }
    }
}

fn shortcuts_script(exe: &Path, create: bool) -> String {
    let body = if create {
        format!(
            "$l = $ws.CreateShortcut($p); $l.TargetPath = {}; $l.WorkingDirectory = {}; $l.Description = 'Голосовой чат'; $l.Save()",
            ps_quote(&exe.to_string_lossy()),
            ps_quote(&exe.parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default())
        )
    } else {
        "if (Test-Path $p) { Remove-Item $p -Force }".to_string()
    };
    format!(
        "$ws = New-Object -ComObject WScript.Shell\nforeach ($d in [Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs')) {{ $p = Join-Path $d 'Рация.lnk'; {body} }}\n"
    )
}

/// Устанавливает программу для текущего пользователя.
/// Права администратора запрашиваются, только если в приглашении есть сеть ZeroTier.
/// `progress` получает короткие сообщения о ходе установки.
/// Возвращает предупреждение, если установка прошла, но подключение к сети — нет.
pub fn install(invite: Option<&Invite>, autostart: bool, progress: &dyn Fn(&str)) -> Result<Option<String>, String> {
    let src = current_exe();
    let dst = installed_exe();
    let dir = install_dir();

    if !same_path(&src, &dst) {
        progress("Копирую программу…");
        std::fs::create_dir_all(&dir).map_err(|e| format!("не удалось создать папку: {e}"))?;
        // Если «Рация» уже запущена — просим её закрыться и ждём, пока файл освободится.
        signal_quit();
        let mut copied = false;
        for _ in 0..40 {
            if std::fs::copy(&src, &dst).is_ok() {
                copied = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        if !copied {
            return Err("не удалось записать программу: закройте «Рацию» (значок у часов → Выход) и повторите".into());
        }
        crate::update::cleanup(&dst);
    }

    progress("Сохраняю настройки…");
    let mut cfg = Config::load_from(crate::config::roaming_dir().join("config.toml"));
    if let Some(inv) = invite {
        cfg.server = inv.server.clone();
        if let Some(n) = &inv.network {
            cfg.zt_network = n.clone();
        }
    }
    cfg.save();

    progress("Создаю ярлыки…");
    win::run_powershell(&shortcuts_script(&dst, true));
    let size_kb = std::fs::metadata(&dst).map(|m| m.len() / 1024).unwrap_or(0) as u32;
    win::reg_set_string(HKEY_CURRENT_USER, UNINSTALL_KEY, "DisplayName", "Рация");
    win::reg_set_string(HKEY_CURRENT_USER, UNINSTALL_KEY, "DisplayVersion", env!("CARGO_PKG_VERSION"));
    win::reg_set_string(HKEY_CURRENT_USER, UNINSTALL_KEY, "Publisher", "Raciya");
    win::reg_set_string(HKEY_CURRENT_USER, UNINSTALL_KEY, "DisplayIcon", &dst.to_string_lossy());
    win::reg_set_string(HKEY_CURRENT_USER, UNINSTALL_KEY, "InstallLocation", &dir.to_string_lossy());
    win::reg_set_string(HKEY_CURRENT_USER, UNINSTALL_KEY, "UninstallString", &format!("\"{}\" --uninstall", dst.display()));
    win::reg_set_u32(HKEY_CURRENT_USER, UNINSTALL_KEY, "NoModify", 1);
    win::reg_set_u32(HKEY_CURRENT_USER, UNINSTALL_KEY, "NoRepair", 1);
    win::reg_set_u32(HKEY_CURRENT_USER, UNINSTALL_KEY, "EstimatedSize", size_kb);
    if autostart || autostart_enabled() {
        // Заодно обновляем путь в существующей записи автозапуска.
        set_autostart(true);
    }

    let network = invite.and_then(|i| i.network.clone()).unwrap_or_default();
    if network.is_empty() {
        return Ok(None);
    }
    progress("Подключаю виртуальную сеть ZeroTier (Windows спросит разрешение)…");
    match request_system_setup("client", &SetupArgs { network, port: None }) {
        Ok(r) if r.ok => Ok(None),
        Ok(r) => Ok(Some(format!("виртуальная сеть не подключилась: {}", r.failures()))),
        Err(e) => Ok(Some(e)),
    }
}

pub fn launch_installed(args: &[&str]) {
    use std::os::windows::process::CommandExt;
    let exe = installed_exe();
    let _ = std::process::Command::new(&exe)
        .args(args)
        .current_dir(install_dir())
        .creation_flags(0x0000_0008) // DETACHED_PROCESS
        .spawn();
}

/// Остатки версии 0.2: копия Mumble Server, из которой запускался сервер (35 МБ).
pub fn cleanup_legacy() {
    let dir = user_dir().join("server");
    let old = dir.join("raciya.exe");
    if old.exists() && std::fs::remove_file(&old).is_ok() {
        clog!("удалена копия Mumble Server из версии 0.2: {}", old.display());
    }
    let _ = std::fs::remove_dir(&dir);
}

/// Удаление программы: `raciya.exe --uninstall` (вызывается из «Параметры → Приложения»).
pub fn uninstall() {
    if !win::message_box(
        "Удалить «Рацию» с этого компьютера?\n\nБудут убраны программа, ярлыки и сетевые настройки, которые она добавила. ZeroTier (если ставился) останется — его можно удалить отдельно в «Параметры → Приложения».",
        "Рация",
        true,
    ) {
        return;
    }
    signal_quit();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let base = crate::config::roaming_dir();
    let cfg = Config::load_from(base.join("config.toml"));
    if anything_applied() {
        let _ = request_system_setup("remove", &SetupArgs { network: cfg.zt_network.clone(), port: None });
    }
    win::run_powershell(&shortcuts_script(&installed_exe(), false));
    win::reg_delete_value(HKEY_CURRENT_USER, RUN_KEY, "Raciya");
    win::reg_delete_tree(HKEY_CURRENT_USER, UNINSTALL_KEY);
    let _ = std::fs::remove_dir_all(user_dir());
    // Настройки пользователя удаляем, данные сервера (сертификат, журнал) оставляем.
    let _ = std::fs::remove_file(base.join("config.toml"));
    win::message_box("«Рация» удалена.", "Рация", false);
    // Папку с программой удаляет командная строка уже после выхода этого процесса.
    let cmd = format!("ping -n 3 127.0.0.1 >nul & rmdir /s /q \"{}\"", install_dir().display());
    win::run_hidden(Path::new("cmd.exe"), &["/c", &cmd]);
}

/// Делает значок в трее видимым сразу, а не в скрытой области (если пользователь сам не решил иначе).
pub fn promote_tray_icon() {
    let base = "Control Panel\\NotifyIconSettings";
    let me = current_exe().to_string_lossy().to_lowercase();
    for sub in win::reg_subkeys(HKEY_CURRENT_USER, base) {
        let key = format!("{base}\\{sub}");
        let Some(path) = win::reg_get_string(HKEY_CURRENT_USER, &key, "ExecutablePath") else { continue };
        if path.to_lowercase() == me && win::reg_get_u32(HKEY_CURRENT_USER, &key, "IsPromoted").is_none() {
            win::reg_set_u32(HKEY_CURRENT_USER, &key, "IsPromoted", 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_parsing() {
        let i = parse_invite(" 0123456789ABCDEF@10.77.64.1 \n").unwrap();
        assert_eq!(i.network.as_deref(), Some("0123456789abcdef"));
        assert_eq!(i.server, "10.77.64.1");
        assert_eq!(make_invite(i.network.as_deref(), &i.server), "0123456789abcdef@10.77.64.1");
        let j = parse_invite("0123456789abcdef@10.77.64.1:40738").unwrap();
        assert_eq!(j.server, "10.77.64.1:40738");
        // Обычный адрес — тоже приглашение, только без виртуальной сети.
        let k = parse_invite("192.168.0.15:64738").unwrap();
        assert_eq!(k, Invite { network: None, server: "192.168.0.15:64738".into() });
        assert_eq!(make_invite(None, "192.168.0.15"), "192.168.0.15");
        assert!(parse_invite("xyz@10.0.0.1").is_none());
        assert!(parse_invite("0123456789abcdef@").is_none());
        assert!(parse_invite("0123456789abcdef@bad host").is_none());
        assert!(parse_invite("host:notaport").is_none());
        assert!(parse_invite("").is_none());
    }
}
