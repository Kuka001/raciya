//! Установка программы и системные настройки — одинаковые для всех участников.
//!
//! Всё, что требует прав администратора (ZeroTier, приоритет голосового трафика, правила
//! брандмауэра), делает один сценарий `scripts/system-setup.ps1`, встроенный в программу.
//! Программа запускает саму себя с ключом `--system-setup` и запросом прав администратора.

use crate::config::Config;
use crate::win::{self, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use std::path::{Path, PathBuf};

/// Номер набора системных настроек. Увеличивается, когда набор меняется:
/// программа после обновления предложит применить его заново.
pub const TWEAKS_VERSION: u32 = 1;

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

/// Служебные файлы пользователя: журнал настройки, ключ доступа к локальной службе ZeroTier.
pub fn user_dir() -> PathBuf {
    local_appdata().join("Raciya")
}

pub fn current_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("raciya.exe"))
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

pub fn tweaks_applied() -> bool {
    win::reg_get_u32(HKEY_LOCAL_MACHINE, APP_KEY, "TweaksVersion").unwrap_or(0) >= TWEAKS_VERSION
}

pub fn game_mode() -> bool {
    win::reg_get_u32(HKEY_LOCAL_MACHINE, APP_KEY, "GameMode").unwrap_or(0) == 1
}

pub fn autostart_enabled() -> bool {
    win::reg_get_string(HKEY_CURRENT_USER, RUN_KEY, "Raciya").is_some()
}

pub fn set_autostart(on: bool) {
    if on {
        let exe = if is_installed() { installed_exe() } else { current_exe() };
        win::reg_set_string(HKEY_CURRENT_USER, RUN_KEY, "Raciya", &format!("\"{}\" --autostart", exe.display()));
    } else {
        win::reg_delete_value(HKEY_CURRENT_USER, RUN_KEY, "Raciya");
    }
}

// --- приглашение -----------------------------------------------------------------------------

/// Код приглашения: `номер_сети@адрес_сервера`, например `0123456789abcdef@10.77.64.1`.
/// Его владелец сервера отправляет друзьям лично; в программе и в репозитории его нет.
#[derive(Clone, Debug, PartialEq)]
pub struct Invite {
    pub network: String,
    pub server: String,
}

pub fn parse_invite(text: &str) -> Option<Invite> {
    let t = text.trim();
    let (net, server) = t.split_once('@')?;
    let net = net.trim().to_lowercase();
    let server = server.trim();
    if net.len() != 16 || !net.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if server.is_empty() || !server.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':')) {
        return None;
    }
    Some(Invite { network: net, server: server.to_string() })
}

pub fn make_invite(network: &str, server: &str) -> String {
    format!("{network}@{server}")
}

/// Приглашение из файла `invite.txt` рядом с установщиком (если владелец сервера его приложил).
pub fn invite_from_file() -> Option<String> {
    let path = current_exe().parent()?.join("invite.txt");
    let text = std::fs::read_to_string(path).ok()?;
    let line = text.lines().map(|l| l.trim().trim_start_matches('\u{feff}')).find(|l| !l.is_empty())?;
    parse_invite(line).map(|i| make_invite(&i.network, &i.server))
}

// --- системная настройка (права администратора) ----------------------------------------------

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Точка входа процесса с правами администратора: `raciya.exe --system-setup <режим> ...`.
pub fn system_setup_worker(args: &[String]) -> i32 {
    let value = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let mode = value("--system-setup").unwrap_or_default();
    let network = value("--network").unwrap_or_default();
    let dir = value("--user-dir").map(PathBuf::from).unwrap_or_else(user_dir);
    if !matches!(mode.as_str(), "apply" | "remove" | "gamemode-on" | "gamemode-off") {
        return 2;
    }
    if !network.is_empty() && !(network.len() == 16 && network.chars().all(|c| c.is_ascii_hexdigit())) {
        return 2;
    }
    let _ = std::fs::create_dir_all(&dir);
    let log = dir.join("setup.log");
    let script = format!(
        "$Mode = {}\n$Network = {}\n$UserDir = {}\n$Log = {}\n$TweaksVersion = {}\n{}",
        ps_quote(&mode),
        ps_quote(&network),
        ps_quote(&dir.to_string_lossy()),
        ps_quote(&log.to_string_lossy()),
        TWEAKS_VERSION,
        SETUP_SCRIPT
    );
    win::run_powershell(&script).0
}

/// Итог системной настройки: строки журнала последнего запуска.
pub struct SetupResult {
    pub ok: bool,
    pub lines: Vec<String>,
}

impl SetupResult {
    /// Короткое описание неудачных шагов для показа пользователю.
    pub fn failures(&self) -> String {
        self.lines
            .iter()
            .filter(|l| l.contains("FAIL "))
            .map(|l| l.split_once("FAIL ").map(|x| x.1).unwrap_or(l).to_string())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Запрашивает права администратора и выполняет системную настройку в указанном режиме.
/// `Err` — пользователь не дал разрешения.
pub fn request_system_setup(mode: &str, network: &str) -> Result<SetupResult, String> {
    let dir = user_dir();
    let _ = std::fs::create_dir_all(&dir);
    let exe = if is_installed() { installed_exe() } else { current_exe() };
    let mut params = format!("--system-setup {mode} --user-dir \"{}\"", dir.display());
    if !network.is_empty() {
        params.push_str(&format!(" --network {network}"));
    }
    let code = win::run_elevated_wait(&exe, &params)
        .ok_or_else(|| "нужно разрешение администратора — настройка не выполнена".to_string())?;
    let text = std::fs::read_to_string(dir.join("setup.log")).unwrap_or_default();
    let text = text.trim_start_matches('\u{feff}');
    // Берём только записи последнего запуска.
    let last_start = text.rfind("--- ").unwrap_or(0);
    let lines: Vec<String> = text[last_start..].lines().skip(1).map(|l| l.to_string()).collect();
    Ok(SetupResult { ok: code == 0, lines })
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

/// Устанавливает программу для текущего пользователя и настраивает систему.
/// `progress` получает короткие сообщения о ходе установки.
/// Возвращает предупреждение, если установка прошла, но системная настройка — не полностью.
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
    let base = std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| dir.clone());
    let mut cfg = Config::load_from(base.join("Raciya").join("config.toml"));
    if let Some(inv) = invite {
        cfg.server = inv.server.clone();
        cfg.zt_network = inv.network.clone();
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
    if autostart {
        set_autostart(true);
    } else if autostart_enabled() {
        // Обновляем путь в существующей записи автозапуска.
        set_autostart(true);
    }

    progress("Настраиваю сеть (Windows спросит разрешение)…");
    let network = cfg.zt_network.clone();
    match request_system_setup("apply", &network) {
        Ok(r) if r.ok => Ok(None),
        Ok(r) => Ok(Some(format!("часть настроек не применилась: {}", r.failures()))),
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

/// Удаление программы: `raciya.exe --uninstall` (вызывается из «Параметры → Приложения»).
pub fn uninstall() {
    if !win::message_box(
        "Удалить «Рацию» с этого компьютера?\n\nБудут убраны программа, ярлыки и сетевые настройки, которые она добавила. ZeroTier останется — его можно удалить отдельно в «Параметры → Приложения».",
        "Рация",
        true,
    ) {
        return;
    }
    signal_quit();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let base = std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| install_dir());
    let cfg = Config::load_from(base.join("Raciya").join("config.toml"));
    let _ = request_system_setup("remove", &cfg.zt_network);
    win::run_powershell(&shortcuts_script(&installed_exe(), false));
    win::reg_delete_value(HKEY_CURRENT_USER, RUN_KEY, "Raciya");
    win::reg_delete_tree(HKEY_CURRENT_USER, UNINSTALL_KEY);
    let _ = std::fs::remove_dir_all(user_dir());
    // Настройки пользователя удаляем, данные сервера (если он был на этом ПК) оставляем.
    let _ = std::fs::remove_file(base.join("Raciya").join("config.toml"));
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
        assert_eq!(i.network, "0123456789abcdef");
        assert_eq!(i.server, "10.77.64.1");
        assert_eq!(make_invite(&i.network, &i.server), "0123456789abcdef@10.77.64.1");
        assert!(parse_invite("0123456789abcdef").is_none());
        assert!(parse_invite("xyz@10.0.0.1").is_none());
        assert!(parse_invite("0123456789abcdef@").is_none());
        assert!(parse_invite("0123456789abcdef@bad host").is_none());
    }
}
