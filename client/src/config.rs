//! Настройки. Хранятся в `raciya.toml` рядом с программой (переносной режим),
//! а если такого файла нет — в `%APPDATA%\Raciya\config.toml`.
//! Пароли в файле зашифрованы средствами Windows (DPAPI) и привязаны к пользователю Windows.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub const DEFAULT_PORT: u16 = crate::server::DEFAULT_PORT;

/// Сервер на этом компьютере.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct HostConfig {
    pub enabled: bool,
    pub port: u16,
    /// Пароль сервера, зашифрованный DPAPI (hex).
    pub password_enc: String,
    pub max_users: u32,
    pub welcome: String,
    pub name: String,
    #[serde(skip)]
    pub password: String,
}

impl Default for HostConfig {
    fn default() -> Self {
        HostConfig {
            enabled: false,
            port: DEFAULT_PORT,
            password_enc: String::new(),
            max_users: crate::server::DEFAULT_MAX_USERS,
            welcome: String::new(),
            name: "Рация".into(),
            password: String::new(),
        }
    }
}

impl HostConfig {
    pub fn settings(&self) -> crate::server::Settings {
        crate::server::Settings {
            port: self.port,
            password: self.password.clone(),
            max_users: self.max_users,
            welcome: self.welcome.clone(),
            name: self.name.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    /// Адрес сервера: `host`, `host:port` (или код приглашения `сеть@адрес[:порт]`).
    pub server: String,
    pub username: String,
    /// Пароль сервера, зашифрованный DPAPI (hex).
    pub password_enc: String,
    pub autoconnect: bool,
    /// Пустая строка — устройство Windows по умолчанию.
    pub input_device: String,
    pub output_device: String,
    /// false — говорить по кнопке, true — по голосу.
    pub voice_activation: bool,
    /// Код клавиши Windows (VK) для «говорить»; 5 = Mouse 4.
    pub ptt_key: u32,
    /// Порог срабатывания «по голосу» (среднеквадратичный уровень, 0..1).
    pub vad_threshold: f32,
    /// Шумоподавление: 0 — выключено, 1 — лёгкое (шумовой порог), 2 — сильное (RNNoise).
    pub noise_mode: u8,
    /// Старое название настройки (до версии 0.2): читается, но больше не записывается.
    #[serde(skip_serializing)]
    pub denoise: bool,
    /// Номер виртуальной сети ZeroTier (из кода приглашения).
    pub zt_network: String,
    /// Версия 0.2: «Рация» запускала Mumble Server. Читается один раз для переноса в `[host]`.
    #[serde(skip_serializing)]
    pub run_server: bool,
    /// Битрейт Opus, бит/с.
    pub bitrate: u32,
    /// Запускать свёрнутым в трей.
    pub start_minimized: bool,
    /// Громкость участников по имени (1.0 = 100%).
    pub volumes: BTreeMap<String, f32>,
    /// Сервер на этом компьютере (нет секции — сервер ни разу не настраивался).
    pub host: Option<HostConfig>,

    #[serde(skip)]
    pub password: String,
    #[serde(skip)]
    pub path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server: String::new(),
            username: String::new(),
            password_enc: String::new(),
            autoconnect: true,
            input_device: String::new(),
            output_device: String::new(),
            voice_activation: false,
            ptt_key: 0x05,
            vad_threshold: 0.02,
            noise_mode: 0,
            denoise: false,
            zt_network: String::new(),
            run_server: false,
            bitrate: 40_000,
            start_minimized: false,
            volumes: BTreeMap::new(),
            host: None,
            password: String::new(),
            path: PathBuf::new(),
        }
    }
}

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn roaming_dir() -> PathBuf {
    std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| exe_dir()).join("Raciya")
}

/// Разбирает адрес сервера: `host`, `host:port`, `[ipv6]:port`, `ipv6`
/// и код приглашения `сеть@адрес[:порт]` (берётся адрес).
pub fn parse_address(text: &str) -> Option<(String, u16)> {
    let s = text.trim();
    let s = s.rsplit_once('@').map(|(_, a)| a).unwrap_or(s).trim();
    if s.is_empty() || s.chars().any(|c| c.is_whitespace()) {
        return None;
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => DEFAULT_PORT,
            None => return None,
        };
        return Some((host.to_string(), port));
    }
    match s.rsplit_once(':') {
        // Несколько двоеточий без скобок — адрес IPv6 без порта.
        Some((h, _)) if h.contains(':') => Some((s.to_string(), DEFAULT_PORT)),
        Some((h, p)) => {
            let port = p.parse::<u16>().ok().filter(|&p| p != 0)?;
            (!h.is_empty()).then(|| (h.to_string(), port))
        }
        None => Some((s.to_string(), DEFAULT_PORT)),
    }
}

impl Config {
    pub fn load() -> Config {
        let portable = exe_dir().join("raciya.toml");
        let path = if portable.exists() { portable } else { roaming_dir().join("config.toml") };
        Self::load_from(path)
    }

    pub fn load_from(path: PathBuf) -> Config {
        let mut cfg: Config = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default();
        cfg.password = crate::win::unprotect(&cfg.password_enc);
        if let Some(h) = cfg.host.as_mut() {
            h.password = crate::win::unprotect(&h.password_enc);
            if h.port == 0 {
                h.port = DEFAULT_PORT;
            }
            h.max_users = h.max_users.clamp(1, 1000);
        }
        cfg.bitrate = cfg.bitrate.clamp(8_000, 96_000);
        cfg.vad_threshold = cfg.vad_threshold.clamp(0.001, 0.5);
        if cfg.denoise && cfg.noise_mode == 0 {
            cfg.noise_mode = 2;
        }
        cfg.noise_mode = cfg.noise_mode.min(2);
        cfg.path = path;
        cfg
    }

    pub fn save(&mut self) {
        self.password_enc = crate::win::protect(&self.password);
        if let Some(h) = self.host.as_mut() {
            h.password_enc = crate::win::protect(&h.password);
        }
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(text) = toml::to_string_pretty(self) {
            let tmp = self.path.with_extension("tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }

    /// Версия 0.2 запускала Mumble Server: переносим его порт, пароль, число мест и приветствие
    /// в настройки встроенного сервера. `true` — перенос выполнен (настройки нужно сохранить).
    pub fn migrate_legacy_server(&mut self) -> bool {
        if self.host.is_some() || !self.run_server {
            return false;
        }
        let mut host = HostConfig { enabled: true, ..Default::default() };
        let ini = crate::server::data_dir().join("mumble-server.ini");
        if let Some(i) = crate::server::migrate::read_mumble_ini(&ini) {
            if let Some(p) = i.port.filter(|&p| p != 0) {
                host.port = p;
            }
            if let Some(pw) = i.password {
                host.password = pw;
            }
            if let Some(n) = i.max_users {
                host.max_users = n.clamp(1, 1000);
            }
            if let Some(w) = i.welcome {
                host.welcome = w;
            }
        }
        self.host = Some(host);
        self.run_server = false;
        true
    }

    /// Адрес сервера: имя и порт.
    pub fn host_port(&self) -> (String, u16) {
        parse_address(&self.server).unwrap_or_else(|| (self.server.trim().to_string(), DEFAULT_PORT))
    }

    pub fn is_complete(&self) -> bool {
        parse_address(&self.server).is_some() && !self.username.trim().is_empty()
    }

    pub fn host(&self) -> HostConfig {
        self.host.clone().unwrap_or_default()
    }

    pub fn hosting(&self) -> bool {
        self.host.as_ref().map(|h| h.enabled).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(parse_address("10.77.64.1"), Some(("10.77.64.1".into(), DEFAULT_PORT)));
        assert_eq!(parse_address(" 10.77.64.1:40738 "), Some(("10.77.64.1".into(), 40738)));
        assert_eq!(parse_address("myhost.example"), Some(("myhost.example".into(), DEFAULT_PORT)));
        assert_eq!(parse_address("[fd00::1]:5000"), Some(("fd00::1".into(), 5000)));
        assert_eq!(parse_address("fd00::1"), Some(("fd00::1".into(), DEFAULT_PORT)));
        assert_eq!(parse_address("0123456789abcdef@10.77.64.1:64739"), Some(("10.77.64.1".into(), 64739)));
        assert_eq!(parse_address(""), None);
        assert_eq!(parse_address("host:abc"), None);
        assert_eq!(parse_address("host:0"), None);
        assert_eq!(parse_address("bad host"), None);
    }

    #[test]
    fn legacy_config_is_read() {
        let text = "server = \"127.0.0.1\"\nusername = \"Kazuma\"\nrun_server = true\ndisable_warp = true\ninvite = \"x@y\"\nnoise_mode = 2\n";
        let mut cfg: Config = toml::from_str(text).unwrap();
        assert!(cfg.run_server && cfg.host.is_none());
        assert_eq!(cfg.noise_mode, 2);
        // Старые поля в файл больше не попадают.
        cfg.host = Some(HostConfig { enabled: true, ..Default::default() });
        let out = toml::to_string_pretty(&cfg).unwrap();
        assert!(!out.contains("run_server") && !out.contains("disable_warp") && !out.contains("invite"));
        assert!(out.contains("[host]"));
        let back: Config = toml::from_str(&out).unwrap();
        assert!(back.hosting());
        assert_eq!(back.host().port, DEFAULT_PORT);
    }
}
