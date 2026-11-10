//! Настройки клиента. Хранятся в `raciya.toml` рядом с программой (portable-режим),
//! а если такого файла нет — в `%APPDATA%\Raciya\config.toml`.
//! Пароль сервера в файле зашифрован средствами Windows (DPAPI) и привязан к пользователю Windows.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub const DEFAULT_PORT: u16 = 64738;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    /// Адрес сервера: `host` или `host:port`.
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
    /// На этом компьютере «Рация» запускает сервер Mumble как свой подпроцесс.
    pub run_server: bool,
    /// Код приглашения для друзей (только у владельца сервера): `номер_сети@адрес_сервера`.
    pub invite: String,
    /// Битрейт Opus, бит/с.
    pub bitrate: u32,
    /// Отключать Cloudflare WARP при запуске.
    pub disable_warp: bool,
    /// Запускать свёрнутым в трей.
    pub start_minimized: bool,
    /// Громкость участников по имени (1.0 = 100%).
    pub volumes: BTreeMap<String, f32>,

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
            invite: String::new(),
            bitrate: 40_000,
            disable_warp: true,
            start_minimized: false,
            volumes: BTreeMap::new(),
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

impl Config {
    pub fn load() -> Config {
        let portable = exe_dir().join("raciya.toml");
        let path = if portable.exists() {
            portable
        } else {
            let base = std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| exe_dir());
            base.join("Raciya").join("config.toml")
        };
        Self::load_from(path)
    }

    pub fn load_from(path: PathBuf) -> Config {
        let mut cfg: Config = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default();
        cfg.password = crate::win::unprotect(&cfg.password_enc);
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

    /// Разбирает адрес сервера на имя и порт.
    pub fn host_port(&self) -> (String, u16) {
        let s = self.server.trim();
        if let Some((h, p)) = s.rsplit_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                if !h.is_empty() && !h.contains(':') {
                    return (h.to_string(), port);
                }
            }
        }
        (s.to_string(), DEFAULT_PORT)
    }

    pub fn is_complete(&self) -> bool {
        !self.server.trim().is_empty() && !self.username.trim().is_empty()
    }
}
