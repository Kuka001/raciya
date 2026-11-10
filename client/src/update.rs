//! Обновления через GitHub Releases.
//!
//! Проверка — один небольшой запрос к api.github.com (при запуске и раз в несколько часов).
//! Загрузка и установка — только по нажатию пользователя: файл скачивается рядом с программой,
//! сверяется контрольная сумма, работающий .exe переименовывается и заменяется новым.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Репозиторий, из которого берутся обновления.
pub const REPO: &str = "Kuka001/raciya";
/// Имя файла в выпуске: он же установщик и сама программа.
pub const ASSET_NAME: &str = "Raciya-Setup.exe";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    pub url: String,
    pub size: u64,
    /// SHA-256 файла (hex), если GitHub его сообщил.
    pub sha256: Option<String>,
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(8))
        .timeout_read(Duration::from_secs(20))
        .user_agent("raciya-updater")
        .build()
}

fn parse_version(v: &str) -> Vec<u32> {
    v.trim()
        .trim_start_matches(['v', 'V'])
        .split(['.', '-', '+'])
        .take(3)
        .map(|p| p.parse::<u32>().unwrap_or(0))
        .collect()
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    let mut a = parse_version(candidate);
    let mut b = parse_version(current);
    a.resize(3, 0);
    b.resize(3, 0);
    a > b
}

/// Спрашивает у GitHub последний выпуск. `Ok(None)` — выпусков ещё нет.
pub fn latest() -> Result<Option<Release>, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let resp = match agent().get(&url).set("Accept", "application/vnd.github+json").call() {
        Ok(r) => r,
        Err(ureq::Error::Status(404, _)) => return Ok(None),
        Err(ureq::Error::Status(code, _)) => return Err(format!("GitHub ответил кодом {code}")),
        Err(_) => return Err("нет связи с GitHub".into()),
    };
    let body = resp.into_string().map_err(|_| "непонятный ответ GitHub".to_string())?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|_| "непонятный ответ GitHub".to_string())?;
    let version = v["tag_name"].as_str().unwrap_or_default().trim_start_matches(['v', 'V']).to_string();
    if version.is_empty() {
        return Ok(None);
    }
    let Some(assets) = v["assets"].as_array() else { return Ok(None) };
    for a in assets {
        if a["name"].as_str() == Some(ASSET_NAME) {
            let url = a["browser_download_url"].as_str().unwrap_or_default().to_string();
            if !url.starts_with("https://github.com/") {
                return Err("неожиданный адрес файла обновления".into());
            }
            return Ok(Some(Release {
                version,
                url,
                size: a["size"].as_u64().unwrap_or(0),
                sha256: a["digest"].as_str().and_then(|d| d.strip_prefix("sha256:")).map(|s| s.to_lowercase()),
            }));
        }
    }
    Ok(None)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Скачивает выпуск в `dest`, проверяя размер и контрольную сумму.
/// `progress` получает долю от 0 до 1.
pub fn download(rel: &Release, dest: &Path, progress: &dyn Fn(f32)) -> Result<(), String> {
    let resp = agent().get(&rel.url).call().map_err(|_| "не удалось скачать обновление".to_string())?;
    let mut reader = resp.into_reader();
    let mut file = std::fs::File::create(dest).map_err(|e| format!("не удалось создать файл: {e}"))?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).map_err(|_| "загрузка прервалась".to_string())?;
        if n == 0 {
            break;
        }
        std::io::Write::write_all(&mut file, &buf[..n]).map_err(|e| format!("ошибка записи: {e}"))?;
        ctx.update(&buf[..n]);
        total += n as u64;
        if total > 200 * 1024 * 1024 {
            return Err("файл обновления слишком большой".into());
        }
        if rel.size > 0 {
            progress((total as f32 / rel.size as f32).min(1.0));
        }
    }
    drop(file);
    if rel.size > 0 && total != rel.size {
        let _ = std::fs::remove_file(dest);
        return Err("размер скачанного файла не совпал".into());
    }
    if let Some(expected) = &rel.sha256 {
        if &hex(ctx.finish().as_ref()) != expected {
            let _ = std::fs::remove_file(dest);
            return Err("контрольная сумма не совпала — файл повреждён".into());
        }
    }
    // Минимальная проверка, что это программа Windows.
    let mut head = [0u8; 2];
    let ok = std::fs::File::open(dest).and_then(|mut f| f.read_exact(&mut head)).is_ok() && &head == b"MZ";
    if !ok {
        let _ = std::fs::remove_file(dest);
        return Err("скачанный файл не является программой".into());
    }
    Ok(())
}

/// Заменяет работающий .exe скачанным файлом. Windows разрешает переименовать запущенную программу,
/// поэтому старая версия уходит в `*.old`, а новая встаёт на её место.
pub fn swap_exe(current: &Path, new_file: &Path) -> Result<(), String> {
    let old = current.with_extension("old");
    let _ = std::fs::remove_file(&old);
    std::fs::rename(current, &old).map_err(|e| format!("не удалось заменить программу: {e}"))?;
    if let Err(e) = std::fs::rename(new_file, current) {
        // Возвращаем как было.
        let _ = std::fs::rename(&old, current);
        return Err(format!("не удалось заменить программу: {e}"));
    }
    Ok(())
}

/// Удаляет остатки прошлого обновления (вызывается при запуске).
pub fn cleanup(current: &Path) {
    let _ = std::fs::remove_file(current.with_extension("old"));
    let _ = std::fs::remove_file(current.with_extension("new"));
}

pub fn new_file_path(current: &Path) -> PathBuf {
    current.with_extension("new")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare() {
        assert!(is_newer("v0.2.1", "0.2.0"));
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("1.0", "0.9.9"));
        assert!(!is_newer("0.2.0", "0.2.0"));
        assert!(!is_newer("v0.1.9", "0.2.0"));
        assert!(!is_newer("мусор", "0.2.0"));
    }
}
