//! Небольшой журнал в файл: одна строка на событие, без сторонних библиотек.
//! Когда файл вырастает до ~512 КБ, он переименовывается в `*.old` и начинается заново.
//!
//! Два журнала: клиентский (`%LOCALAPPDATA%\Raciya\raciya.log`) и серверный
//! (`%APPDATA%\Raciya\server\server.log`). Пока журнал не открыт, записи просто отбрасываются.

use std::fmt::Arguments;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const MAX_SIZE: u64 = 512 * 1024;

pub struct Log {
    path: PathBuf,
    file: Mutex<Option<(File, u64)>>,
}

static CLIENT: OnceLock<Log> = OnceLock::new();
static SERVER: OnceLock<Log> = OnceLock::new();

fn open(path: &Path) -> Option<(File, u64)> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let f = OpenOptions::new().create(true).append(true).open(path).ok()?;
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    Some((f, size))
}

fn timestamp() -> String {
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    let mut t: SYSTEMTIME = unsafe { std::mem::zeroed() };
    unsafe { GetLocalTime(&mut t) };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds
    )
}

impl Log {
    /// Файл создаётся при первой записи, а не заранее.
    fn new(path: PathBuf) -> Log {
        Log { path, file: Mutex::new(None) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write(&self, args: Arguments) {
        let line = format!("{} {}\r\n", timestamp(), args);
        if crate::win::trace_level() > 0 {
            eprint!("{line}");
        }
        let Ok(mut guard) = self.file.lock() else { return };
        if guard.as_ref().map(|(_, size)| *size > MAX_SIZE).unwrap_or(false) {
            *guard = None;
            let _ = std::fs::rename(&self.path, self.path.with_extension("old"));
        }
        if guard.is_none() {
            *guard = open(&self.path);
        }
        if let Some((f, size)) = guard.as_mut() {
            if f.write_all(line.as_bytes()).is_ok() {
                *size += line.len() as u64;
            }
        }
    }
}

pub fn init_client(path: PathBuf) {
    let _ = CLIENT.set(Log::new(path));
}

pub fn init_server(path: PathBuf) {
    let _ = SERVER.set(Log::new(path));
}

pub fn client_path() -> Option<PathBuf> {
    CLIENT.get().map(|l| l.path().to_path_buf())
}

pub fn client(args: Arguments) {
    if let Some(l) = CLIENT.get() {
        l.write(args);
    }
}

pub fn server(args: Arguments) {
    if let Some(l) = SERVER.get() {
        l.write(args);
    }
}

/// Запись в журнал клиента: `clog!("подключение к {addr}")`.
macro_rules! clog {
    ($($t:tt)*) => { $crate::log::client(format_args!($($t)*)) };
}

/// Запись в журнал сервера.
macro_rules! slog {
    ($($t:tt)*) => { $crate::log::server(format_args!($($t)*)) };
}
