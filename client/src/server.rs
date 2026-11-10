//! Сервер Mumble как скрытый подпроцесс «Рации» (только на компьютере, где он установлен).
//!
//! Сервер запускается на отдельном невидимом рабочем столе Windows, поэтому у него нет ни окна,
//! ни значка в трее. Запускается он из копии файла с именем `raciya.exe`, поэтому в Диспетчере
//! задач входит в группу «Рация». Приоритет — «Ниже среднего».
//! Объект задания Windows гарантирует, что сервер завершится вместе с программой, даже при сбое.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::StationsAndDesktops::CreateDesktopW;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, ResumeThread, TerminateProcess, WaitForSingleObject, BELOW_NORMAL_PRIORITY_CLASS,
    CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
};

const DESKTOP_NAME: &str = "RaciyaServer";

pub struct ServerHost {
    stop: AtomicBool,
    running: AtomicBool,
    pid: AtomicU32,
    process: std::sync::Mutex<usize>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Файл, из которого сервер запускается на самом деле: копия `mumble-server.exe` с именем
/// `raciya.exe`. Диспетчер задач объединяет дочерний процесс с «Рацией» в одну группу только
/// тогда, когда имена исполняемых файлов совпадают (проверено на Windows 11).
/// Копия обновляется сама, если установленный сервер изменился.
fn runnable_exe() -> PathBuf {
    let src = default_exe();
    let dst = crate::system::user_dir().join("server").join("raciya.exe");
    let stamp = |p: &Path| std::fs::metadata(p).ok().map(|m| (m.len(), m.modified().ok()));
    let fresh = match (stamp(&src), stamp(&dst)) {
        (Some((sl, sm)), Some((dl, dm))) => sl == dl && dm >= sm,
        _ => false,
    };
    if !fresh {
        if let Some(dir) = dst.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if std::fs::copy(&src, &dst).is_err() && !dst.exists() {
            // Не удалось скопировать — запускаем оригинал (просто без объединения в Диспетчере задач).
            return src;
        }
    }
    dst
}

pub fn default_exe() -> PathBuf {
    let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
    Path::new(&pf).join("Mumble").join("server").join("mumble-server.exe")
}

/// Папка с настройками и базой сервера: `%APPDATA%\Raciya\server`.
pub fn data_dir() -> PathBuf {
    let base = std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."));
    base.join("Raciya").join("server")
}

pub fn ini_path() -> PathBuf {
    data_dir().join("mumble-server.ini")
}

/// Есть ли на этом компьютере всё для запуска сервера.
pub fn available() -> bool {
    default_exe().exists() && ini_path().exists()
}

impl ServerHost {
    pub fn start() -> Arc<ServerHost> {
        let host = Arc::new(ServerHost {
            stop: AtomicBool::new(false),
            running: AtomicBool::new(false),
            pid: AtomicU32::new(0),
            process: std::sync::Mutex::new(0),
        });
        let h = host.clone();
        let _ = std::thread::Builder::new().name("server-host".into()).spawn(move || {
            crate::win::set_thread_priority(crate::win::Prio::Low);
            h.supervise();
        });
        host
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn pid(&self) -> u32 {
        self.pid.load(Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let h = *self.process.lock().unwrap();
        if h != 0 {
            unsafe {
                TerminateProcess(h as HANDLE, 0);
            }
        }
    }

    fn supervise(&self) {
        let exe = runnable_exe();
        let ini = ini_path();
        let dir = data_dir();
        // Задание: при закрытии его последнего дескриптора (то есть при любом завершении «Рации»)
        // Windows сама завершает сервер.
        let job = unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if !job.is_null() {
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as _,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
            }
            job
        };
        let desktop = wide(DESKTOP_NAME);
        unsafe {
            // GENERIC_ALL: рабочий стол создаётся один раз и живёт, пока жива программа.
            CreateDesktopW(desktop.as_ptr(), std::ptr::null(), std::ptr::null(), 0, 0x1000_0000, std::ptr::null());
        }

        let mut quick_failures = 0u32;
        while !self.stop.load(Ordering::SeqCst) {
            let started = std::time::Instant::now();
            let mut cmd = wide(&format!("\"{}\" -ini \"{}\"", exe.display(), ini.display()));
            let cwd = wide(&dir.to_string_lossy());
            let mut desk = desktop.clone();
            let process = unsafe {
                let mut si: STARTUPINFOW = std::mem::zeroed();
                si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
                si.lpDesktop = desk.as_mut_ptr();
                let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
                let ok = CreateProcessW(
                    std::ptr::null(),
                    cmd.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    BELOW_NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED,
                    std::ptr::null(),
                    cwd.as_ptr(),
                    &si,
                    &mut pi,
                );
                if ok == 0 {
                    None
                } else {
                    if !job.is_null() {
                        AssignProcessToJobObject(job, pi.hProcess);
                    }
                    ResumeThread(pi.hThread);
                    CloseHandle(pi.hThread);
                    self.pid.store(pi.dwProcessId, Ordering::Relaxed);
                    Some(pi.hProcess)
                }
            };

            if let Some(h) = process {
                *self.process.lock().unwrap() = h as usize;
                self.running.store(true, Ordering::Relaxed);
                unsafe {
                    WaitForSingleObject(h, u32::MAX);
                }
                self.running.store(false, Ordering::Relaxed);
                self.pid.store(0, Ordering::Relaxed);
                *self.process.lock().unwrap() = 0;
                unsafe {
                    CloseHandle(h);
                }
            }
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            // Сервер завершился сам (сбой или занят порт): перезапускаем, но не чаще разумного.
            if started.elapsed().as_secs() < 10 {
                quick_failures += 1;
            } else {
                quick_failures = 0;
            }
            let wait = if quick_failures > 3 { 30 } else { 3 };
            for _ in 0..wait * 4 {
                if self.stop.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
        if !job.is_null() {
            unsafe {
                CloseHandle(job);
            }
        }
    }
}
