//! Окно, трей и связь интерфейса с ядром. Здесь же — экран установки.

use crate::audio;
use crate::config::Config;
use crate::core::{Core, Event, Status};
use crate::diag::{self, Fix, Severity};
use crate::{system, update, win};
use slint::{ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

slint::include_modules!();

static CORE: OnceLock<Arc<Core>> = OnceLock::new();
static DIAG_TX: OnceLock<Mutex<Sender<()>>> = OnceLock::new();
static VISIBLE: AtomicBool = AtomicBool::new(false);

fn core() -> &'static Arc<Core> {
    CORE.get().expect("core")
}

const DEFAULT_DEVICE: &str = "По умолчанию";

struct Ui {
    win: AppWindow,
    users: Rc<VecModel<UserItem>>,
    issues: Rc<VecModel<IssueItem>>,
    fixes: Vec<Fix>,
    in_names: Vec<String>,
    out_names: Vec<String>,
    notice_timer: Timer,
    level_timer: Timer,
    visible: bool,
    tray: Option<TrayIcon>,
    tray_muted: bool,
    release: Option<update::Release>,
}

thread_local! {
    static UI: RefCell<Option<Ui>> = const { RefCell::new(None) };
}

fn with_ui(f: impl FnOnce(&mut Ui)) {
    UI.with(|u| {
        if let Ok(mut guard) = u.try_borrow_mut() {
            if let Some(ui) = guard.as_mut() {
                f(ui);
            }
        }
    });
}

/// Выполняет действие в потоке интерфейса (можно вызывать из любого потока).
fn post(f: impl FnOnce(&mut Ui) + Send + 'static) {
    let _ = slint::invoke_from_event_loop(move || with_ui(f));
}

// Порог «по голосу»: ползунок 0..1 <-> среднеквадратичный уровень 0..0.25 (квадратичная шкала).
fn slider_to_rms(v: f32) -> f32 {
    (v * v * 0.25).clamp(0.001, 0.25)
}

fn rms_to_slider(rms: f32) -> f32 {
    (rms / 0.25).clamp(0.0, 1.0).sqrt()
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn version_line(release: Option<&update::Release>) -> String {
    match release {
        Some(r) => format!("Новое обновление! Версия: {} (Текущая: {})", r.version, update::CURRENT),
        None => format!("Версия: {}", update::CURRENT),
    }
}

impl Ui {
    fn apply_status(&mut self, s: &Status) {
        let (kind, text, detail) = match s {
            Status::Offline => (0, "Нет связи", String::new()),
            Status::Connecting => (1, "Подключение…", String::new()),
            Status::Online => (2, "На связи", String::new()),
            Status::Reconnecting(r) => (1, "Переподключение…", capitalize(r)),
            Status::Failed(r) => (3, "Ошибка", capitalize(r)),
        };
        self.win.set_status_kind(kind);
        self.win.set_status_text(text.into());
        self.win.set_status_detail(detail.into());
        self.win.set_wants_connection(core().wants_connection());
        if kind != 2 {
            self.win.set_ping_text(SharedString::new());
        }
        self.update_tray();
    }

    fn sync_users(&mut self) {
        let items: Vec<UserItem> = core()
            .users()
            .into_iter()
            .map(|u| UserItem {
                session: u.session as i32,
                initial: u.name.chars().next().map(|c| c.to_uppercase().collect::<String>()).unwrap_or_default().into(),
                name: u.name.into(),
                muted: u.muted,
                deafened: u.deafened,
                speaking: u.speaking,
                volume: u.volume,
                is_self: u.is_self,
            })
            .collect();
        if self.users.row_count() == items.len() {
            // Обновляем только изменившиеся строки, чтобы не сбивать перетаскивание ползунка.
            for (i, item) in items.into_iter().enumerate() {
                if self.users.row_data(i).as_ref() != Some(&item) {
                    self.users.set_row_data(i, item);
                }
            }
        } else {
            self.users.set_vec(items);
        }
    }

    fn show_notice(&mut self, text: String) {
        self.win.set_notice(capitalize(&text).into());
        self.notice_timer.start(TimerMode::SingleShot, Duration::from_secs(8), || {
            with_ui(|ui| ui.win.set_notice(SharedString::new()));
        });
    }

    /// Индикатор уровня микрофона обновляется, только когда он виден.
    fn update_level_timer(&mut self) {
        let need = self.visible && self.win.get_page() == 0 && self.win.get_vad_mode();
        if need && !self.level_timer.running() {
            self.level_timer.start(TimerMode::Repeated, Duration::from_millis(70), || {
                with_ui(|ui| ui.win.set_mic_level(rms_to_slider(core().mic_level())));
            });
        } else if !need && self.level_timer.running() {
            self.level_timer.stop();
        }
    }

    fn set_devices(&mut self, ins: Vec<String>, outs: Vec<String>) {
        let (cur_in, cur_out) = {
            let cfg = core().cfg.lock().unwrap();
            (cfg.input_device.clone(), cfg.output_device.clone())
        };
        let to_model = |names: &[String]| -> ModelRc<SharedString> {
            let mut v: Vec<SharedString> = vec![DEFAULT_DEVICE.into()];
            v.extend(names.iter().map(|n| SharedString::from(n.as_str())));
            ModelRc::new(VecModel::from(v))
        };
        let index = |names: &[String], cur: &str| -> i32 {
            names.iter().position(|n| n == cur).map(|i| i as i32 + 1).unwrap_or(0)
        };
        self.win.set_in_devices(to_model(&ins));
        self.win.set_out_devices(to_model(&outs));
        self.win.set_in_index(index(&ins, &cur_in));
        self.win.set_out_index(index(&outs, &cur_out));
        self.in_names = ins;
        self.out_names = outs;
    }

    fn show(&mut self) {
        let _ = self.win.show();
        self.win.window().set_minimized(false);
        self.visible = true;
        VISIBLE.store(true, Ordering::Relaxed);
        // Окно Windows создаётся чуть позже вызова show(), поэтому оформление применяем с задержкой.
        Timer::single_shot(Duration::from_millis(40), || with_ui(|ui| style_window(&ui.win)));
        self.update_level_timer();
    }

    fn hide(&mut self) {
        let _ = self.win.hide();
        self.visible = false;
        VISIBLE.store(false, Ordering::Relaxed);
        self.update_level_timer();
    }

    fn update_tray(&mut self) {
        let muted = core().is_muted() || core().is_deafened();
        if let Some(tray) = self.tray.as_ref() {
            if muted != self.tray_muted {
                let _ = tray.set_icon(Some(tray_icon_image(muted)));
            }
            let state = match core().status() {
                Status::Online => "на связи",
                Status::Connecting | Status::Reconnecting(_) => "подключение…",
                _ => "нет связи",
            };
            let _ = tray.set_tooltip(Some(format!("Рация — {state}{}", if muted { ", микрофон выключен" } else { "" })));
        }
        self.tray_muted = muted;
    }

    fn toggle_mute(&mut self) {
        let c = core();
        if c.is_deafened() {
            // Включение микрофона возвращает и звук.
            c.set_deafened(false);
            c.set_muted(false);
        } else {
            c.set_muted(!c.is_muted());
        }
        self.win.set_muted(c.is_muted());
        self.win.set_deafened(c.is_deafened());
        self.update_tray();
    }

    fn toggle_deafen(&mut self) {
        let c = core();
        c.set_deafened(!c.is_deafened());
        self.win.set_deafened(c.is_deafened());
        self.update_tray();
    }

    fn apply_report(&mut self, rep: diag::Report) {
        self.fixes = rep.issues.iter().map(|i| i.fix).collect();
        let items: Vec<IssueItem> = rep
            .issues
            .iter()
            .map(|i| IssueItem {
                title: i.title.as_str().into(),
                advice: i.advice.as_str().into(),
                severity: if i.severity == Severity::Problem { 2 } else { 1 },
                fix: if i.fix == Fix::None { 0 } else { 1 },
            })
            .collect();
        self.issues.set_vec(items);
        self.win.set_diag_facts(rep.facts.join("  ·  ").into());
        self.win.set_diag_running(false);
        self.win.set_diag_done(true);
        self.refresh_system_state();
    }

    fn refresh_system_state(&mut self) {
        self.win.set_tweaks_applied(system::tweaks_applied());
        self.win.set_game_mode(system::game_mode());
        self.win.set_autostart(system::autostart_enabled());
    }
}

fn refresh_devices() {
    // Перечисление устройств занимает десятки миллисекунд — делаем его вне потока интерфейса.
    std::thread::spawn(|| {
        let (ins, outs) = audio::list_devices();
        post(move |ui| ui.set_devices(ins, outs));
    });
}

fn request_diag() {
    if let Some(tx) = DIAG_TX.get() {
        let _ = tx.lock().unwrap().send(());
    }
}

/// Фоновая проверка сети: вскоре после запуска, затем изредка и по запросу.
fn spawn_diag() {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let _ = DIAG_TX.set(Mutex::new(tx));
    let _ = std::thread::Builder::new().name("diag".into()).spawn(move || {
        win::set_thread_priority(win::Prio::Low);
        std::thread::sleep(Duration::from_secs(5));
        loop {
            post(|ui| ui.win.set_diag_running(true));
            let ctx = core().diag_context();
            let rep = diag::run(&ctx);
            post(move |ui| ui.apply_report(rep));
            // Пока окно свёрнуто (идёт игра), проверяем реже.
            let pause = if VISIBLE.load(Ordering::Relaxed) { 180 } else { 600 };
            match rx.recv_timeout(Duration::from_secs(pause)) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => return,
            }
            while rx.try_recv().is_ok() {}
        }
    });
}

/// Проверка обновлений: один запрос при запуске и затем раз в 6 часов. Скачивание — только по нажатию.
fn spawn_update_checker() {
    let _ = std::thread::Builder::new().name("update-check".into()).spawn(|| {
        win::set_thread_priority(win::Prio::Low);
        std::thread::sleep(Duration::from_secs(4));
        loop {
            if let Ok(Some(rel)) = update::latest() {
                if update::is_newer(&rel.version, update::CURRENT) {
                    post(move |ui| {
                        ui.win.set_version_text(version_line(Some(&rel)).into());
                        ui.win.set_update_available(true);
                        ui.release = Some(rel);
                    });
                }
            }
            std::thread::sleep(Duration::from_secs(6 * 3600));
        }
    });
}

/// Нажатие на строку версии: если обновление уже найдено — ставим его, иначе проверяем сейчас.
fn version_clicked() {
    let mut known = false;
    with_ui(|ui| known = ui.release.is_some());
    if known {
        start_update();
        return;
    }
    with_ui(|ui| {
        ui.win.set_update_busy(true);
        ui.win.set_version_text("Проверяю обновления…".into());
    });
    std::thread::spawn(|| {
        let result = update::latest();
        post(move |ui| {
            ui.win.set_update_busy(false);
            match result {
                Ok(Some(rel)) if update::is_newer(&rel.version, update::CURRENT) => {
                    ui.win.set_version_text(version_line(Some(&rel)).into());
                    ui.win.set_update_available(true);
                    ui.release = Some(rel);
                }
                Ok(_) => {
                    ui.win.set_version_text(format!("Версия: {} — новых версий нет", update::CURRENT).into());
                }
                Err(e) => {
                    ui.win.set_version_text(version_line(None).into());
                    ui.show_notice(format!("не удалось проверить обновления: {e}"));
                }
            }
        });
    });
}

fn start_update() {
    let mut rel = None;
    with_ui(|ui| {
        if ui.win.get_update_busy() {
            return;
        }
        rel = ui.release.clone();
        if rel.is_some() {
            ui.win.set_update_busy(true);
            ui.win.set_version_text("Загрузка обновления… 0 %".into());
        }
    });
    let Some(rel) = rel else { return };
    std::thread::spawn(move || {
        let exe = system::current_exe();
        let tmp = update::new_file_path(&exe);
        let last = AtomicU32::new(0);
        let result = update::download(&rel, &tmp, &|f| {
            let pct = (f * 100.0) as u32;
            if last.swap(pct, Ordering::Relaxed) != pct {
                post(move |ui| ui.win.set_version_text(format!("Загрузка обновления… {pct} %").into()));
            }
        })
        .and_then(|_| update::swap_exe(&exe, &tmp));
        match result {
            Ok(()) => {
                // Новая версия запускается и ждёт, пока эта копия завершится.
                let _ = std::process::Command::new(&exe).arg("--after-update").spawn();
                let _ = slint::invoke_from_event_loop(quit_app);
            }
            Err(e) => post(move |ui| {
                ui.win.set_update_busy(false);
                ui.win.set_version_text(version_line(ui.release.as_ref()).into());
                ui.show_notice(format!("обновление не удалось: {e}"));
            }),
        }
    });
}

/// Системная настройка с правами администратора (режимы — см. scripts/system-setup.ps1).
fn run_system_setup(mode: &'static str) {
    with_ui(|ui| ui.win.set_system_busy(true));
    std::thread::spawn(move || {
        let network = core().cfg.lock().unwrap().zt_network.clone();
        let result = system::request_system_setup(mode, &network);
        post(move |ui| {
            ui.win.set_system_busy(false);
            ui.refresh_system_state();
            match result {
                Ok(r) if r.ok => ui.show_notice(
                    match mode {
                        "gamemode-on" => "фоновые загрузки ограничены",
                        "gamemode-off" => "ограничение загрузок снято",
                        _ => "сетевые настройки применены",
                    }
                    .into(),
                ),
                Ok(r) => ui.show_notice(format!("не всё получилось: {}", r.failures())),
                Err(e) => ui.show_notice(e),
            }
        });
        request_diag();
    });
}

fn on_core_event(ev: Event) {
    post(move |ui| match ev {
        Event::Status(s) => {
            let online = s == Status::Online;
            ui.apply_status(&s);
            ui.sync_users();
            if online {
                // Через несколько секунд после входа известно, работает ли быстрый канал.
                std::thread::spawn(|| {
                    std::thread::sleep(Duration::from_secs(15));
                    request_diag();
                });
            }
        }
        Event::Users | Event::Speaking { .. } => ui.sync_users(),
        Event::Ping { ms, udp } => {
            let t = if ms < 1.0 { "<1 мс".to_string() } else { format!("{ms:.0} мс") };
            ui.win.set_ping_text(if udp { t } else { format!("{t} · TCP") }.into());
        }
        Event::Notice(n) => ui.show_notice(n),
        Event::KeyCaptured(k) => {
            ui.win.set_capturing_key(false);
            if k.is_some() {
                ui.win.set_key_name(win::key_name(core().ptt_key()).into());
            }
        }
        Event::Devices { .. } => refresh_devices(),
    });
}

/// Значок для трея: тёмный скруглённый квадрат с полосками — виден и на светлой, и на тёмной
/// панели задач. Жёлтые полоски — микрофон выключен.
fn tray_icon_image(muted: bool) -> Icon {
    const S: usize = 32;
    const SS: usize = 4;
    let bg: [u8; 3] = [28, 30, 34];
    let fg: [u8; 3] = if muted { [226, 160, 63] } else { [236, 237, 238] };
    let accent: [u8; 3] = if muted { [226, 160, 63] } else { [76, 195, 138] };
    let bars = [(0.27f32, 0.11f32), (0.42, 0.24), (0.58, 0.33), (0.73, 0.17)];
    let half_w = 0.05f32;
    let rounded = |u: f32, v: f32, x0: f32, y0: f32, x1: f32, y1: f32, r: f32| -> bool {
        if u < x0 || u > x1 || v < y0 || v > y1 {
            return false;
        }
        let cx = u.clamp(x0 + r, x1 - r);
        let cy = v.clamp(y0 + r, y1 - r);
        (u - cx).powi(2) + (v - cy).powi(2) <= r * r
    };
    let mut px = vec![0u8; S * S * 4];
    for y in 0..S {
        for x in 0..S {
            let (mut r, mut g, mut b, mut a) = (0u32, 0u32, 0u32, 0u32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let u = (x as f32 + (sx as f32 + 0.5) / SS as f32) / S as f32;
                    let v = (y as f32 + (sy as f32 + 0.5) / SS as f32) / S as f32;
                    if !rounded(u, v, 0.0, 0.0, 1.0, 1.0, 0.22) {
                        continue;
                    }
                    let mut c = bg;
                    for (i, (cx, hh)) in bars.iter().enumerate() {
                        if rounded(u, v, cx - half_w, 0.5 - hh, cx + half_w, 0.5 + hh, half_w) {
                            c = if i == 2 { accent } else { fg };
                        }
                    }
                    r += c[0] as u32;
                    g += c[1] as u32;
                    b += c[2] as u32;
                    a += 1;
                }
            }
            let i = (y * S + x) * 4;
            if a > 0 {
                px[i] = (r / a) as u8;
                px[i + 1] = (g / a) as u8;
                px[i + 2] = (b / a) as u8;
                px[i + 3] = (255 * a / (SS * SS) as u32) as u8;
            }
        }
    }
    Icon::from_rgba(px, S as u32, S as u32).expect("tray icon")
}

/// Тёмный заголовок окна в цвет фона и значок окна (Windows 11).
fn style_window(win: &AppWindow) {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{LoadImageW, SendMessageW, IMAGE_ICON, LR_DEFAULTSIZE, WM_SETICON};

    let handle = win.window().window_handle();
    let Ok(h) = handle.window_handle() else { return };
    let RawWindowHandle::Win32(w) = h.as_raw() else { return };
    let hwnd = w.hwnd.get() as *mut std::ffi::c_void;
    unsafe {
        let dark: u32 = 1;
        DwmSetWindowAttribute(hwnd, 20, &dark as *const u32 as _, 4);
        // COLORREF = 0x00BBGGRR; фон окна #0F1012.
        let caption: u32 = 0x0012_100F;
        DwmSetWindowAttribute(hwnd, 35, &caption as *const u32 as _, 4);
        let border: u32 = 0x0028_2422;
        DwmSetWindowAttribute(hwnd, 34, &border as *const u32 as _, 4);
        let text: u32 = 0x00AF_A7A3;
        DwmSetWindowAttribute(hwnd, 36, &text as *const u32 as _, 4);

        let module = GetModuleHandleW(std::ptr::null());
        // Значок встроен в .exe под номером 1.
        let big = LoadImageW(module, 1 as _, IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
        let small = LoadImageW(module, 1 as _, IMAGE_ICON, 16, 16, 0);
        if !big.is_null() {
            SendMessageW(hwnd, WM_SETICON, 1, big as isize);
        }
        if !small.is_null() {
            SendMessageW(hwnd, WM_SETICON, 0, small as isize);
        }
    }
}

fn wide0(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Одна копия программы: вторая будит первую и завершается.
/// `wait` — запуск сразу после обновления: ждём, пока прежняя копия завершится.
fn single_instance(wait: bool) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
    use windows_sys::Win32::System::Threading::{
        CreateEventW, CreateMutexW, OpenEventW, SetEvent, WaitForSingleObject, INFINITE,
    };
    let mutex_name = wide0("RaciyaVoiceChat.Instance");
    let show_name = wide0("RaciyaVoiceChat.Show");
    let quit_name = wide0(system::QUIT_EVENT);
    unsafe {
        let mut attempts = if wait { 60 } else { 1 };
        loop {
            let mutex = CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr());
            if GetLastError() != 183 {
                break;
            }
            CloseHandle(mutex);
            attempts -= 1;
            if attempts == 0 {
                let ev = OpenEventW(0x0002, 0, show_name.as_ptr());
                if !ev.is_null() {
                    SetEvent(ev);
                }
                return false;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let show = CreateEventW(std::ptr::null(), 0, 0, show_name.as_ptr()) as usize;
        if show != 0 {
            std::thread::spawn(move || loop {
                if WaitForSingleObject(show as _, INFINITE) != 0 {
                    break;
                }
                post(|ui| ui.show());
            });
        }
        // Установщик и удаление просят работающую программу закрыться через это событие.
        let quit = CreateEventW(std::ptr::null(), 0, 0, quit_name.as_ptr()) as usize;
        if quit != 0 {
            std::thread::spawn(move || {
                if WaitForSingleObject(quit as _, INFINITE) == 0 {
                    let _ = slint::invoke_from_event_loop(quit_app);
                }
            });
        }
    }
    true
}

fn build_tray() -> Option<(TrayIcon, MenuItem, MenuItem, MenuItem, MenuItem)> {
    let menu = Menu::new();
    let open = MenuItem::new("Открыть Рацию", true, None);
    let mic = MenuItem::new("Микрофон: вкл / выкл", true, None);
    let sound = MenuItem::new("Звук: вкл / выкл", true, None);
    let quit = MenuItem::new("Выход", true, None);
    menu.append(&open).ok()?;
    menu.append(&PredefinedMenuItem::separator()).ok()?;
    menu.append(&mic).ok()?;
    menu.append(&sound).ok()?;
    menu.append(&PredefinedMenuItem::separator()).ok()?;
    menu.append(&quit).ok()?;
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_tooltip("Рация")
        .with_icon(tray_icon_image(false))
        .build()
        .ok()?;
    Some((tray, open, mic, sound, quit))
}

fn quit_app() {
    core().shutdown();
    with_ui(|ui| {
        ui.tray = None;
    });
    let _ = slint::quit_event_loop();
}

/// Экран установки: программа запущена не из папки установки (например, из «Загрузок»).
fn run_installer(install_now: bool) {
    let window = AppWindow::new().expect("window");
    window.set_page(3);
    window.set_app_version(update::CURRENT.into());
    window.set_install_upgrade(system::is_installed());

    // Приглашение: из файла invite.txt рядом с установщиком или из прежних настроек.
    let base = std::env::var("APPDATA").map(std::path::PathBuf::from).unwrap_or_default();
    let old = Config::load_from(base.join("Raciya").join("config.toml"));
    let known = if !old.zt_network.is_empty() && !old.run_server {
        Some(system::make_invite(&old.zt_network, &old.host_port().0))
    } else {
        None
    };
    if let Some(inv) = system::invite_from_file().or(known) {
        window.set_install_invite(inv.into());
    }
    window.set_install_autostart(!system::is_installed() || system::autostart_enabled());

    let weak = window.as_weak();
    window.on_install_clicked(move || {
        let Some(w) = weak.upgrade() else { return };
        let text = w.get_install_invite().to_string();
        let invite = if text.trim().is_empty() {
            None
        } else {
            match system::parse_invite(&text) {
                Some(i) => Some(i),
                None => {
                    w.set_install_status(
                        "Код приглашения выглядит неверно. Он должен иметь вид номер_сети@адрес_сервера — скопируйте его целиком."
                            .into(),
                    );
                    return;
                }
            }
        };
        let autostart = w.get_install_autostart();
        w.set_install_busy(true);
        w.set_install_status("Начинаю установку…".into());
        let weak = weak.clone();
        std::thread::spawn(move || {
            let wk = weak.clone();
            let result = system::install(invite.as_ref(), autostart, &move |msg: &str| {
                let m = msg.to_string();
                let _ = wk.upgrade_in_event_loop(move |w| w.set_install_status(m.into()));
            });
            match result {
                Ok(warning) => {
                    if let Some(wtext) = warning {
                        win::message_box(
                            &format!(
                                "«Рация» установлена, но {wtext}.\n\nПрограмма работает и без этого. Повторить настройку можно в ней самой: «Подключение и настройки» → «Сетевые настройки Windows»."
                            ),
                            "Рация",
                            false,
                        );
                    }
                    system::launch_installed(&[]);
                    let _ = slint::invoke_from_event_loop(|| {
                        let _ = slint::quit_event_loop();
                    });
                }
                Err(e) => {
                    let _ = weak.upgrade_in_event_loop(move |w| {
                        w.set_install_busy(false);
                        w.set_install_status(capitalize(&e).into());
                    });
                }
            }
        });
    });

    let _ = window.show();
    let weak = window.as_weak();
    Timer::single_shot(Duration::from_millis(40), move || {
        if let Some(w) = weak.upgrade() {
            style_window(&w);
        }
    });
    // `Raciya-Setup.exe --install-now` — установка без нажатия кнопки (приглашение берётся
    // из invite.txt рядом с файлом или из прежних настроек).
    if install_now {
        let weak = window.as_weak();
        Timer::single_shot(Duration::from_millis(600), move || {
            if let Some(w) = weak.upgrade() {
                w.invoke_install_clicked();
            }
        });
    }
    let _ = slint::run_event_loop();
}

pub fn run(args: &[String]) {
    let has = |name: &str| args.iter().any(|a| a == name);
    if !system::is_installed_location() && !system::is_portable() && !has("--no-install") {
        run_installer(has("--install-now"));
        return;
    }
    let exe = system::current_exe();
    if !single_instance(has("--after-update")) {
        return;
    }
    update::cleanup(&exe);
    win::set_thread_priority(win::Prio::Low);

    let cfg = Config::load();
    let complete = cfg.is_complete();
    let autoconnect = cfg.autoconnect && complete;
    let start_hidden = (cfg.start_minimized || has("--autostart")) && complete;
    if cfg.disable_warp {
        win::disconnect_warp();
    }

    let window = AppWindow::new().expect("window");
    let users = Rc::new(VecModel::<UserItem>::default());
    let issues = Rc::new(VecModel::<IssueItem>::default());
    window.set_users(ModelRc::from(users.clone()));
    window.set_issues(ModelRc::from(issues.clone()));
    window.set_server(cfg.server.clone().into());
    window.set_username(cfg.username.clone().into());
    window.set_password(cfg.password.clone().into());
    window.set_autoconnect(cfg.autoconnect);
    window.set_noise_mode(cfg.noise_mode as i32);
    window.set_start_minimized(cfg.start_minimized);
    window.set_disable_warp(cfg.disable_warp);
    window.set_vad_mode(cfg.voice_activation);
    window.set_vad_threshold(rms_to_slider(cfg.vad_threshold));
    window.set_key_name(win::key_name(cfg.ptt_key).into());
    window.set_page(if complete { 0 } else { 1 });
    window.set_version_text(version_line(None).into());
    window.set_app_version(update::CURRENT.into());
    window.set_autostart(system::autostart_enabled());
    window.set_game_mode(system::game_mode());
    window.set_tweaks_applied(system::tweaks_applied());
    window.set_server_available(crate::server::available());
    window.set_run_server(cfg.run_server);
    window.set_invite_code(if cfg.run_server { cfg.invite.clone() } else { String::new() }.into());
    let empty: Vec<SharedString> = vec![DEFAULT_DEVICE.into()];
    window.set_in_devices(ModelRc::new(VecModel::from(empty.clone())));
    window.set_out_devices(ModelRc::new(VecModel::from(empty)));

    let _ = CORE.set(Core::new(cfg, true, Box::new(on_core_event)));

    // --- действия пользователя ---
    window.on_toggle_mute(|| with_ui(|ui| ui.toggle_mute()));
    window.on_toggle_deafen(|| with_ui(|ui| ui.toggle_deafen()));
    window.on_set_vad_mode(|on| {
        core().set_voice_activation(on);
        with_ui(|ui| {
            ui.win.set_vad_mode(on);
            ui.update_level_timer();
        });
    });
    window.on_capture_key(|| {
        with_ui(|ui| {
            if ui.win.get_capturing_key() {
                core().cancel_key_capture();
                ui.win.set_capturing_key(false);
            } else {
                core().begin_key_capture();
                ui.win.set_capturing_key(true);
            }
        })
    });
    window.on_toggle_mic_test(|| {
        let on = !core().mic_test();
        core().set_mic_test(on);
        with_ui(|ui| ui.win.set_mic_test(on));
    });
    window.on_volume_changed(|session, v| {
        // Небольшая «липкая» зона вокруг 100 %.
        let v = if (v - 1.0).abs() < 0.04 { 1.0 } else { v };
        core().set_user_volume(session as u32, v);
        with_ui(|ui| {
            for i in 0..ui.users.row_count() {
                if let Some(mut item) = ui.users.row_data(i) {
                    if item.session == session {
                        item.volume = v;
                        ui.users.set_row_data(i, item);
                        break;
                    }
                }
            }
        });
    });
    window.on_input_selected(|i| {
        with_ui(|ui| {
            let input = if i <= 0 { String::new() } else { ui.in_names.get(i as usize - 1).cloned().unwrap_or_default() };
            let output = core().cfg.lock().unwrap().output_device.clone();
            core().set_devices(&input, &output);
        })
    });
    window.on_output_selected(|i| {
        with_ui(|ui| {
            let output = if i <= 0 { String::new() } else { ui.out_names.get(i as usize - 1).cloned().unwrap_or_default() };
            let input = core().cfg.lock().unwrap().input_device.clone();
            core().set_devices(&input, &output);
        })
    });
    window.on_save_connection(|| {
        with_ui(|ui| {
            let server = ui.win.get_server().to_string();
            let username = ui.win.get_username().to_string();
            let password = ui.win.get_password().to_string();
            let auto = ui.win.get_autoconnect();
            core().set_connection(&server, &username, &password, auto);
            ui.win.set_wants_connection(true);
            ui.win.set_page(0);
            ui.update_level_timer();
        })
    });
    window.on_toggle_connection(|| {
        with_ui(|ui| {
            if core().wants_connection() {
                core().disconnect();
                ui.win.set_wants_connection(false);
            } else if core().cfg.lock().unwrap().is_complete() {
                core().connect();
                ui.win.set_wants_connection(true);
            } else {
                ui.win.set_page(1);
            }
        })
    });
    window.on_set_autoconnect(|on| {
        core().cfg.lock().unwrap().autoconnect = on;
        core().mark_dirty();
        with_ui(|ui| ui.win.set_autoconnect(on));
    });
    window.on_set_noise_mode(|mode| {
        core().set_noise_mode(mode.clamp(0, 2) as u8);
        with_ui(|ui| ui.win.set_noise_mode(mode));
    });
    window.on_set_start_minimized(|on| {
        core().cfg.lock().unwrap().start_minimized = on;
        core().mark_dirty();
        with_ui(|ui| ui.win.set_start_minimized(on));
    });
    window.on_set_disable_warp(|on| {
        core().cfg.lock().unwrap().disable_warp = on;
        core().mark_dirty();
        with_ui(|ui| ui.win.set_disable_warp(on));
    });
    window.on_threshold_changed(|v| {
        core().set_vad_threshold(slider_to_rms(v));
        with_ui(|ui| ui.win.set_vad_threshold(v));
    });
    window.on_page_changed(|_| with_ui(|ui| ui.update_level_timer()));
    window.on_update_clicked(version_clicked);
    window.on_rerun_diag(|| {
        with_ui(|ui| ui.win.set_diag_running(true));
        request_diag();
    });
    window.on_fix_issue(|i| {
        let mut fix = Fix::None;
        with_ui(|ui| fix = ui.fixes.get(i as usize).copied().unwrap_or(Fix::None));
        match fix {
            Fix::DisableWarp => {
                win::disconnect_warp();
                with_ui(|ui| {
                    ui.show_notice("отключаю Cloudflare WARP…".into());
                    ui.win.set_diag_running(true);
                });
                std::thread::spawn(|| {
                    std::thread::sleep(Duration::from_secs(4));
                    request_diag();
                });
            }
            Fix::ApplyTweaks => run_system_setup("apply"),
            Fix::None => {}
        }
    });
    window.on_set_autostart(|on| {
        system::set_autostart(on);
        with_ui(|ui| ui.win.set_autostart(system::autostart_enabled()));
    });
    window.on_set_game_mode(|on| run_system_setup(if on { "gamemode-on" } else { "gamemode-off" }));
    window.on_apply_tweaks(|| run_system_setup("apply"));
    window.on_set_run_server(|on| {
        core().set_run_server(on);
        with_ui(|ui| {
            ui.win.set_run_server(on);
            let invite = if on { core().cfg.lock().unwrap().invite.clone() } else { String::new() };
            ui.win.set_invite_code(invite.into());
        });
    });
    window.on_copy_invite(|| {
        let invite = core().cfg.lock().unwrap().invite.clone();
        let ok = win::copy_to_clipboard(&invite);
        with_ui(|ui| ui.show_notice(if ok { "код приглашения скопирован".into() } else { "не удалось скопировать".into() }));
    });

    // Крестик сворачивает в трей, а не закрывает программу.
    window.window().on_close_requested(|| {
        // Откладываем, чтобы не менять состояние окна прямо внутри обработчика закрытия.
        Timer::single_shot(Duration::from_millis(0), || with_ui(|ui| ui.hide()));
        slint::CloseRequestResponse::KeepWindowShown
    });

    // --- трей ---
    let tray_parts = build_tray();
    let mut tray_icon = None;
    if let Some((tray, open, mic, sound, quit)) = tray_parts {
        let (open_id, mic_id, sound_id, quit_id) = (open.id().clone(), mic.id().clone(), sound.id().clone(), quit.id().clone());
        MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
            let id = e.id;
            if id == open_id {
                post(|ui| ui.show());
            } else if id == mic_id {
                post(|ui| ui.toggle_mute());
            } else if id == sound_id {
                post(|ui| ui.toggle_deafen());
            } else if id == quit_id {
                let _ = slint::invoke_from_event_loop(quit_app);
            }
        }));
        TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
                post(|ui| {
                    if ui.visible {
                        ui.hide();
                    } else {
                        ui.show();
                    }
                });
            }
        }));
        // Пункты меню должны жить, пока жив значок.
        std::mem::forget((open, mic, sound, quit));
        tray_icon = Some(tray);
    }
    let has_tray = tray_icon.is_some();

    UI.with(|u| {
        *u.borrow_mut() = Some(Ui {
            win: window,
            users,
            issues,
            fixes: Vec::new(),
            in_names: Vec::new(),
            out_names: Vec::new(),
            notice_timer: Timer::default(),
            level_timer: Timer::default(),
            visible: false,
            tray: tray_icon,
            tray_muted: false,
            release: None,
        });
    });

    refresh_devices();
    with_ui(|ui| {
        // Без значка в трее окно прятать нельзя — его было бы нечем вернуть.
        if !start_hidden || !has_tray {
            ui.show();
        }
    });
    if autoconnect {
        core().connect();
        with_ui(|ui| ui.win.set_wants_connection(true));
    }
    spawn_diag();
    spawn_update_checker();
    // Windows прячет новые значки в скрытую область; выносим свой на видное место.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(3));
        system::promote_tray_icon();
    });

    // Для автоматической проверки интерфейса: RACIYA_UI_TEST=mute,vad,page1 выполняет действия
    // так же, как если бы их нажал пользователь.
    if let Ok(actions) = std::env::var("RACIYA_UI_TEST") {
        Timer::single_shot(Duration::from_millis(2500), move || {
            let win = UI.with(|u| u.borrow().as_ref().map(|ui| ui.win.clone_strong()));
            let Some(win) = win else { return };
            for a in actions.split(',') {
                match a.trim() {
                    "mute" => win.invoke_toggle_mute(),
                    "deafen" => win.invoke_toggle_deafen(),
                    "vad" => win.invoke_set_vad_mode(true),
                    "mictest" => win.invoke_toggle_mic_test(),
                    "capture" => win.invoke_capture_key(),
                    "noise1" => win.invoke_set_noise_mode(1),
                    "noise2" => win.invoke_set_noise_mode(2),
                    "update" => win.invoke_update_clicked(),
                    // Непрерывная передача тихого тона — для замера нагрузки во время разговора.
                    "talk" => {
                        core().audio.tone.store(true, Ordering::Relaxed);
                        core().audio.ptt_down.store(true, Ordering::Relaxed);
                    }
                    "page1" => {
                        win.set_page(1);
                        win.invoke_page_changed(1);
                    }
                    "page2" => {
                        win.set_page(2);
                        win.invoke_page_changed(2);
                    }
                    "hide" => with_ui(|ui| ui.hide()),
                    _ => {}
                }
            }
        });
    }

    let _ = slint::run_event_loop_until_quit();
    core().shutdown();
}
