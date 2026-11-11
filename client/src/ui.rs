//! Окно, трей и связь интерфейса с ядром. Здесь же — экран установки.

use crate::audio;
use crate::config::{Config, HostConfig};
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
/// Запрос проверки сети; `true` — по просьбе пользователя (без кэша медленных проверок).
static DIAG_TX: OnceLock<Mutex<Sender<bool>>> = OnceLock::new();
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
        self.win.set_qos_applied(system::qos_applied());
        self.win.set_game_mode(system::game_mode());
        self.win.set_autostart(system::autostart_enabled());
    }

    /// Состояние сервера на этом компьютере: строка в настройках и страница «Сервер».
    fn apply_server_view(&mut self) {
        let v = core().server_view();
        let (state, text) = if !v.enabled {
            (0, "Выключен".to_string())
        } else if v.starting {
            (1, "Запускается…".to_string())
        } else if v.running {
            let n = v.users.len();
            (2, format!("Работает · порт {} · участников: {n}", v.port))
        } else if let Some(e) = &v.error {
            (3, capitalize(e))
        } else {
            (0, "Не запущен".to_string())
        };
        self.win.set_srv_enabled(v.enabled);
        self.win.set_srv_state(state);
        self.win.set_srv_status(text.into());
        self.win.set_srv_fixable(v.fixable);
        self.win.set_srv_online(if v.running && !v.users.is_empty() {
            format!("Сейчас на сервере: {}", v.users.join(", ")).into()
        } else {
            SharedString::new()
        });
        let zt_network = core().cfg.lock().unwrap().zt_network.clone();
        let mut items = Vec::new();
        let mut invite = String::new();
        if v.enabled {
            let port_suffix = if v.port == crate::config::DEFAULT_PORT { String::new() } else { format!(":{}", v.port) };
            for (label, ip) in diag::local_addresses() {
                let addr = format!("{ip}{port_suffix}");
                if label == "ZeroTier" && !zt_network.is_empty() && invite.is_empty() {
                    invite = system::make_invite(Some(&zt_network), &addr);
                    items.push(AddressItem { label: "Код приглашения (через ZeroTier)".into(), value: invite.clone().into() });
                } else {
                    items.push(AddressItem { label: label.into(), value: addr.into() });
                }
            }
        }
        self.win.set_srv_addresses(ModelRc::new(VecModel::from(items)));
        self.win.set_invite_code(invite.into());
    }

    /// Поля страницы «Сервер» — из сохранённых настроек.
    fn fill_server_fields(&mut self) {
        let h = core().cfg.lock().unwrap().host();
        self.win.set_srv_password(h.password.into());
        self.win.set_srv_port(h.port.to_string().into());
        self.win.set_srv_users(h.max_users.to_string().into());
        self.win.set_srv_welcome(h.welcome.into());
    }

    /// Настройки сервера из полей страницы. `Err` — текст ошибки для пользователя.
    fn read_server_fields(&self, enabled: bool) -> Result<HostConfig, String> {
        let port: u16 = self
            .win
            .get_srv_port()
            .trim()
            .parse()
            .ok()
            .filter(|&p| p > 0)
            .ok_or("порт — число от 1 до 65535")?;
        let users: u32 = self
            .win
            .get_srv_users()
            .trim()
            .parse()
            .ok()
            .filter(|n| (1..=1000).contains(n))
            .ok_or("мест — число от 1 до 1000")?;
        let current = core().cfg.lock().unwrap().host();
        Ok(HostConfig {
            enabled,
            port,
            max_users: users,
            password: self.win.get_srv_password().to_string(),
            welcome: self.win.get_srv_welcome().trim().to_string(),
            ..current
        })
    }
}

fn refresh_devices() {
    // Перечисление устройств занимает десятки миллисекунд — делаем его вне потока интерфейса.
    std::thread::spawn(|| {
        let (ins, outs) = audio::list_devices();
        post(move |ui| ui.set_devices(ins, outs));
    });
}

fn request_diag(force: bool) {
    if let Some(tx) = DIAG_TX.get() {
        let _ = tx.lock().unwrap().send(force);
    }
}

/// Фоновая проверка сети: вскоре после запуска, затем изредка и по запросу.
fn spawn_diag() {
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    let _ = DIAG_TX.set(Mutex::new(tx));
    let _ = std::thread::Builder::new().name("diag".into()).spawn(move || {
        win::set_thread_priority(win::Prio::Low);
        std::thread::sleep(Duration::from_secs(5));
        let mut force = false;
        loop {
            post(|ui| ui.win.set_diag_running(true));
            let mut ctx = core().diag_context();
            ctx.force = force;
            let rep = diag::run(&ctx);
            post(move |ui| ui.apply_report(rep));
            // Пока окно свёрнуто (идёт игра), проверяем реже.
            let pause = if VISIBLE.load(Ordering::Relaxed) { 180 } else { 600 };
            force = match rx.recv_timeout(Duration::from_secs(pause)) {
                Ok(f) => f,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => false,
                Err(_) => return,
            };
            while let Ok(f) = rx.try_recv() {
                force |= f;
            }
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
    run_system_setup_then(mode, None);
}

/// Системная настройка; `then` выполняется после неё (даже если пользователь отказал в правах).
fn run_system_setup_then(mode: &'static str, then: Option<Box<dyn FnOnce() + Send>>) {
    let mut busy = false;
    with_ui(|ui| {
        busy = ui.win.get_system_busy();
        ui.win.set_system_busy(true);
    });
    if busy {
        return;
    }
    std::thread::spawn(move || {
        let args = {
            let cfg = core().cfg.lock().unwrap();
            system::SetupArgs { network: cfg.zt_network.clone(), port: Some(cfg.host().port) }
        };
        let result = system::request_system_setup(mode, &args);
        let ok = matches!(&result, Ok(r) if r.ok);
        if mode == "server" {
            diag::invalidate_cache();
        }
        match then {
            Some(f) => f(),
            // Порт теперь закреплён — пробуем запустить сервер ещё раз.
            None if mode == "server" && (ok || core().server_view().error.is_some()) => core().apply_server_setting(2),
            None => {}
        }
        post(move |ui| {
            ui.win.set_system_busy(false);
            ui.refresh_system_state();
            match result {
                Ok(r) if r.ok => ui.show_notice(
                    match mode {
                        "gamemode-on" => "фоновые загрузки ограничены",
                        "gamemode-off" => "ограничение загрузок снято",
                        "qos-on" => "приоритет голоса включён",
                        "qos-off" => "приоритет голоса выключен",
                        "server" => "компьютер настроен для сервера",
                        "client" => "виртуальная сеть подключена",
                        _ => "готово",
                    }
                    .into(),
                ),
                Ok(r) => ui.show_notice(format!("не всё получилось: {}", r.failures())),
                Err(e) => ui.show_notice(e),
            }
        });
        request_diag(true);
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
                    request_diag(false);
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
        Event::Server => ui.apply_server_view(),
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
    let old = Config::load_from(crate::config::roaming_dir().join("config.toml"));
    let known = if !old.server.trim().is_empty() && !old.hosting() && !old.run_server {
        let net = (!old.zt_network.is_empty()).then_some(old.zt_network.as_str());
        Some(system::make_invite(net, old.server.trim()))
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
                        "Адрес или код выглядит неверно. Подойдёт адрес (192.168.0.15, myhost.example:64738) или код вида номер_сети@адрес — скопируйте его целиком."
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
                                "«Рация» установлена, но {wtext}.\n\nПовторить можно в самой программе: «Сеть» → «Исправить»."
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
    crate::log::init_client(system::user_dir().join("raciya.log"));
    crate::log::init_server(crate::server::data_dir().join("server.log"));
    clog!("Рация {} запущена ({})", update::CURRENT, exe.display());

    let mut cfg = Config::load();
    if cfg.migrate_legacy_server() {
        clog!("настройки сервера перенесены из Mumble Server (версия 0.2)");
        cfg.save();
    }
    system::cleanup_legacy();
    let complete = cfg.is_complete();
    let autoconnect = cfg.autoconnect && complete;
    let start_hidden = (cfg.start_minimized || has("--autostart")) && complete;

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
    window.set_vad_mode(cfg.voice_activation);
    window.set_vad_threshold(rms_to_slider(cfg.vad_threshold));
    window.set_key_name(win::key_name(cfg.ptt_key).into());
    window.set_page(if complete { 0 } else { 1 });
    window.set_version_text(version_line(None).into());
    window.set_app_version(update::CURRENT.into());
    window.set_autostart(system::autostart_enabled());
    window.set_game_mode(system::game_mode());
    window.set_qos_applied(system::qos_applied());
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
        let mut join_network = false;
        with_ui(|ui| {
            let text = ui.win.get_server().to_string();
            // Код с виртуальной сетью: адрес — отдельно, сеть подключается (если ещё нет).
            let server = match system::parse_invite(&text) {
                Some(inv) => {
                    if let Some(n) = inv.network {
                        let mut cfg = core().cfg.lock().unwrap();
                        if cfg.zt_network != n {
                            cfg.zt_network = n;
                            join_network = true;
                        }
                        core().mark_dirty();
                    }
                    inv.server
                }
                None => {
                    if crate::config::parse_address(&text).is_none() {
                        ui.show_notice("адрес сервера выглядит неверно".into());
                        return;
                    }
                    text.trim().to_string()
                }
            };
            ui.win.set_server(server.clone().into());
            let username = ui.win.get_username().to_string();
            let password = ui.win.get_password().to_string();
            let auto = ui.win.get_autoconnect();
            core().set_connection(&server, &username, &password, auto);
            ui.win.set_wants_connection(true);
            ui.win.set_page(0);
            ui.update_level_timer();
        });
        if join_network {
            run_system_setup("client");
        }
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
    window.on_threshold_changed(|v| {
        core().set_vad_threshold(slider_to_rms(v));
        with_ui(|ui| ui.win.set_vad_threshold(v));
    });
    window.on_page_changed(|page| {
        with_ui(|ui| {
            ui.update_level_timer();
            if page == 4 {
                ui.fill_server_fields();
                ui.apply_server_view();
            }
        })
    });
    window.on_update_clicked(version_clicked);
    window.on_rerun_diag(|| {
        with_ui(|ui| ui.win.set_diag_running(true));
        request_diag(true);
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
                    request_diag(true);
                });
            }
            Fix::JoinZeroTier => run_system_setup("client"),
            Fix::ServerSetup => run_system_setup("server"),
            Fix::ZeroTierRules => {
                let (network, port) = {
                    let cfg = core().cfg.lock().unwrap();
                    (cfg.zt_network.clone(), cfg.host().port)
                };
                std::thread::spawn(move || {
                    let text = match crate::zt::set_server_port(&network, port) {
                        Ok(true) => format!("сеть ZeroTier теперь пропускает порт {port}"),
                        Ok(false) => "сеть ZeroTier создана на другом компьютере — правила меняют там".into(),
                        Err(e) => format!("не удалось: {e}"),
                    };
                    post(move |ui| ui.show_notice(text));
                    request_diag(true);
                });
            }
            Fix::None => {}
        }
    });
    window.on_set_autostart(|on| {
        system::set_autostart(on);
        with_ui(|ui| ui.win.set_autostart(system::autostart_enabled()));
    });
    window.on_set_game_mode(|on| run_system_setup(if on { "gamemode-on" } else { "gamemode-off" }));
    window.on_set_qos(|on| run_system_setup(if on { "qos-on" } else { "qos-off" }));
    window.on_set_server_enabled(|on| {
        let mut host = None;
        with_ui(|ui| match ui.read_server_fields(on) {
            Ok(h) => host = Some(h),
            Err(e) => {
                ui.show_notice(e);
                ui.win.set_srv_enabled(!on);
            }
        });
        let Some(host) = host else { return };
        // Первое включение на этом компьютере: сначала брандмауэр и закрепление порта (одно окно UAC),
        // потом запуск. Тогда Windows не показывает свой запрос, где «Отмена» заблокировала бы сервер.
        if on && system::server_setup_port() != Some(host.port) {
            with_ui(|ui| ui.win.set_srv_status("Настраиваю компьютер для сервера…".into()));
            // Настройка берёт порт из сохранённых настроек — кладём туда новые значения заранее.
            core().cfg.lock().unwrap().host = Some(host.clone());
            core().mark_dirty();
            run_system_setup_then("server", Some(Box::new(move || core().set_host(host))));
        } else {
            core().set_host(host);
        }
    });
    window.on_save_server(|| {
        let mut host = None;
        with_ui(|ui| match ui.read_server_fields(ui.win.get_srv_enabled()) {
            Ok(h) => host = Some(h),
            Err(e) => ui.show_notice(e),
        });
        let Some(host) = host else { return };
        let port_changed = core().cfg.lock().unwrap().host().port != host.port;
        with_ui(|ui| ui.show_notice("настройки сервера сохранены".into()));
        if host.enabled && port_changed && system::server_setup_port() != Some(host.port) {
            // Новый порт: правила брандмауэра и закрепление — до запуска сервера на нём.
            core().cfg.lock().unwrap().host = Some(host.clone());
            core().mark_dirty();
            run_system_setup_then("server", Some(Box::new(move || core().set_host(host))));
        } else {
            core().set_host(host);
        }
    });
    window.on_fix_server(|| run_system_setup("server"));
    window.on_copy_text(|text| {
        let ok = win::copy_to_clipboard(&text);
        with_ui(|ui| ui.show_notice(if ok { format!("скопировано: {text}") } else { "не удалось скопировать".into() }));
    });
    window.on_copy_invite(|| {
        let mut invite = String::new();
        with_ui(|ui| invite = ui.win.get_invite_code().to_string());
        let ok = !invite.is_empty() && win::copy_to_clipboard(&invite);
        with_ui(|ui| ui.show_notice(if ok { "код приглашения скопирован".into() } else { "не удалось скопировать".into() }));
    });
    window.on_open_log(|| {
        if let Some(path) = crate::log::client_path() {
            let dir = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
            let _ = std::fs::create_dir_all(&dir);
            let _ = std::process::Command::new("explorer.exe").arg(&dir).spawn();
        }
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
    with_ui(|ui| {
        ui.fill_server_fields();
        ui.apply_server_view();
    });
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
                    "page4" => {
                        win.set_page(4);
                        win.invoke_page_changed(4);
                    }
                    "fixserver" => win.invoke_fix_server(),
                    "hide" => with_ui(|ui| ui.hide()),
                    _ => {}
                }
            }
        });
    }

    let _ = slint::run_event_loop_until_quit();
    core().shutdown();
}
