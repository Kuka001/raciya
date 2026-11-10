// Без консольного окна. В режиме --headless вывод идёт в перенаправленный stdout.
#![windows_subsystem = "windows"]

mod audio;
mod config;
mod core;
mod diag;
mod headless;
mod jitter;
mod net;
mod ocb2;
mod proto;
mod server;
mod system;
mod ui;
mod update;
mod varint;
mod win;

// Режимы запуска:
//   (без ключей)            обычная работа; если программа запущена не из папки установки — экран установки
//   --autostart             запуск вместе с Windows: сразу в трей
//   --after-update          запуск новой версии сразу после обновления
//   --no-install            не показывать экран установки (для разработки)
//   --system-setup <режим>  системная настройка с правами администратора (см. scripts/system-setup.ps1)
//   --uninstall             удаление программы
//   --headless ...          работа без окна для проверок и замеров
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let has = |name: &str| args.iter().any(|a| a == name);
    if has("--system-setup") {
        std::process::exit(system::system_setup_worker(&args));
    }
    if has("--uninstall") {
        system::uninstall();
        return;
    }
    if has("--headless") {
        headless::run(&args);
        return;
    }
    win::set_app_id();
    ui::run(&args);
}
