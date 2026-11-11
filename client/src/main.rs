// Без консольного окна. В режимах --headless и --server вывод идёт в перенаправленный stdout.
#![windows_subsystem = "windows"]

#[macro_use]
mod log;
mod audio;
mod config;
mod core;
mod diag;
mod framing;
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
mod zt;

// Режимы запуска:
//   (без ключей)            обычная работа; если программа запущена не из папки установки — экран установки
//   --autostart             запуск вместе с Windows: сразу в трей
//   --after-update          запуск новой версии сразу после обновления
//   --no-install            не показывать экран установки (для разработки)
//   --system-setup <режим>  системная настройка с правами администратора (см. scripts/system-setup.ps1)
//   --uninstall             удаление программы
//   --server ...            только сервер, без окна (для отдельного компьютера-сервера и проверок)
//   --headless ...          клиент без окна для проверок и замеров
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
    if has("--server") {
        headless::run_server(&args);
        return;
    }
    win::set_app_id();
    ui::run(&args);
}
