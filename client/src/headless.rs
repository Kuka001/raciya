//! Режим без окна для проверок и замеров:
//!   raciya.exe --headless --server 127.0.0.1:64738 --user test --password ... [--tone] [--talk MS:MS] [--seconds N]
//!
//!   --tone         вместо микрофона передаётся тон 440 Гц
//!   --talk ON:OFF  имитировать нажатие «говорить»: ON мс говорить, OFF мс молчать
//!   --vad          режим «по голосу»
//!   --seconds N    завершиться через N секунд (по умолчанию 20)

use crate::config::Config;
use crate::core::{Core, Event, Status};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

pub fn run(args: &[String]) {
    let mut cfg = Config::default();
    cfg.server = arg_value(args, "--server").unwrap_or_else(|| "127.0.0.1".into());
    cfg.username = arg_value(args, "--user").unwrap_or_else(|| "headless".into());
    cfg.password = arg_value(args, "--password").unwrap_or_default();
    cfg.voice_activation = args.iter().any(|a| a == "--vad");
    let seconds: u64 = arg_value(args, "--seconds").and_then(|s| s.parse().ok()).unwrap_or(20);
    let talk: Option<(u64, u64)> = arg_value(args, "--talk").and_then(|s| {
        let (a, b) = s.split_once(':')?;
        Some((a.parse().ok()?, b.parse().ok()?))
    });
    let tone = args.iter().any(|a| a == "--tone");
    // --ptt-vk N: код клавиши «говорить» (для проверки глобальной клавиши без окна).
    if let Some(vk) = arg_value(args, "--ptt-vk").and_then(|s| s.parse().ok()) {
        cfg.ptt_key = vk;
    }
    // --udp-probe IP:PORT: отправить 20 пустых UDP-пакетов с того же вида сокета, что и голос
    // (для проверки метки DSCP сетевым анализатором), и выйти.
    if let Some(target) = arg_value(args, "--udp-probe") {
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            let marked = crate::win::mark_voice_socket(&sock);
            for _ in 0..20 {
                let _ = sock.send_to(&[0u8; 60], &target);
                std::thread::sleep(Duration::from_millis(50));
            }
            println!("udp-probe: sent 20 packets to {target}, tos request accepted: {marked}");
        }
        return;
    }
    let name = cfg.username.clone();

    let t0 = Instant::now();
    let tag = name.clone();
    let core = Core::new(
        cfg,
        false,
        Box::new(move |ev| {
            let t = t0.elapsed().as_millis();
            match ev {
                Event::Status(s) => println!("[{tag} {t:>6}] status: {s:?}"),
                Event::Users => println!("[{tag} {t:>6}] users changed"),
                Event::Speaking { session, on } => println!("[{tag} {t:>6}] speaking session={session} on={on}"),
                Event::Ping { ms, udp } => {
                    println!("[{tag} {t:>6}] ping {ms:.2} ms via {}", if udp { "UDP" } else { "TCP" })
                }
                Event::Notice(n) => println!("[{tag} {t:>6}] notice: {n}"),
                Event::KeyCaptured(k) => println!("[{tag} {t:>6}] key captured: {k:?}"),
                Event::Devices { input, output } => println!("[{tag} {t:>6}] devices: in='{input}' out='{output}'"),
            }
        }),
    );
    core.audio.tone.store(tone, Ordering::Relaxed);
    core.connect();

    let end = Instant::now() + Duration::from_secs(seconds);
    let mut next_report = Instant::now() + Duration::from_secs(2);
    let mut talk_on = false;
    let mut talk_switch = Instant::now() + Duration::from_millis(1500);
    let mut last_tx = 0u64;
    let mut last_rx = 0u64;
    while Instant::now() < end {
        std::thread::sleep(Duration::from_millis(5));
        if matches!(core.status(), Status::Failed(_)) {
            break;
        }
        if let Some((on_ms, off_ms)) = talk {
            if core.is_online() && Instant::now() >= talk_switch {
                talk_on = !talk_on;
                core.audio.ptt_down.store(talk_on, Ordering::Relaxed);
                println!(
                    "[{name} {:>6}] ptt {} at_us={}",
                    t0.elapsed().as_millis(),
                    if talk_on { "DOWN" } else { "UP" },
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_micros())
                        .unwrap_or(0)
                );
                talk_switch = Instant::now() + Duration::from_millis(if talk_on { on_ms } else { off_ms });
            }
        }
        let st = &core.audio.stats;
        let tx = st.last_tx_start_us.load(Ordering::Relaxed);
        if tx != last_tx {
            last_tx = tx;
            println!("[{name} {:>6}] tx_start_us={tx}", t0.elapsed().as_millis());
        }
        let rx = st.last_rx_start_us.load(Ordering::Relaxed);
        if rx != last_rx {
            last_rx = rx;
            println!("[{name} {:>6}] rx_start_us={rx}", t0.elapsed().as_millis());
        }
        if Instant::now() >= next_report {
            next_report += Duration::from_secs(2);
            let users: Vec<String> = core
                .users()
                .iter()
                .map(|u| format!("{}{}{}", u.name, if u.is_self { "*" } else { "" }, if u.speaking { "(говорит)" } else { "" }))
                .collect();
            println!(
                "[{name} {:>6}] sent={} played={} concealed={} in_cb={}@{} out_cb={}@{} mic={:.3} users={:?} jitter={:?}",
                t0.elapsed().as_millis(),
                st.frames_sent.load(Ordering::Relaxed),
                st.frames_played.load(Ordering::Relaxed),
                st.frames_concealed.load(Ordering::Relaxed),
                st.in_callback_frames.load(Ordering::Relaxed),
                st.in_rate.load(Ordering::Relaxed),
                st.out_callback_frames.load(Ordering::Relaxed),
                st.out_rate.load(Ordering::Relaxed),
                core.mic_level(),
                users,
                core.audio.jitter_report(),
            );
        }
    }
    core.shutdown();
    std::thread::sleep(Duration::from_millis(300));
    println!("[{name}] final status: {:?}", core.status());
}
