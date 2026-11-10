//! Звук: захват микрофона → Opus → сеть, и сеть → джиттер-буфер → Opus → микшер → наушники.
//! Кодирование и отправка идут прямо в потоке захвата, декодирование — в потоке вывода,
//! чтобы между микрофоном и сетью не было лишних очередей.

use crate::jitter::{Jitter, Pop};
use crate::net::{build_voice_packet, Link};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{FromSample, Sample, SizedSample};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// Кадр 10 мс при 48 кГц.
pub const FRAME: usize = 480;
pub const RATE: u32 = 48_000;
/// Условный «участник» для проверки собственного голоса.
pub const LOOPBACK_SESSION: u32 = u32::MAX;
/// Сколько кадров тишины держим индикатор «говорит» (чтобы не мигал между словами).
const SPEAK_HOLD: u32 = 15;
/// «Хвост» после отпускания кнопки (кадры по 10 мс), чтобы не обрезать конец слова.
const PTT_TAIL: u32 = 6;
/// Сколько кадров продолжаем передачу после падения громкости ниже порога (режим «по голосу»).
const VAD_HANG: u32 = 35;

pub enum AudioEvent {
    Speaking { session: u32, on: bool },
    SelfTalking(bool),
    DeviceError(String),
    Devices { input: String, output: String },
}

#[derive(Default)]
pub struct AudioStats {
    pub in_callback_frames: AtomicU32,
    pub out_callback_frames: AtomicU32,
    pub in_rate: AtomicU32,
    pub out_rate: AtomicU32,
    pub frames_sent: AtomicU64,
    pub frames_played: AtomicU64,
    pub frames_concealed: AtomicU64,
    /// Время (мкс от начала эпохи Unix), когда был отправлен первый кадр последней фразы.
    pub last_tx_start_us: AtomicU64,
    /// Время, когда микшер начал воспроизводить последнюю начавшуюся чужую фразу.
    pub last_rx_start_us: AtomicU64,
}

struct RxUser {
    jitter: Jitter,
    dec: opus::Decoder,
    pcm: Vec<f32>,
    pcm_pos: usize,
    span: usize,
    volume: f32,
    speaking: bool,
    quiet: u32,
}

impl RxUser {
    fn new(volume: f32) -> Option<Self> {
        Some(RxUser {
            jitter: Jitter::new(),
            dec: opus::Decoder::new(RATE, opus::Channels::Mono).ok()?,
            pcm: Vec::with_capacity(FRAME * 4),
            pcm_pos: 0,
            span: 1,
            volume,
            speaking: false,
            quiet: 0,
        })
    }
}

#[derive(Default)]
struct RxState {
    users: HashMap<u32, RxUser>,
    volumes: HashMap<u32, f32>,
}

pub struct AudioShared {
    pub link: RwLock<Option<Arc<Link>>>,
    pub ptt_down: AtomicBool,
    pub muted: AtomicBool,
    pub deafened: AtomicBool,
    pub vad_mode: AtomicBool,
    /// 0 — без шумоподавления, 1 — лёгкое (шумовой порог), 2 — сильное (RNNoise).
    pub noise_mode: AtomicU32,
    pub mic_test: AtomicBool,
    /// Вместо микрофона подаётся тон 440 Гц (для автоматических проверок).
    pub tone: AtomicBool,
    pub vad_threshold: AtomicU32,
    pub bitrate: AtomicU32,
    pub mic_peak: AtomicU32,
    pub stats: AudioStats,
    rx: Mutex<RxState>,
    sink: Box<dyn Fn(AudioEvent) + Send + Sync>,
}

fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

impl AudioShared {
    pub fn new(sink: Box<dyn Fn(AudioEvent) + Send + Sync>) -> Arc<Self> {
        Arc::new(AudioShared {
            link: RwLock::new(None),
            ptt_down: AtomicBool::new(false),
            muted: AtomicBool::new(false),
            deafened: AtomicBool::new(false),
            vad_mode: AtomicBool::new(false),
            noise_mode: AtomicU32::new(0),
            mic_test: AtomicBool::new(false),
            tone: AtomicBool::new(false),
            vad_threshold: AtomicU32::new(0.02f32.to_bits()),
            bitrate: AtomicU32::new(40_000),
            mic_peak: AtomicU32::new(0),
            stats: AudioStats::default(),
            rx: Mutex::new(RxState::default()),
            sink,
        })
    }

    /// Принят голосовой пакет от участника.
    pub fn push_voice(&self, session: u32, seq: u64, data: &[u8], last: bool) {
        let mut rx = self.rx.lock().unwrap();
        let vol = rx.volumes.get(&session).copied().unwrap_or(1.0);
        if !rx.users.contains_key(&session) {
            match RxUser::new(vol) {
                Some(u) => {
                    rx.users.insert(session, u);
                }
                None => return,
            }
        }
        if let Some(u) = rx.users.get_mut(&session) {
            u.jitter.push(seq, data.to_vec(), last);
        }
    }

    pub fn set_volume(&self, session: u32, volume: f32) {
        let mut rx = self.rx.lock().unwrap();
        rx.volumes.insert(session, volume);
        if let Some(u) = rx.users.get_mut(&session) {
            u.volume = volume;
        }
    }

    pub fn remove_user(&self, session: u32) {
        let mut rx = self.rx.lock().unwrap();
        rx.users.remove(&session);
        rx.volumes.remove(&session);
    }

    /// Сбрасывает всё принятое (после отключения от сервера).
    pub fn clear_rx(&self) {
        let mut rx = self.rx.lock().unwrap();
        rx.users.clear();
        rx.volumes.clear();
    }

    /// Состояние джиттер-буферов: (сессия, глубина, запас, потеряно, опоздало).
    pub fn jitter_report(&self) -> Vec<(u32, usize, usize, u32, u32)> {
        let rx = self.rx.lock().unwrap();
        rx.users
            .iter()
            .map(|(s, u)| (*s, u.jitter.depth(), u.jitter.margin(), u.jitter.stat_lost, u.jitter.stat_late))
            .collect()
    }

    fn emit(&self, ev: AudioEvent) {
        (self.sink)(ev);
    }
}

// ---------------------------------------------------------------------------------------------
// Преобразование частоты (линейная интерполяция). Нужна только если устройство работает не на 48 кГц.

struct Resampler {
    step: f64,
    pos: f64,
    prev: f32,
}

impl Resampler {
    fn new(from: u32, to: u32) -> Option<Self> {
        if from == to {
            None
        } else {
            Some(Resampler { step: from as f64 / to as f64, pos: 0.0, prev: 0.0 })
        }
    }

    #[inline]
    fn push(&mut self, x: f32, out: &mut [f32; 16]) -> usize {
        let mut n = 0;
        while self.pos < 1.0 && n < out.len() {
            out[n] = self.prev + (x - self.prev) * self.pos as f32;
            n += 1;
            self.pos += self.step;
        }
        self.pos -= 1.0;
        self.prev = x;
        n
    }
}

// ---------------------------------------------------------------------------------------------
// Захват

#[derive(PartialEq, Clone, Copy)]
enum Dest {
    None,
    Net,
    Test,
}

struct Capture {
    shared: Arc<AudioShared>,
    enc: opus::Encoder,
    bitrate: u32,
    buf: [f32; FRAME],
    fill: usize,
    channels: usize,
    resampler: Option<Resampler>,
    seq: u64,
    dest: Dest,
    hang: u32,
    tail: u32,
    denoise: Option<Box<nnnoiseless::DenoiseState<'static>>>,
    gate_floor: f32,
    gate_gain: f32,
    gate_hold: u32,
    packet: Vec<u8>,
    opus_buf: [u8; 1275],
    peak_hold: f32,
    tone_phase: f32,
    boosted: bool,
}

impl Capture {
    fn new(shared: Arc<AudioShared>, channels: usize, rate: u32) -> Result<Self, String> {
        let mut enc = opus::Encoder::new(RATE, opus::Channels::Mono, opus::Application::Voip)
            .map_err(|e| format!("кодек Opus: {e}"))?;
        let bitrate = shared.bitrate.load(Ordering::Relaxed);
        let _ = enc.set_bitrate(opus::Bitrate::Bits(bitrate as i32));
        // Постоянный битрейт: размер пакетов предсказуем, и сервер не отбрасывает их
        // за превышение лимита `bandwidth` на пиках.
        let _ = enc.set_vbr(false);
        Ok(Capture {
            shared,
            enc,
            bitrate,
            buf: [0.0; FRAME],
            fill: 0,
            channels: channels.max(1),
            resampler: Resampler::new(rate, RATE),
            seq: 0,
            dest: Dest::None,
            hang: 0,
            tail: 0,
            denoise: None,
            gate_floor: 0.0,
            gate_gain: 1.0,
            gate_hold: 0,
            packet: Vec::with_capacity(256),
            opus_buf: [0u8; 1275],
            peak_hold: 0.0,
            tone_phase: 0.0,
            boosted: false,
        })
    }

    fn feed<T>(&mut self, data: &[T])
    where
        T: Copy,
        f32: FromSample<T>,
    {
        if !self.boosted {
            crate::win::boost_audio_thread();
            self.boosted = true;
        }
        self.shared
            .stats
            .in_callback_frames
            .store((data.len() / self.channels) as u32, Ordering::Relaxed);
        let mut tmp = [0f32; 16];
        let inv = 1.0 / self.channels as f32;
        for chunk in data.chunks_exact(self.channels) {
            let mut s = 0.0f32;
            for &c in chunk {
                s += f32::from_sample(c);
            }
            s *= inv;
            if self.resampler.is_some() {
                let n = self.resampler.as_mut().unwrap().push(s, &mut tmp);
                for &v in &tmp[..n] {
                    self.push_sample(v);
                }
            } else {
                self.push_sample(s);
            }
        }
    }

    #[inline]
    fn push_sample(&mut self, s: f32) {
        self.buf[self.fill] = s;
        self.fill += 1;
        if self.fill == FRAME {
            self.fill = 0;
            self.process_frame();
        }
    }

    fn process_frame(&mut self) {
        let sh = self.shared.clone();

        if sh.tone.load(Ordering::Relaxed) {
            let step = 2.0 * std::f32::consts::PI * 440.0 / RATE as f32;
            for s in self.buf.iter_mut() {
                // Тихий тон (около −34 дБ), чтобы проверки не шумели в наушниках.
                *s = 0.02 * self.tone_phase.sin();
                self.tone_phase += step;
            }
            if self.tone_phase > 1000.0 {
                self.tone_phase %= 2.0 * std::f32::consts::PI;
            }
        }

        let noise_mode = sh.noise_mode.load(Ordering::Relaxed);
        if noise_mode == 2 {
            let st = self.denoise.get_or_insert_with(nnnoiseless::DenoiseState::new);
            let mut input = [0f32; FRAME];
            let mut output = [0f32; FRAME];
            for (i, s) in self.buf.iter().enumerate() {
                input[i] = s * 32768.0;
            }
            st.process_frame(&mut output, &input);
            for (i, s) in self.buf.iter_mut().enumerate() {
                *s = output[i] / 32768.0;
            }
        } else if self.denoise.is_some() {
            self.denoise = None;
        }
        if noise_mode == 1 {
            self.noise_gate();
        } else {
            self.gate_gain = 1.0;
        }

        let mut peak = 0f32;
        let mut sumsq = 0f32;
        for &s in self.buf.iter() {
            peak = peak.max(s.abs());
            sumsq += s * s;
        }
        let rms = (sumsq / FRAME as f32).sqrt();
        // Для индикатора в интерфейсе — тот же уровень, по которому срабатывает режим «по голосу».
        let _ = peak;
        self.peak_hold = rms.max(self.peak_hold * 0.85);
        sh.mic_peak.store(self.peak_hold.to_bits(), Ordering::Relaxed);

        let test = sh.mic_test.load(Ordering::Relaxed);
        let silenced = sh.muted.load(Ordering::Relaxed) || sh.deafened.load(Ordering::Relaxed);

        let want = if sh.vad_mode.load(Ordering::Relaxed) {
            let thr = f32::from_bits(sh.vad_threshold.load(Ordering::Relaxed));
            if rms > thr {
                self.hang = VAD_HANG;
                true
            } else if self.hang > 0 {
                self.hang -= 1;
                true
            } else {
                false
            }
        } else if test {
            true
        } else if sh.ptt_down.load(Ordering::Relaxed) {
            self.tail = PTT_TAIL;
            true
        } else if self.tail > 0 {
            self.tail -= 1;
            true
        } else {
            false
        };

        // Во время проверки голоса звук идёт только в собственные наушники.
        let dest = if !want {
            Dest::None
        } else if test {
            Dest::Test
        } else if silenced {
            Dest::None
        } else {
            Dest::Net
        };

        if dest != self.dest && self.dest != Dest::None {
            // Фраза закончилась (или сменился получатель): завершающий пакет прежнему получателю.
            self.encode_and_send(self.dest, true);
            if self.dest == Dest::Net {
                sh.emit(AudioEvent::SelfTalking(false));
            }
            self.dest = Dest::None;
            if dest == Dest::None {
                return;
            }
        }
        if dest == Dest::None {
            return;
        }
        if self.dest == Dest::None {
            if dest == Dest::Net {
                sh.stats.last_tx_start_us.store(now_us(), Ordering::Relaxed);
                sh.emit(AudioEvent::SelfTalking(true));
            }
            self.dest = dest;
        }
        self.encode_and_send(dest, false);
    }

    /// Лёгкое шумоподавление: шумовой порог. Программа следит за уровнем фона и приглушает звук
    /// на 16 дБ, когда он не выше фона (шум вентилятора, гул), не трогая речь. Почти не тратит процессор.
    fn noise_gate(&mut self) {
        let mut sumsq = 0f32;
        for &s in self.buf.iter() {
            sumsq += s * s;
        }
        let rms = (sumsq / FRAME as f32).sqrt();
        // Оценка фона: быстро опускается к тихим кадрам, медленно поднимается.
        if self.gate_floor <= 0.0 || rms < self.gate_floor {
            self.gate_floor = rms.max(1e-5);
        } else {
            self.gate_floor += (rms - self.gate_floor) * 0.003;
        }
        let open = rms > self.gate_floor * 3.0 + 0.0015;
        if open {
            self.gate_hold = 25;
        } else if self.gate_hold > 0 {
            self.gate_hold -= 1;
        }
        let target = if open || self.gate_hold > 0 { 1.0 } else { 0.16 };
        // Открывается за один кадр, закрывается плавно — без щелчков и обрезанных окончаний.
        let end = if target > self.gate_gain { target } else { self.gate_gain + (target - self.gate_gain) * 0.12 };
        let step = (end - self.gate_gain) / FRAME as f32;
        let mut g = self.gate_gain;
        for s in self.buf.iter_mut() {
            g += step;
            *s *= g;
        }
        self.gate_gain = end;
    }

    fn encode_and_send(&mut self, dest: Dest, last: bool) {
        let want_bitrate = self.shared.bitrate.load(Ordering::Relaxed);
        if want_bitrate != self.bitrate {
            self.bitrate = want_bitrate;
            let _ = self.enc.set_bitrate(opus::Bitrate::Bits(want_bitrate as i32));
        }
        let n = match self.enc.encode_float(&self.buf, &mut self.opus_buf) {
            Ok(n) => n,
            Err(_) => return,
        };
        let seq = self.seq;
        self.seq += 1;
        match dest {
            Dest::Net => {
                build_voice_packet(&mut self.packet, seq, &self.opus_buf[..n], last);
                if let Some(link) = self.shared.link.read().unwrap().as_ref() {
                    link.send_voice(&self.packet);
                }
                self.shared.stats.frames_sent.fetch_add(1, Ordering::Relaxed);
            }
            Dest::Test => self.shared.push_voice(LOOPBACK_SESSION, seq, &self.opus_buf[..n], last),
            Dest::None => {}
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Воспроизведение

struct Mixer {
    shared: Arc<AudioShared>,
    frame: [f32; FRAME],
    pos: usize,
    scratch: Vec<f32>,
    changes: Vec<(u32, bool)>,
    resampler: Option<Resampler>,
    rs_have: f32,
    rs_next: f32,
    rs_pos: f64,
    rs_step: f64,
    channels: usize,
    boosted: bool,
}

impl Mixer {
    fn new(shared: Arc<AudioShared>, channels: usize, rate: u32) -> Self {
        Mixer {
            shared,
            frame: [0.0; FRAME],
            pos: FRAME,
            scratch: vec![0.0; 5760],
            changes: Vec::with_capacity(8),
            resampler: Resampler::new(RATE, rate),
            rs_have: 0.0,
            rs_next: 0.0,
            rs_pos: 1.0,
            rs_step: RATE as f64 / rate as f64,
            channels: channels.max(1),
            boosted: false,
        }
    }

    /// Собирает следующий кадр 10 мс из всех говорящих участников.
    fn next_frame(&mut self) {
        self.frame = [0.0; FRAME];
        self.changes.clear();
        let deaf = self.shared.deafened.load(Ordering::Relaxed);
        let stats = &self.shared.stats;
        {
            let mut rx = self.shared.rx.lock().unwrap();
            for (&session, u) in rx.users.iter_mut() {
                let mut produced = false;
                // Добираем декодированный звук, пока не хватит на кадр.
                while u.pcm.len() - u.pcm_pos < FRAME {
                    if u.pcm_pos > 0 {
                        u.pcm.drain(..u.pcm_pos);
                        u.pcm_pos = 0;
                    }
                    match u.jitter.pop() {
                        (Pop::Frame(data), seq) => {
                            let n = u.dec.decode_float(&data, &mut self.scratch, false).unwrap_or(0);
                            if n == 0 {
                                u.pcm.extend(std::iter::repeat(0.0).take(FRAME));
                            } else {
                                u.pcm.extend_from_slice(&self.scratch[..n]);
                                u.span = (n / FRAME).max(1);
                                u.jitter.set_span(u.span as u64, seq);
                            }
                            stats.frames_played.fetch_add(1, Ordering::Relaxed);
                            produced = true;
                        }
                        (Pop::Lost, _) => {
                            let want = FRAME * u.span;
                            let n = u.dec.decode_float(&[], &mut self.scratch[..want], false).unwrap_or(0);
                            if n == 0 {
                                u.pcm.extend(std::iter::repeat(0.0).take(FRAME));
                            } else {
                                u.pcm.extend_from_slice(&self.scratch[..n]);
                            }
                            stats.frames_concealed.fetch_add(1, Ordering::Relaxed);
                            produced = true;
                        }
                        (Pop::Idle, _) => break,
                    }
                }

                let avail = u.pcm.len() - u.pcm_pos;
                if avail >= FRAME {
                    // Свой голос при проверке слышен всегда; остальных заглушает «выключить звук».
                    if !deaf || session == LOOPBACK_SESSION {
                        let vol = u.volume;
                        let src = &u.pcm[u.pcm_pos..u.pcm_pos + FRAME];
                        for (o, s) in self.frame.iter_mut().zip(src) {
                            *o += s * vol;
                        }
                    }
                    u.pcm_pos += FRAME;
                    produced = true;
                }

                if produced {
                    u.quiet = 0;
                    if !u.speaking {
                        u.speaking = true;
                        if session != LOOPBACK_SESSION {
                            stats.last_rx_start_us.store(now_us(), Ordering::Relaxed);
                        }
                        self.changes.push((session, true));
                    }
                } else if u.speaking {
                    u.quiet += 1;
                    if u.quiet > SPEAK_HOLD {
                        u.speaking = false;
                        self.changes.push((session, false));
                    }
                }
            }
        }
        // Мягкое ограничение, чтобы сумма нескольких голосов не давала треска.
        for s in self.frame.iter_mut() {
            let a = s.abs();
            if a > 0.8 {
                let over = (a - 0.8) / 0.2;
                *s = s.signum() * (0.8 + 0.2 * over.tanh());
            }
        }
        for &(session, on) in &self.changes {
            self.shared.emit(AudioEvent::Speaking { session, on });
        }
    }

    #[inline]
    fn next_sample(&mut self) -> f32 {
        if self.pos >= FRAME {
            self.next_frame();
            self.pos = 0;
        }
        let s = self.frame[self.pos];
        self.pos += 1;
        s
    }

    fn fill<T>(&mut self, out: &mut [T])
    where
        T: SizedSample + FromSample<f32>,
    {
        if !self.boosted {
            crate::win::boost_audio_thread();
            self.boosted = true;
        }
        let ch = self.channels;
        self.shared
            .stats
            .out_callback_frames
            .store((out.len() / ch) as u32, Ordering::Relaxed);
        let resample = self.resampler.is_some();
        for frame in out.chunks_exact_mut(ch) {
            let v = if resample {
                while self.rs_pos >= 1.0 {
                    self.rs_have = self.rs_next;
                    self.rs_next = self.next_sample();
                    self.rs_pos -= 1.0;
                }
                let v = self.rs_have + (self.rs_next - self.rs_have) * self.rs_pos as f32;
                self.rs_pos += self.rs_step;
                v
            } else {
                self.next_sample()
            };
            let sample = T::from_sample(v);
            // Голос — в левый и правый каналы; остальные (5.1 и т.п.) остаются тихими.
            for (i, o) in frame.iter_mut().enumerate() {
                *o = if i < 2 { sample } else { T::from_sample(0.0f32) };
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Устройства и потоки

pub fn list_devices() -> (Vec<String>, Vec<String>) {
    let host = cpal::default_host();
    let ins = host
        .input_devices()
        .map(|it| it.filter_map(|d| d.name().ok()).collect())
        .unwrap_or_default();
    let outs = host
        .output_devices()
        .map(|it| it.filter_map(|d| d.name().ok()).collect())
        .unwrap_or_default();
    (ins, outs)
}

fn pick_input(host: &cpal::Host, name: &str) -> Option<cpal::Device> {
    if !name.is_empty() {
        if let Ok(mut it) = host.input_devices() {
            if let Some(d) = it.find(|d| d.name().map(|n| n == name).unwrap_or(false)) {
                return Some(d);
            }
        }
    }
    host.default_input_device()
}

fn pick_output(host: &cpal::Host, name: &str) -> Option<cpal::Device> {
    if !name.is_empty() {
        if let Ok(mut it) = host.output_devices() {
            if let Some(d) = it.find(|d| d.name().map(|n| n == name).unwrap_or(false)) {
                return Some(d);
            }
        }
    }
    host.default_output_device()
}

pub enum AudioCmd {
    /// Пересоздать потоки (сменили устройство или устройство отвалилось).
    Restart,
    Stop,
}

pub struct DeviceChoice {
    pub input: String,
    pub output: String,
}

fn build_input(
    shared: &Arc<AudioShared>,
    name: &str,
    tx: &Sender<AudioCmd>,
) -> Result<(cpal::Stream, String), String> {
    let host = cpal::default_host();
    let dev = pick_input(&host, name).ok_or("микрофон не найден")?;
    let dev_name = dev.name().unwrap_or_default();
    let supported = dev.default_input_config().map_err(|e| format!("микрофон: {e}"))?;
    let fmt = supported.sample_format();
    let rate = supported.sample_rate().0;
    let channels = supported.channels() as usize;
    shared.stats.in_rate.store(rate, Ordering::Relaxed);

    let make = |buffer: cpal::BufferSize| -> Result<cpal::Stream, String> {
        let mut config: cpal::StreamConfig = supported.config();
        config.buffer_size = buffer;
        let mut cap = Capture::new(shared.clone(), channels, rate)?;
        let txe = tx.clone();
        let err = move |_e: cpal::StreamError| {
            let _ = txe.send(AudioCmd::Restart);
        };
        let r = match fmt {
            cpal::SampleFormat::F32 => {
                dev.build_input_stream(&config, move |d: &[f32], _: &cpal::InputCallbackInfo| cap.feed(d), err, None)
            }
            cpal::SampleFormat::I16 => {
                dev.build_input_stream(&config, move |d: &[i16], _: &cpal::InputCallbackInfo| cap.feed(d), err, None)
            }
            cpal::SampleFormat::U16 => {
                dev.build_input_stream(&config, move |d: &[u16], _: &cpal::InputCallbackInfo| cap.feed(d), err, None)
            }
            cpal::SampleFormat::I32 => {
                dev.build_input_stream(&config, move |d: &[i32], _: &cpal::InputCallbackInfo| cap.feed(d), err, None)
            }
            other => return Err(format!("формат микрофона не поддерживается: {other:?}")),
        };
        r.map_err(|e| format!("микрофон: {e}"))
    };

    // Сначала просим у Windows самый маленький буфер (10 мс), при отказе — стандартный.
    let small = cpal::BufferSize::Fixed((rate / 100).max(64));
    let stream = make(small).or_else(|_| make(cpal::BufferSize::Default))?;
    stream.play().map_err(|e| format!("микрофон: {e}"))?;
    Ok((stream, dev_name))
}

fn build_output(
    shared: &Arc<AudioShared>,
    name: &str,
    tx: &Sender<AudioCmd>,
) -> Result<(cpal::Stream, String), String> {
    let host = cpal::default_host();
    let dev = pick_output(&host, name).ok_or("устройство вывода не найдено")?;
    let dev_name = dev.name().unwrap_or_default();
    let supported = dev.default_output_config().map_err(|e| format!("вывод звука: {e}"))?;
    let fmt = supported.sample_format();
    let rate = supported.sample_rate().0;
    let channels = supported.channels() as usize;
    shared.stats.out_rate.store(rate, Ordering::Relaxed);

    let make = |buffer: cpal::BufferSize| -> Result<cpal::Stream, String> {
        let mut config: cpal::StreamConfig = supported.config();
        config.buffer_size = buffer;
        let mut mix = Mixer::new(shared.clone(), channels, rate);
        let txe = tx.clone();
        let err = move |_e: cpal::StreamError| {
            let _ = txe.send(AudioCmd::Restart);
        };
        let r = match fmt {
            cpal::SampleFormat::F32 => dev.build_output_stream(
                &config,
                move |d: &mut [f32], _: &cpal::OutputCallbackInfo| mix.fill(d),
                err,
                None,
            ),
            cpal::SampleFormat::I16 => dev.build_output_stream(
                &config,
                move |d: &mut [i16], _: &cpal::OutputCallbackInfo| mix.fill(d),
                err,
                None,
            ),
            cpal::SampleFormat::U16 => dev.build_output_stream(
                &config,
                move |d: &mut [u16], _: &cpal::OutputCallbackInfo| mix.fill(d),
                err,
                None,
            ),
            cpal::SampleFormat::I32 => dev.build_output_stream(
                &config,
                move |d: &mut [i32], _: &cpal::OutputCallbackInfo| mix.fill(d),
                err,
                None,
            ),
            other => return Err(format!("формат вывода не поддерживается: {other:?}")),
        };
        r.map_err(|e| format!("вывод звука: {e}"))
    };

    let small = cpal::BufferSize::Fixed((rate / 100).max(64));
    let stream = make(small).or_else(|_| make(cpal::BufferSize::Default))?;
    stream.play().map_err(|e| format!("вывод звука: {e}"))?;
    Ok((stream, dev_name))
}

/// Поток-владелец звуковых устройств. Потоки cpal нельзя передавать между потоками ОС,
/// поэтому они создаются и живут здесь, а управление идёт через канал команд.
pub fn spawn_audio(
    shared: Arc<AudioShared>,
    choice: Arc<Mutex<DeviceChoice>>,
) -> (Sender<AudioCmd>, std::thread::JoinHandle<()>) {
    let (tx, rx): (Sender<AudioCmd>, Receiver<AudioCmd>) = std::sync::mpsc::channel();
    let tx_ret = tx.clone();
    let handle = std::thread::Builder::new()
        .name("audio-devices".into())
        .spawn(move || {
            crate::win::set_thread_priority(crate::win::Prio::Low);
            loop {
                let (in_name, out_name) = {
                    let c = choice.lock().unwrap();
                    (c.input.clone(), c.output.clone())
                };
                let input = build_input(&shared, &in_name, &tx);
                let output = build_output(&shared, &out_name, &tx);
                let mut missing = false;
                let mut used_in = String::new();
                let mut used_out = String::new();
                let _in_stream = match input {
                    Ok((s, n)) => {
                        used_in = n;
                        Some(s)
                    }
                    Err(e) => {
                        missing = true;
                        shared.emit(AudioEvent::DeviceError(e));
                        None
                    }
                };
                let _out_stream = match output {
                    Ok((s, n)) => {
                        used_out = n;
                        Some(s)
                    }
                    Err(e) => {
                        missing = true;
                        shared.emit(AudioEvent::DeviceError(e));
                        None
                    }
                };
                shared.emit(AudioEvent::Devices { input: used_in, output: used_out });

                // Ждём команду. Если устройства нет (например, наушники отключены) — пробуем снова раз в 3 с.
                let cmd = if missing {
                    match rx.recv_timeout(Duration::from_secs(3)) {
                        Ok(c) => c,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => AudioCmd::Restart,
                        Err(_) => AudioCmd::Stop,
                    }
                } else {
                    rx.recv().unwrap_or(AudioCmd::Stop)
                };
                match cmd {
                    AudioCmd::Stop => break,
                    AudioCmd::Restart => {
                        // Сбрасываем накопившиеся повторные команды и даём устройству время появиться.
                        std::thread::sleep(Duration::from_millis(300));
                        while let Ok(c) = rx.try_recv() {
                            if matches!(c, AudioCmd::Stop) {
                                return;
                            }
                        }
                    }
                }
            }
        })
        .expect("audio thread");
    (tx_ret, handle)
}
