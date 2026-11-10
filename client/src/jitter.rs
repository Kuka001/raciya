//! Адаптивный джиттер-буфер на одного говорящего.
//!
//! Идея: держать в запасе минимум пакетов. Если пакет не успел — воспроизведение на один кадр
//! «замирает» (заполняется маскировкой потерь), и задержка сама вырастает ровно настолько,
//! насколько нужно. Если несколько секунд подряд в буфере стабильно лежит лишнее —
//! один кадр выбрасывается, и задержка уменьшается.

use std::collections::BTreeMap;

/// Сколько вызовов `pop` подряд ждём опоздавший пакет, прежде чем считать, что речь закончилась.
const MAX_STALL: u32 = 6;
/// Окно наблюдения для уменьшения задержки (в вызовах `pop`, т.е. в кадрах по 10 мс).
const TRIM_WINDOW: u32 = 200;
/// Максимум пакетов в буфере (защита от разрастания).
const MAX_QUEUED: usize = 50;

pub enum Pop {
    /// Очередной пакет Opus.
    Frame(Vec<u8>),
    /// Пакет потерян или опаздывает: нужно сгенерировать маскировку (PLC).
    Lost,
    /// Пользователь сейчас не говорит.
    Idle,
}

pub struct Jitter {
    queue: BTreeMap<u64, (Vec<u8>, bool)>,
    next_seq: u64,
    span: u64,
    active: bool,
    prefill: bool,
    prefill_wait: u32,
    stall: u32,
    win_count: u32,
    win_min_depth: usize,
    win_underrun: bool,
    /// Запас в пакетах, который стараемся держать (растёт после опозданий, медленно спадает).
    margin: usize,
    calm_windows: u32,
    pub stat_lost: u32,
    pub stat_late: u32,
    pub stat_trimmed: u32,
}

impl Default for Jitter {
    fn default() -> Self {
        Self::new()
    }
}

impl Jitter {
    pub fn new() -> Self {
        Jitter {
            queue: BTreeMap::new(),
            next_seq: 0,
            span: 1,
            active: false,
            prefill: false,
            prefill_wait: 0,
            stall: 0,
            win_count: 0,
            win_min_depth: usize::MAX,
            win_underrun: false,
            margin: 1,
            calm_windows: 0,
            stat_lost: 0,
            stat_late: 0,
            stat_trimmed: 0,
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Текущая глубина буфера в пакетах.
    pub fn depth(&self) -> usize {
        self.queue.len()
    }

    pub fn margin(&self) -> usize {
        self.margin
    }

    pub fn push(&mut self, seq: u64, data: Vec<u8>, last: bool) {
        if self.active {
            // Счётчик у отправителя сбросился (новая сессия записи) — начинаем заново.
            if seq + 200 < self.next_seq || seq > self.next_seq + 2000 {
                self.reset();
            }
        }
        if !self.active {
            #[cfg(not(test))]
            if crate::win::trace_level() > 0 {
                eprintln!("jitter: spurt start seq={seq} last={last}");
            }
            self.active = true;
            self.prefill = true;
            self.prefill_wait = 0;
            self.stall = 0;
            self.next_seq = seq;
            self.queue.clear();
            // Окно наблюдения не сбрасываем: короткие фразы накапливаются в одно окно,
            // а подобранный запас сохраняется между фразами.
        } else if seq < self.next_seq {
            // Пакет опоздал: его место уже заполнено маскировкой.
            self.stat_late += 1;
            return;
        }
        if self.queue.len() >= MAX_QUEUED {
            // Воспроизведение остановлено или сильно отстаёт: сбрасываем самый старый пакет.
            if let Some((&first, _)) = self.queue.iter().next() {
                self.queue.remove(&first);
                self.next_seq = self.queue.keys().next().copied().unwrap_or(seq);
            }
        }
        self.queue.insert(seq, (data, last));
    }

    /// После декодирования пакета: сколько кадров по 10 мс в нём было.
    pub fn set_span(&mut self, frames: u64, seq_of_frame: u64) {
        let frames = frames.clamp(1, 12);
        self.span = frames;
        self.next_seq = seq_of_frame + frames;
    }

    pub fn reset(&mut self) {
        self.active = false;
        self.queue.clear();
        self.stall = 0;
    }

    /// Вызывается, когда микшеру нужен следующий пакет этого пользователя.
    /// Возвращает пакет и его номер (номер нужен для `set_span`).
    pub fn pop(&mut self) -> (Pop, u64) {
        if !self.active {
            return (Pop::Idle, 0);
        }

        if self.prefill {
            // В начале фразы ждём, пока накопится запас (но не дольше нескольких кадров).
            self.prefill_wait += 1;
            if self.queue.len() > self.margin || self.prefill_wait > (self.margin as u32 + 2) {
                self.prefill = false;
            } else {
                return (Pop::Idle, 0);
            }
        }

        let depth = self.queue.len();
        self.win_min_depth = self.win_min_depth.min(depth);
        self.win_count += 1;

        // Пропускаем номера, которые уже неактуальны (например, после set_span).
        while let Some((&first, _)) = self.queue.iter().next() {
            if first < self.next_seq {
                self.queue.remove(&first);
            } else {
                break;
            }
        }

        let result = if let Some((data, last)) = self.queue.remove(&self.next_seq) {
            let seq = self.next_seq;
            self.stall = 0;
            self.next_seq = seq + self.span;
            if last {
                // Конец фразы: следующая начнётся с нового предзаполнения.
                self.active = false;
                self.queue.clear();
            }
            (Pop::Frame(data), seq)
        } else if !self.queue.is_empty() {
            // Следующие пакеты уже есть, а нужного нет — он потерян.
            self.stat_lost += 1;
            #[cfg(not(test))]
            if crate::win::trace_level() > 0 {
                eprintln!("jitter: lost seq={} queued={:?} span={}", self.next_seq, self.queue.keys().collect::<Vec<_>>(), self.span);
            }
            self.stall = 0;
            let seq = self.next_seq;
            self.next_seq += self.span;
            (Pop::Lost, seq)
        } else {
            // Буфер пуст: пакет опаздывает. Ждём его, не сдвигая номер.
            self.stall += 1;
            if self.stall == 1 && !self.win_underrun {
                // Запас оказался мал — сразу увеличиваем его для следующих фраз.
                self.margin = (self.margin + 1).min(6);
                self.calm_windows = 0;
            }
            self.win_underrun = true;
            if self.stall > MAX_STALL {
                self.active = false;
                self.stall = 0;
                return (Pop::Idle, 0);
            }
            (Pop::Lost, u64::MAX)
        };

        if self.win_count >= TRIM_WINDOW {
            self.end_window();
        }
        result
    }

    fn end_window(&mut self) {
        if self.win_underrun {
            // Были опоздания (запас уже увеличен в момент первого из них).
            self.calm_windows = 0;
        } else {
            self.calm_windows += 1;
            // После ~30 секунд речи без единого опоздания пробуем уменьшить запас.
            if self.calm_windows >= 15 && self.margin > 1 {
                self.margin -= 1;
                self.calm_windows = 0;
            }
            // В буфере стабильно лежало лишнее — выбрасываем один пакет, задержка падает на 10 мс.
            if self.win_min_depth != usize::MAX && self.win_min_depth > self.margin + 1 {
                if let Some((&first, _)) = self.queue.iter().next() {
                    self.queue.remove(&first);
                    self.next_seq = first + self.span;
                    self.stat_trimmed += 1;
                }
            }
        }
        self.win_count = 0;
        self.win_min_depth = usize::MAX;
        self.win_underrun = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_playback() {
        let mut j = Jitter::new();
        j.push(10, vec![1], false);
        j.push(11, vec![2], false);
        assert!(matches!(j.pop().0, Pop::Frame(d) if d == vec![1]));
        j.push(12, vec![3], true);
        assert!(matches!(j.pop().0, Pop::Frame(d) if d == vec![2]));
        assert!(matches!(j.pop().0, Pop::Frame(d) if d == vec![3]));
        assert!(matches!(j.pop().0, Pop::Idle));
        assert!(!j.is_active());
    }

    #[test]
    fn loss_is_concealed() {
        let mut j = Jitter::new();
        j.push(0, vec![0], false);
        j.push(1, vec![1], false);
        j.push(3, vec![3], false);
        assert!(matches!(j.pop().0, Pop::Frame(_)));
        assert!(matches!(j.pop().0, Pop::Frame(_)));
        assert!(matches!(j.pop().0, Pop::Lost));
        assert!(matches!(j.pop().0, Pop::Frame(d) if d == vec![3]));
        assert_eq!(j.stat_lost, 1);
    }

    #[test]
    fn stall_then_resume_keeps_packet() {
        let mut j = Jitter::new();
        j.push(0, vec![0], false);
        j.push(1, vec![1], false);
        assert!(matches!(j.pop().0, Pop::Frame(_)));
        assert!(matches!(j.pop().0, Pop::Frame(_)));
        // Пакет 2 опаздывает на два кадра.
        assert!(matches!(j.pop().0, Pop::Lost));
        assert!(matches!(j.pop().0, Pop::Lost));
        j.push(2, vec![2], false);
        assert!(matches!(j.pop().0, Pop::Frame(d) if d == vec![2]));
    }

    #[test]
    fn silence_ends_spurt() {
        let mut j = Jitter::new();
        j.push(0, vec![0], false);
        j.push(1, vec![1], false);
        let _ = j.pop();
        let _ = j.pop();
        for _ in 0..MAX_STALL {
            assert!(matches!(j.pop().0, Pop::Lost));
        }
        assert!(matches!(j.pop().0, Pop::Idle));
        assert!(!j.is_active());
        // После опозданий запас увеличен и сохраняется для следующей фразы.
        assert_eq!(j.margin(), 2);
        // Новая фраза с другим номером начинается нормально: ждёт запас из трёх пакетов...
        j.push(500, vec![9], false);
        j.push(501, vec![9], false);
        assert!(matches!(j.pop().0, Pop::Idle));
        j.push(502, vec![9], false);
        assert!(matches!(j.pop().0, Pop::Frame(_)));
        assert!(matches!(j.pop().0, Pop::Frame(_)));
    }

    #[test]
    fn prefill_does_not_wait_forever() {
        let mut j = Jitter::new();
        // Одиночный пакет без продолжения всё равно будет воспроизведён через несколько кадров.
        j.push(7, vec![1], false);
        let mut got = false;
        for _ in 0..8 {
            if matches!(j.pop().0, Pop::Frame(_)) {
                got = true;
                break;
            }
        }
        assert!(got);
    }

    #[test]
    fn excess_delay_is_trimmed() {
        let mut j = Jitter::new();
        // Отправитель выдал пачку: в буфере стабильно 5 лишних пакетов.
        for s in 0..6u64 {
            j.push(s, vec![s as u8], false);
        }
        let mut seq = 6u64;
        for _ in 0..(TRIM_WINDOW * 6) {
            let _ = j.pop();
            j.push(seq, vec![0], false);
            seq += 1;
        }
        assert!(j.stat_trimmed >= 2, "trimmed {}", j.stat_trimmed);
        assert!(j.depth() <= 4);
    }
}
