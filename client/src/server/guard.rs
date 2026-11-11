//! Защита сервера от подбора пароля и от наплыва соединений с одного адреса.
//!
//! - не больше 8 одновременных соединений с одного IP (несколько друзей за одним роутером — норма);
//! - 10 неудачных входов за 2 минуты — адрес блокируется на 5 минут;
//! - удачный вход сбрасывает счётчик неудач;
//! - свой компьютер (127.0.0.1) не ограничивается.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const MAX_CONNS_PER_IP: u32 = 8;
const FAIL_LIMIT: u32 = 10;
const FAIL_WINDOW: Duration = Duration::from_secs(120);
const BAN_TIME: Duration = Duration::from_secs(300);

#[derive(Default)]
pub struct Guard {
    conns: HashMap<IpAddr, u32>,
    fails: HashMap<IpAddr, (u32, Instant)>,
    bans: HashMap<IpAddr, Instant>,
}

impl Guard {
    pub fn banned(&mut self, ip: IpAddr, now: Instant) -> bool {
        match self.bans.get(&ip) {
            Some(&until) if until > now => true,
            Some(_) => {
                self.bans.remove(&ip);
                false
            }
            None => false,
        }
    }

    /// Новое TCP-соединение: `false` — отклонить сразу.
    pub fn admit(&mut self, ip: IpAddr, now: Instant) -> bool {
        if !ip.is_loopback() {
            if self.banned(ip, now) {
                return false;
            }
            if self.conns.get(&ip).copied().unwrap_or(0) >= MAX_CONNS_PER_IP {
                return false;
            }
        }
        *self.conns.entry(ip).or_insert(0) += 1;
        true
    }

    pub fn release(&mut self, ip: IpAddr) {
        if let Some(n) = self.conns.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.conns.remove(&ip);
            }
        }
    }

    /// Неверный пароль. Возвращает `true`, если адрес только что заблокирован.
    pub fn failed(&mut self, ip: IpAddr, now: Instant) -> bool {
        if ip.is_loopback() {
            return false;
        }
        let e = self.fails.entry(ip).or_insert((0, now));
        if now.duration_since(e.1) > FAIL_WINDOW {
            *e = (0, now);
        }
        e.0 += 1;
        if e.0 >= FAIL_LIMIT {
            self.fails.remove(&ip);
            self.bans.insert(ip, now + BAN_TIME);
            return true;
        }
        false
    }

    pub fn succeeded(&mut self, ip: IpAddr) {
        self.fails.remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brute_force_is_banned() {
        let mut g = Guard::default();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let t0 = Instant::now();
        for i in 0..9 {
            assert!(!g.failed(ip, t0 + Duration::from_secs(i)));
        }
        assert!(g.failed(ip, t0 + Duration::from_secs(10)));
        assert!(!g.admit(ip, t0 + Duration::from_secs(11)));
        // Через 5 минут блокировка снимается.
        assert!(g.admit(ip, t0 + Duration::from_secs(10) + BAN_TIME + Duration::from_secs(1)));
    }

    #[test]
    fn slow_failures_and_success_reset() {
        let mut g = Guard::default();
        let ip: IpAddr = "203.0.113.6".parse().unwrap();
        let t0 = Instant::now();
        // Неудачи реже, чем 10 за 2 минуты, не приводят к блокировке.
        for i in 0..30u64 {
            assert!(!g.failed(ip, t0 + Duration::from_secs(i * 15)));
        }
        for _ in 0..9 {
            g.failed(ip, t0 + Duration::from_secs(1000));
        }
        g.succeeded(ip);
        assert!(!g.failed(ip, t0 + Duration::from_secs(1001)));
    }

    #[test]
    fn connection_limit_and_loopback() {
        let mut g = Guard::default();
        let now = Instant::now();
        let ip: IpAddr = "10.77.64.34".parse().unwrap();
        for _ in 0..MAX_CONNS_PER_IP {
            assert!(g.admit(ip, now));
        }
        assert!(!g.admit(ip, now));
        g.release(ip);
        assert!(g.admit(ip, now));
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..50 {
            assert!(g.admit(lo, now));
            assert!(!g.failed(lo, now));
        }
    }
}
