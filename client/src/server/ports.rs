//! Порты сервера и резервирование портов Windows.
//!
//! Hyper-V, WSL и Docker при каждом старте Windows резервируют случайные диапазоны портов
//! в динамической области (обычно 49152–65535). Порт внутри такого диапазона занять нельзя:
//! `bind` возвращает WSAEACCES («The address is protected»). Административное исключение
//! (`netsh int ipv4 add excludedportrange ...`, его ставит режим `server` системной настройки)
//! закрепляет порт: Hyper-V его больше не трогает, а сервер занимать может.

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Range {
    pub start: u16,
    pub end: u16,
    /// Исключение добавлено администратором (отмечено `*` в выводе netsh).
    pub administered: bool,
}

impl Range {
    pub fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

/// Разбирает вывод `netsh int ipv4 show excludedportrange protocol=...`.
/// Заголовки бывают на любом языке, а строки диапазонов — всегда два числа и, возможно, `*`.
pub fn parse_excluded(text: &str) -> Vec<Range> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 2 || t.len() > 3 {
            continue;
        }
        let (Ok(start), Ok(end)) = (t[0].parse::<u16>(), t[1].parse::<u16>()) else { continue };
        if t.len() == 3 && t[2] != "*" {
            continue;
        }
        out.push(Range { start, end, administered: t.len() == 3 });
    }
    out
}

/// Разбирает вывод `netsh int ipv4 show dynamicport tcp`: (первый порт, число портов).
pub fn parse_dynamic(text: &str) -> Option<(u16, u32)> {
    let mut nums = text
        .lines()
        .filter_map(|l| l.split_once(':').map(|(_, v)| v.trim()))
        .filter_map(|v| v.parse::<u32>().ok());
    let start = nums.next()?;
    let count = nums.next()?;
    Some((u16::try_from(start).ok()?, count))
}

pub fn excluded(proto: &str) -> Vec<Range> {
    let arg = format!("protocol={proto}");
    crate::win::run_capture("netsh", &["int", "ipv4", "show", "excludedportrange", &arg])
        .map(|t| parse_excluded(&t))
        .unwrap_or_default()
}

pub fn dynamic(proto: &str) -> (u16, u32) {
    crate::win::run_capture("netsh", &["int", "ipv4", "show", "dynamicport", proto])
        .and_then(|t| parse_dynamic(&t))
        .unwrap_or((49152, 16384))
}

/// Состояние порта с точки зрения резервирований Windows.
#[derive(Clone, Debug, PartialEq)]
pub struct PortState {
    /// Диапазон, который сейчас держит Windows (без административного исключения).
    pub reserved: Option<Range>,
    /// На порт есть административные исключения TCP и UDP.
    pub pinned: bool,
    /// Порт в динамической области: после перезагрузки его может занять Hyper-V.
    pub in_dynamic: bool,
}

impl PortState {
    /// Нужна ли системная настройка, чтобы порт не «пропадал» после перезагрузок.
    pub fn at_risk(&self) -> bool {
        self.reserved.is_some() || (self.in_dynamic && !self.pinned)
    }
}

pub fn evaluate(port: u16, tcp: &[Range], udp: &[Range], dynamic: (u16, u32)) -> PortState {
    let reserved = tcp
        .iter()
        .chain(udp.iter())
        .find(|r| !r.administered && r.contains(port))
        .copied();
    let pinned = tcp.iter().any(|r| r.administered && r.contains(port))
        && udp.iter().any(|r| r.administered && r.contains(port));
    let (start, count) = dynamic;
    let in_dynamic = (port as u32) >= start as u32 && (port as u32) < start as u32 + count;
    PortState { reserved, pinned, in_dynamic }
}

/// Полная проверка порта (запускает netsh три раза — вызывать из фонового потока).
pub fn state(port: u16) -> PortState {
    evaluate(port, &excluded("tcp"), &excluded("udp"), dynamic("tcp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Настоящий вывод netsh с этого ПК 2026-11-11 (до починки).
    const SAMPLE: &str = "\r\nProtocol tcp Port Exclusion Ranges\r\n\r\nStart Port    End Port      \r\n----------    --------      \r\n     49671       49770      \r\n     50000       50059     *\r\n     64686       64785      \r\n\r\n* - Administered port exclusions.\r\n";

    #[test]
    fn excluded_ranges() {
        let r = parse_excluded(SAMPLE);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0], Range { start: 49671, end: 49770, administered: false });
        assert_eq!(r[1], Range { start: 50000, end: 50059, administered: true });
        assert!(r[2].contains(64738) && !r[2].administered);
    }

    #[test]
    fn dynamic_range_any_language() {
        let ru = "\r\nПротокол tcp Диапазон динамических портов\r\n---------------------------------\r\nНачальный порт      : 49152\r\nЧисло портов        : 16384\r\n";
        assert_eq!(parse_dynamic(ru), Some((49152, 16384)));
        let en = "Protocol tcp Dynamic Port Range\n---------------------------------\nStart Port      : 1025\nNumber of Ports : 64511\n";
        assert_eq!(parse_dynamic(en), Some((1025, 64511)));
    }

    #[test]
    fn port_state() {
        let dynamic = (49152, 16384);
        // Как было: порт внутри диапазона Hyper-V.
        let broken = evaluate(64738, &parse_excluded(SAMPLE), &[], dynamic);
        assert_eq!(broken.reserved.map(|r| r.start), Some(64686));
        assert!(broken.at_risk());
        // Как стало: административные исключения TCP и UDP.
        let pin = vec![Range { start: 64738, end: 64738, administered: true }];
        let fixed = evaluate(64738, &pin, &pin, dynamic);
        assert!(fixed.pinned && fixed.in_dynamic && fixed.reserved.is_none());
        assert!(!fixed.at_risk());
        // Свободный порт в динамической области — риск после перезагрузки.
        let risky = evaluate(60000, &[], &[], dynamic);
        assert!(risky.at_risk() && risky.reserved.is_none());
        // Порт вне динамической области не трогает никто.
        assert!(!evaluate(40738, &[], &[], dynamic).at_risk());
    }
}
