//! Перенос настроек со старого сервера (Mumble Server из версии 0.2): порт, пароль, число мест,
//! приветствие из `%APPDATA%\Raciya\server\mumble-server.ini`. Сам файл остаётся резервной копией.

use std::path::Path;

#[derive(Debug, Default, PartialEq)]
pub struct Imported {
    pub port: Option<u16>,
    pub password: Option<String>,
    pub max_users: Option<u32>,
    pub welcome: Option<String>,
}

/// Значение в формате QSettings: может быть в кавычках, внутри — `\"` и `\\`.
fn unquote(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        let inner = &v[1..v.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some(other) => out.push(other),
                    None => {}
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        v.to_string()
    }
}

pub fn parse_ini(text: &str) -> Imported {
    let mut out = Imported::default();
    for line in text.lines() {
        let line = line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let value = unquote(v);
        match k.trim().to_ascii_lowercase().as_str() {
            "port" => out.port = value.parse().ok(),
            "serverpassword" => out.password = Some(value),
            "users" => out.max_users = value.parse().ok(),
            "welcometext" => out.welcome = Some(value),
            _ => {}
        }
    }
    out
}

pub fn read_mumble_ini(path: &Path) -> Option<Imported> {
    let text = std::fs::read_to_string(path).ok()?;
    Some(parse_ini(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mumble_ini() {
        let text = "\u{feff}; комментарий\r\ndatabase=C:/x.sqlite\r\nport=64738\r\nserverpassword=секрет; с точкой\r\nusers=10\r\nwelcometext=\"Добро пожаловать! \\\"Привет\\\"\"\r\n[Ice]\r\nfoo=bar\r\n";
        let i = parse_ini(text);
        assert_eq!(i.port, Some(64738));
        assert_eq!(i.password.as_deref(), Some("секрет; с точкой"));
        assert_eq!(i.max_users, Some(10));
        assert_eq!(i.welcome.as_deref(), Some("Добро пожаловать! \"Привет\""));
        assert_eq!(parse_ini("serverpassword=\r\n").password.as_deref(), Some(""));
    }
}
