//! Bencode — формат сообщений BitTorrent DHT (BEP 3). Только то, что нужно для KRPC.

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum B {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<B>),
    Dict(BTreeMap<Vec<u8>, B>),
}

impl B {
    pub fn bytes(v: impl Into<Vec<u8>>) -> B {
        B::Bytes(v.into())
    }

    /// Словарь из пар (ключи сортируются сами — так требует формат).
    pub fn dict(items: Vec<(&str, B)>) -> B {
        B::Dict(items.into_iter().map(|(k, v)| (k.as_bytes().to_vec(), v)).collect())
    }

    pub fn get(&self, key: &str) -> Option<&B> {
        match self {
            B::Dict(d) => d.get(key.as_bytes()),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            B::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[B]> {
        match self {
            B::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            B::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            B::Int(i) => out.extend_from_slice(format!("i{i}e").as_bytes()),
            B::Bytes(b) => {
                out.extend_from_slice(b.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(b);
            }
            B::List(l) => {
                out.push(b'l');
                for x in l {
                    x.encode_into(out);
                }
                out.push(b'e');
            }
            B::Dict(d) => {
                out.push(b'd');
                for (k, v) in d {
                    out.extend_from_slice(k.len().to_string().as_bytes());
                    out.push(b':');
                    out.extend_from_slice(k);
                    v.encode_into(out);
                }
                out.push(b'e');
            }
        }
    }
}

/// Разбирает одно значение целиком (лишние байты в конце — ошибка). Глубина вложенности ограничена.
pub fn decode(data: &[u8]) -> Option<B> {
    let mut pos = 0;
    let v = parse(data, &mut pos, 0)?;
    (pos == data.len()).then_some(v)
}

fn parse(d: &[u8], pos: &mut usize, depth: u32) -> Option<B> {
    if depth > 16 {
        return None;
    }
    match *d.get(*pos)? {
        b'i' => {
            let end = d[*pos..].iter().position(|&c| c == b'e')? + *pos;
            let s = std::str::from_utf8(&d[*pos + 1..end]).ok()?;
            *pos = end + 1;
            s.parse().ok().map(B::Int)
        }
        b'l' => {
            *pos += 1;
            let mut l = Vec::new();
            while *d.get(*pos)? != b'e' {
                l.push(parse(d, pos, depth + 1)?);
            }
            *pos += 1;
            Some(B::List(l))
        }
        b'd' => {
            *pos += 1;
            let mut m = BTreeMap::new();
            while *d.get(*pos)? != b'e' {
                let B::Bytes(k) = parse_bytes(d, pos)? else { return None };
                let v = parse(d, pos, depth + 1)?;
                m.insert(k, v);
            }
            *pos += 1;
            Some(B::Dict(m))
        }
        b'0'..=b'9' => parse_bytes(d, pos),
        _ => None,
    }
}

fn parse_bytes(d: &[u8], pos: &mut usize) -> Option<B> {
    let colon = d[*pos..].iter().position(|&c| c == b':')? + *pos;
    let len: usize = std::str::from_utf8(&d[*pos..colon]).ok()?.parse().ok()?;
    let start = colon + 1;
    let end = start.checked_add(len)?;
    let bytes = d.get(start..end)?.to_vec();
    *pos = end;
    Some(B::Bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn krpc_samples() {
        // Пример из BEP 5: запрос get_peers.
        let q = b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe";
        let v = decode(q).unwrap();
        assert_eq!(v.get("q").and_then(|x| x.as_bytes()), Some(&b"get_peers"[..]));
        assert_eq!(v.get("a").and_then(|a| a.get("info_hash")).and_then(|x| x.as_bytes()).map(|b| b.len()), Some(20));
        // Кодирование даёт те же байты (ключи сортируются).
        assert_eq!(v.encode(), q.to_vec());
        // Ответ со значениями.
        let r = b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:y1:re";
        let v = decode(r).unwrap();
        let values = v.get("r").and_then(|r| r.get("values")).and_then(|x| x.as_list()).unwrap();
        assert_eq!(values.len(), 2);
        // Ошибка.
        let e = decode(b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee").unwrap();
        assert_eq!(e.get("e").and_then(|x| x.as_list()).and_then(|l| l[0].as_int()), Some(201));
    }

    #[test]
    fn garbage_is_rejected() {
        for bad in [&b""[..], b"d", b"i12", b"5:abc", b"d3:keye", b"l1:ae trailing", b"99999999999999999999:x"] {
            assert!(decode(bad).is_none(), "{:?}", String::from_utf8_lossy(bad));
        }
        let deep = "l".repeat(40) + &"e".repeat(40);
        assert!(decode(deep.as_bytes()).is_none());
    }
}
