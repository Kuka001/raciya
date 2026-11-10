//! Целые переменной длины в формате Mumble (не путать с protobuf varint).

pub fn write_varint(out: &mut Vec<u8>, v: u64) {
    if v < 0x80 {
        out.push(v as u8);
    } else if v < 0x4000 {
        out.push(((v >> 8) as u8) | 0x80);
        out.push(v as u8);
    } else if v < 0x20_0000 {
        out.push(((v >> 16) as u8) | 0xC0);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    } else if v < 0x1000_0000 {
        out.push(((v >> 24) as u8) | 0xE0);
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    } else if v < 0x1_0000_0000 {
        out.push(0xF0);
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        out.push(0xF4);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// Читает varint из `buf`, начиная с `*pos`; сдвигает `*pos`. `None` — если данных не хватает.
pub fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let b0 = *buf.get(*pos)? as u64;
    *pos += 1;
    let mut take = |n: usize| -> Option<u64> {
        let s = buf.get(*pos..*pos + n)?;
        *pos += n;
        Some(s.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64))
    };
    if b0 & 0x80 == 0 {
        Some(b0)
    } else if b0 & 0xC0 == 0x80 {
        Some(((b0 & 0x3F) << 8) | take(1)?)
    } else if b0 & 0xE0 == 0xC0 {
        Some(((b0 & 0x1F) << 16) | take(2)?)
    } else if b0 & 0xF0 == 0xE0 {
        Some(((b0 & 0x0F) << 24) | take(3)?)
    } else {
        match b0 & 0xFC {
            0xF0 => take(4),
            0xF4 => take(8),
            // Отрицательные значения в голосовых пакетах не встречаются; читаем и инвертируем.
            0xF8 => read_varint(buf, pos).map(|v| !v),
            _ => Some(!(b0 & 0x03)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for &v in &[
            0u64,
            1,
            0x7F,
            0x80,
            0x3FFF,
            0x4000,
            0x1F_FFFF,
            0x20_0000,
            0xFFF_FFFF,
            0x1000_0000,
            0xFFFF_FFFF,
            0x1_0000_0000,
            u64::MAX / 3,
        ] {
            let mut b = Vec::new();
            write_varint(&mut b, v);
            let mut p = 0;
            assert_eq!(read_varint(&b, &mut p), Some(v));
            assert_eq!(p, b.len());
        }
    }

    #[test]
    fn truncated() {
        let mut p = 0;
        assert_eq!(read_varint(&[0x80], &mut p), None);
    }
}
