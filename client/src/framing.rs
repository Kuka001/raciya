//! Кадры управляющего канала Mumble: тип (u16, BE) + длина (u32, BE) + данные.
//! Общие для клиента (`net.rs`) и встроенного сервера.

use prost::Message;

pub const HEADER: usize = 6;

pub fn frame(ty: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn frame_msg<M: Message>(ty: u16, msg: &M) -> Vec<u8> {
    let len = msg.encoded_len();
    let mut out = Vec::with_capacity(HEADER + len);
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&(len as u32).to_be_bytes());
    // Запись в Vec не может завершиться ошибкой.
    let _ = msg.encode(&mut out);
    out
}

/// Собирает сообщения из потока байтов. Сообщения длиннее `limit` считаются ошибкой
/// (защита от того, что собеседник объявит гигантскую длину и заставит копить память).
pub struct Deframer {
    buf: Vec<u8>,
    pos: usize,
    limit: usize,
}

impl Deframer {
    pub fn new(limit: usize) -> Self {
        Deframer { buf: Vec::with_capacity(8 * 1024), pos: 0, limit }
    }

    pub fn push(&mut self, data: &[u8]) {
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos >= 32 * 1024 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// Следующее целое сообщение: `Ok(None)` — данных пока не хватает,
    /// `Err(len)` — объявлена недопустимая длина.
    pub fn next(&mut self) -> Result<Option<(u16, &[u8])>, usize> {
        let avail = &self.buf[self.pos..];
        if avail.len() < HEADER {
            return Ok(None);
        }
        let ty = u16::from_be_bytes([avail[0], avail[1]]);
        let len = u32::from_be_bytes([avail[2], avail[3], avail[4], avail[5]]) as usize;
        if len > self.limit {
            return Err(len);
        }
        if avail.len() < HEADER + len {
            return Ok(None);
        }
        let start = self.pos + HEADER;
        self.pos = start + len;
        Ok(Some((ty, &self.buf[start..start + len])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_joined_frames() {
        let mut stream = frame(3, b"abc");
        stream.extend(frame(9, b""));
        stream.extend(frame(1, &[7u8; 1000]));
        let mut d = Deframer::new(4096);
        let mut got = Vec::new();
        // Подаём по одному байту: сообщения должны собираться через границы порций.
        for b in &stream {
            d.push(std::slice::from_ref(b));
            while let Some((ty, body)) = d.next().unwrap() {
                got.push((ty, body.to_vec()));
            }
        }
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], (3, b"abc".to_vec()));
        assert_eq!(got[1], (9, Vec::new()));
        assert_eq!(got[2], (1, vec![7u8; 1000]));
    }

    #[test]
    fn oversized_is_rejected() {
        let mut d = Deframer::new(100);
        d.push(&frame(1, &[0u8; 101]));
        assert_eq!(d.next(), Err(101));
    }

    #[test]
    fn frame_msg_matches_manual() {
        let p = crate::proto::Ping { timestamp: Some(42), ..Default::default() };
        assert_eq!(frame_msg(3, &p), frame(3, &p.encode_to_vec()));
    }
}
