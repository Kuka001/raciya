//! Шифрование голосовых UDP-пакетов Mumble: OCB2-AES128 (совместимо с CryptStateOCB2 сервера).

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

const BLOCK: usize = 16;

pub struct CryptState {
    cipher: Aes128,
    encrypt_iv: [u8; BLOCK],
    decrypt_iv: [u8; BLOCK],
    history: [u8; 256],
    pub good: u32,
    pub late: u32,
    pub lost: u32,
}

#[inline]
fn s2(v: u128) -> u128 {
    let carry = v >> 127;
    (v << 1) ^ (carry * 0x87)
}

#[inline]
fn s3(v: u128) -> u128 {
    v ^ s2(v)
}

impl CryptState {
    pub fn new(key: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> Option<Self> {
        if key.len() != BLOCK || client_nonce.len() != BLOCK || server_nonce.len() != BLOCK {
            return None;
        }
        let mut s = CryptState {
            cipher: Aes128::new(GenericArray::from_slice(key)),
            encrypt_iv: [0; BLOCK],
            decrypt_iv: [0; BLOCK],
            history: [0; 256],
            good: 0,
            late: 0,
            lost: 0,
        };
        s.encrypt_iv.copy_from_slice(client_nonce);
        s.decrypt_iv.copy_from_slice(server_nonce);
        Some(s)
    }

    pub fn encrypt_iv(&self) -> [u8; BLOCK] {
        self.encrypt_iv
    }

    pub fn set_decrypt_iv(&mut self, iv: &[u8]) -> bool {
        if iv.len() != BLOCK {
            return false;
        }
        self.decrypt_iv.copy_from_slice(iv);
        true
    }

    #[inline]
    fn bump_encrypt_iv(&mut self) {
        for b in self.encrypt_iv.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }

    #[inline]
    fn aes_enc(&self, v: u128) -> u128 {
        let mut b = GenericArray::from(v.to_be_bytes());
        self.cipher.encrypt_block(&mut b);
        u128::from_be_bytes(b.into())
    }

    #[inline]
    fn aes_dec(&self, v: u128) -> u128 {
        let mut b = GenericArray::from(v.to_be_bytes());
        self.cipher.decrypt_block(&mut b);
        u128::from_be_bytes(b.into())
    }

    /// Шифрует `plain` в `out`. Возвращает длину результата (`plain.len() + 4`).
    /// `out` должен быть не короче `plain.len() + 4`.
    pub fn encrypt(&mut self, plain: &[u8], out: &mut [u8]) -> usize {
        self.bump_encrypt_iv();
        // Обход ошибки Mumble Server 1.5: при включённом `allowping` сервер принимает любой пакет,
        // начинающийся с байта 1, за ping нового формата и после этого неправильно разбирает
        // расшифрованный пакет «классического» формата — пакет теряется (каждый 256-й).
        // Поэтому значение счётчика с младшим байтом 1 пропускаем: сервер видит это как
        // один «потерянный» номер и принимает следующий пакет штатно.
        if self.encrypt_iv[0] == 1 {
            self.bump_encrypt_iv();
        }
        let iv = self.encrypt_iv;
        let (head, body) = out.split_at_mut(4);
        let tag = self.ocb_encrypt(plain, &mut body[..plain.len()], &iv);
        head[0] = iv[0];
        head[1..4].copy_from_slice(&tag[..3]);
        plain.len() + 4
    }

    /// Расшифровывает `src` в `out` (`out.len() >= src.len() - 4`). `false` — пакет отброшен.
    pub fn decrypt(&mut self, src: &[u8], out: &mut [u8]) -> bool {
        if src.len() < 4 {
            return false;
        }
        let plain_len = src.len() - 4;
        let saveiv = self.decrypt_iv;
        let ivbyte = src[0];
        let mut restore = false;
        let mut late = 0i32;
        let mut lost = 0i32;
        let d0 = self.decrypt_iv[0];

        if d0.wrapping_add(1) == ivbyte {
            // Пакет пришёл по порядку.
            if ivbyte > d0 {
                self.decrypt_iv[0] = ivbyte;
            } else if ivbyte < d0 {
                self.decrypt_iv[0] = ivbyte;
                for b in self.decrypt_iv[1..].iter_mut() {
                    *b = b.wrapping_add(1);
                    if *b != 0 {
                        break;
                    }
                }
            } else {
                return false;
            }
        } else {
            // Не по порядку или повтор.
            let mut diff = ivbyte as i32 - d0 as i32;
            if diff > 128 {
                diff -= 256;
            } else if diff < -128 {
                diff += 256;
            }

            if ivbyte < d0 && diff > -30 && diff < 0 {
                // Опоздавший пакет, без переноса.
                late = 1;
                lost = -1;
                self.decrypt_iv[0] = ivbyte;
                restore = true;
            } else if ivbyte > d0 && diff > -30 && diff < 0 {
                // Опоздавший пакет из предыдущего «круга» счётчика.
                late = 1;
                lost = -1;
                self.decrypt_iv[0] = ivbyte;
                for b in self.decrypt_iv[1..].iter_mut() {
                    let old = *b;
                    *b = b.wrapping_sub(1);
                    if old != 0 {
                        break;
                    }
                }
                restore = true;
            } else if ivbyte > d0 && diff > 0 {
                // Несколько пакетов потеряно.
                lost = ivbyte as i32 - d0 as i32 - 1;
                self.decrypt_iv[0] = ivbyte;
            } else if ivbyte < d0 && diff > 0 {
                // Потеря с переносом счётчика.
                lost = 256 - d0 as i32 + ivbyte as i32 - 1;
                self.decrypt_iv[0] = ivbyte;
                for b in self.decrypt_iv[1..].iter_mut() {
                    *b = b.wrapping_add(1);
                    if *b != 0 {
                        break;
                    }
                }
            } else {
                return false;
            }

            if self.history[self.decrypt_iv[0] as usize] == self.decrypt_iv[1] {
                self.decrypt_iv = saveiv;
                return false;
            }
        }

        let iv = self.decrypt_iv;
        let (ok, tag) = self.ocb_decrypt(&src[4..], &mut out[..plain_len], &iv);
        if !ok || tag[..3] != src[1..4] {
            self.decrypt_iv = saveiv;
            return false;
        }
        self.history[self.decrypt_iv[0] as usize] = self.decrypt_iv[1];
        if restore {
            self.decrypt_iv = saveiv;
        }
        self.good = self.good.wrapping_add(1);
        self.late = self.late.wrapping_add(late as u32);
        self.lost = self.lost.wrapping_add(lost as u32);
        true
    }

    fn ocb_encrypt(&self, plain: &[u8], enc: &mut [u8], nonce: &[u8; BLOCK]) -> [u8; BLOCK] {
        let mut delta = self.aes_enc(u128::from_be_bytes(*nonce));
        let mut checksum = 0u128;
        let mut off = 0usize;
        let mut len = plain.len();

        while len > BLOCK {
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(&plain[off..off + BLOCK]);
            // Защита от атаки XEX* (как в сервере): в предпоследнем блоке меняем один бит.
            let mut flip = false;
            if len - BLOCK <= BLOCK && block[..BLOCK - 1].iter().all(|&b| b == 0) {
                flip = true;
            }
            let p = u128::from_be_bytes(block);
            delta = s2(delta);
            let mut tmp = delta ^ p;
            if flip {
                tmp ^= 1u128 << 120;
            }
            tmp = self.aes_enc(tmp);
            enc[off..off + BLOCK].copy_from_slice(&(delta ^ tmp).to_be_bytes());
            checksum ^= p;
            if flip {
                checksum ^= 1u128 << 120;
            }
            len -= BLOCK;
            off += BLOCK;
        }

        delta = s2(delta);
        let pad = self.aes_enc(((len as u128) * 8) ^ delta);
        let mut tmp = pad.to_be_bytes();
        tmp[..len].copy_from_slice(&plain[off..off + len]);
        let tmp_v = u128::from_be_bytes(tmp);
        checksum ^= tmp_v;
        let out = (pad ^ tmp_v).to_be_bytes();
        enc[off..off + len].copy_from_slice(&out[..len]);

        delta = s3(delta);
        self.aes_enc(delta ^ checksum).to_be_bytes()
    }

    fn ocb_decrypt(&self, enc: &[u8], plain: &mut [u8], nonce: &[u8; BLOCK]) -> (bool, [u8; BLOCK]) {
        let mut delta = self.aes_enc(u128::from_be_bytes(*nonce));
        let mut checksum = 0u128;
        let mut off = 0usize;
        let mut len = enc.len();

        while len > BLOCK {
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(&enc[off..off + BLOCK]);
            delta = s2(delta);
            let tmp = self.aes_dec(delta ^ u128::from_be_bytes(block));
            let p = delta ^ tmp;
            plain[off..off + BLOCK].copy_from_slice(&p.to_be_bytes());
            checksum ^= p;
            len -= BLOCK;
            off += BLOCK;
        }

        delta = s2(delta);
        let pad = self.aes_enc(((len as u128) * 8) ^ delta);
        let mut tmp = [0u8; BLOCK];
        tmp[..len].copy_from_slice(&enc[off..off + len]);
        let tmp_v = u128::from_be_bytes(tmp) ^ pad;
        checksum ^= tmp_v;
        let tmp_b = tmp_v.to_be_bytes();
        plain[off..off + len].copy_from_slice(&tmp_b[..len]);

        // Контрмера против подделки пакета (раздел 9 в https://eprint.iacr.org/2019/311).
        let ok = tmp_b[..BLOCK - 1] != delta.to_be_bytes()[..BLOCK - 1];

        delta = s3(delta);
        (ok, self.aes_enc(delta ^ checksum).to_be_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 16] {
        let mut k = [0u8; 16];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn ocb_spec_vectors() {
        // Тестовые векторы OCB-AES-128 из спецификации OCB2 (те же, что в тестах Mumble).
        let k = key();
        let cs = CryptState::new(&k, &k, &k).unwrap();

        let tag = cs.ocb_encrypt(&[], &mut [], &k);
        assert_eq!(
            tag,
            [
                0xBF, 0x31, 0x08, 0x13, 0x07, 0x73, 0xAD, 0x5E, 0xC7, 0x0E, 0xC6, 0x9E, 0x78, 0x75, 0xA7, 0xB0
            ]
        );

        let src: Vec<u8> = (0u8..40).collect();
        let mut enc = vec![0u8; 40];
        let tag = cs.ocb_encrypt(&src, &mut enc, &k);
        assert_eq!(
            enc,
            vec![
                0xF7, 0x5D, 0x6B, 0xC8, 0xB4, 0xDC, 0x8D, 0x66, 0xB8, 0x36, 0xA2, 0xB0, 0x8B, 0x32, 0xA6, 0x36, 0x9F,
                0x1C, 0xD3, 0xC5, 0x22, 0x8D, 0x79, 0xFD, 0x6C, 0x26, 0x7F, 0x5F, 0x6A, 0xA7, 0xB2, 0x31, 0xC7, 0xDF,
                0xB9, 0xD5, 0x99, 0x51, 0xAE, 0x9C
            ]
        );
        assert_eq!(
            tag,
            [
                0x9D, 0xB0, 0xCD, 0xF8, 0x80, 0xF7, 0x3E, 0x3E, 0x10, 0xD4, 0xEB, 0x32, 0x17, 0x76, 0x66, 0x88
            ]
        );
    }

    #[test]
    fn roundtrip_reorder_and_loss() {
        let k = key();
        let n1 = [7u8; 16];
        let n2 = [9u8; 16];
        let mut a = CryptState::new(&k, &n1, &n2).unwrap();
        let mut b = CryptState::new(&k, &n2, &n1).unwrap();

        let mut packets = Vec::new();
        for i in 0..600u32 {
            let msg: Vec<u8> = (0..(1 + i % 70)).map(|x| (x * 3 + i) as u8).collect();
            let mut enc = vec![0u8; msg.len() + 4];
            let n = a.encrypt(&msg, &mut enc);
            assert_eq!(n, msg.len() + 4);
            packets.push((msg, enc));
        }
        // По порядку, с потерей (каждый 50-й) и одной перестановкой.
        let mut out = vec![0u8; 128];
        let mut i = 0;
        while i < packets.len() {
            if i % 50 == 49 {
                i += 1;
                continue;
            }
            if i == 100 {
                let (m1, e1) = &packets[101];
                assert!(b.decrypt(e1, &mut out));
                assert_eq!(&out[..m1.len()], &m1[..]);
                let (m0, e0) = &packets[100];
                assert!(b.decrypt(e0, &mut out));
                assert_eq!(&out[..m0.len()], &m0[..]);
                // Повтор отвергается.
                assert!(!b.decrypt(e0, &mut out));
                i += 2;
                continue;
            }
            let (m, e) = &packets[i];
            assert!(b.decrypt(e, &mut out), "packet {i}");
            assert_eq!(&out[..m.len()], &m[..]);
            i += 1;
        }
        // Испорченный пакет отвергается.
        let (_, e) = &packets[0];
        let mut bad = e.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x55;
        assert!(!b.decrypt(&bad, &mut out));
    }
}
