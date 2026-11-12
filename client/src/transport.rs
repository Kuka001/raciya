//! Транспорт протокола: поток (по нему идёт TLS с управляющими сообщениями)
//! и датаграммы (зашифрованный голос).
//!
//! Классический путь — TCP + UDP. P2P-путь (`p2p::Flow`) — один UDP-поток через пробитый NAT:
//! надёжный поток и датаграммы внутри него.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, UdpSocket};
use std::time::Duration;

pub trait Stream: Send + Sync + 'static {
    /// Читает доступные данные; `Ok(0)` — поток закрыт; TimedOut/WouldBlock — истёк тайм-аут.
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn send_all(&self, buf: &[u8]) -> io::Result<()>;
    fn set_timeout(&self, t: Duration);
    fn close(&self);
}

pub trait Datagrams: Send + Sync + 'static {
    fn send(&self, buf: &[u8]) -> io::Result<()>;
    /// Ждёт пакет не дольше полусекунды; TimedOut/WouldBlock — пакета не было.
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
}

impl Stream for TcpStream {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self).read(buf)
    }

    fn send_all(&self, buf: &[u8]) -> io::Result<()> {
        (&*self).write_all(buf)
    }

    fn set_timeout(&self, t: Duration) {
        let _ = self.set_read_timeout(Some(t));
    }

    fn close(&self) {
        let _ = self.shutdown(Shutdown::Both);
    }
}

/// UDP-сокет, соединённый с сервером (`connect`), с тайм-аутом чтения.
impl Datagrams for UdpSocket {
    fn send(&self, buf: &[u8]) -> io::Result<()> {
        UdpSocket::send(self, buf).map(|_| ())
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        UdpSocket::recv(self, buf)
    }
}

/// `io::Write` поверх потока — для `rustls::write_tls`.
pub struct StreamWriter<'a>(pub &'a dyn Stream);

impl Write for StreamWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.send_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
