//! Сертификат сервера: самоподписанный ECDSA P-256, создаётся один раз и хранится в папке сервера.
//! Закрытый ключ зашифрован DPAPI (расшифровать может только этот пользователь Windows).

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::path::Path;
use std::sync::Arc;

const CERT_FILE: &str = "tls-cert.der";
const KEY_FILE: &str = "tls-key.bin";

pub struct Identity {
    pub cert: Vec<u8>,
    key: Vec<u8>,
}

impl Identity {
    /// SHA-256 сертификата (hex) — по нему клиенты узнают «свой» сервер.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.cert)
    }
}

pub fn fingerprint(cert_der: &[u8]) -> String {
    crate::win::to_hex(ring::digest::digest(&ring::digest::SHA256, cert_der).as_ref())
}

pub fn load_or_create(dir: &Path) -> Result<Identity, String> {
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);
    if let (Ok(cert), Ok(enc)) = (std::fs::read(&cert_path), std::fs::read(&key_path)) {
        if let Some(key) = crate::win::unprotect_bytes(&enc) {
            if !cert.is_empty() && !key.is_empty() {
                return Ok(Identity { cert, key });
            }
        }
    }
    let made = rcgen::generate_simple_self_signed(vec!["raciya".to_string()])
        .map_err(|e| format!("не удалось создать сертификат: {e}"))?;
    let cert = made.cert.der().to_vec();
    let key = made.key_pair.serialize_der();
    let enc = crate::win::protect_bytes(&key).ok_or("не удалось защитить ключ сертификата")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("папка сервера: {e}"))?;
    std::fs::write(&cert_path, &cert).map_err(|e| format!("сертификат: {e}"))?;
    std::fs::write(&key_path, &enc).map_err(|e| format!("ключ сертификата: {e}"))?;
    slog!("создан новый сертификат сервера, отпечаток {}", fingerprint(&cert));
    Ok(Identity { cert, key })
}

pub fn server_config(id: &Identity) -> Result<Arc<rustls::ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(id.cert.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key.clone())),
        )
        .map_err(|e| format!("сертификат сервера: {e}"))?;
    Ok(Arc::new(cfg))
}
