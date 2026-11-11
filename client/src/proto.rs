//! Сообщения управляющего канала Mumble (TCP/TLS). Только те поля, которые нужны клиенту и
//! встроенному серверу. Номера полей соответствуют Mumble.proto; неизвестные поля prost пропускает.

pub const T_VERSION: u16 = 0;
pub const T_UDPTUNNEL: u16 = 1;
pub const T_AUTHENTICATE: u16 = 2;
pub const T_PING: u16 = 3;
pub const T_REJECT: u16 = 4;
pub const T_SERVERSYNC: u16 = 5;
pub const T_CHANNELREMOVE: u16 = 6;
pub const T_CHANNELSTATE: u16 = 7;
pub const T_USERREMOVE: u16 = 8;
pub const T_USERSTATE: u16 = 9;
pub const T_BANLIST: u16 = 10;
pub const T_TEXTMESSAGE: u16 = 11;
pub const T_PERMISSIONDENIED: u16 = 12;
pub const T_ACL: u16 = 13;
pub const T_CRYPTSETUP: u16 = 15;
pub const T_PERMISSIONQUERY: u16 = 20;
pub const T_CODECVERSION: u16 = 21;
pub const T_SERVERCONFIG: u16 = 24;

/// Версия протокола 1.4.0: и клиент, и встроенный сервер используют «классический» формат
/// голосовых пакетов, одинаковый для UDP и TCP-туннеля.
pub const PROTOCOL_VERSION: u32 = (1 << 16) | (4 << 8);

#[derive(Clone, PartialEq, prost::Message)]
pub struct Version {
    #[prost(uint32, optional, tag = "1")]
    pub version_v1: Option<u32>,
    #[prost(string, optional, tag = "2")]
    pub release: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub os: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub os_version: Option<String>,
    #[prost(uint64, optional, tag = "5")]
    pub version_v2: Option<u64>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Authenticate {
    #[prost(string, optional, tag = "1")]
    pub username: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub password: Option<String>,
    #[prost(bool, optional, tag = "5")]
    pub opus: Option<bool>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Ping {
    #[prost(uint64, optional, tag = "1")]
    pub timestamp: Option<u64>,
    #[prost(uint32, optional, tag = "2")]
    pub good: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub late: Option<u32>,
    #[prost(uint32, optional, tag = "4")]
    pub lost: Option<u32>,
    #[prost(uint32, optional, tag = "5")]
    pub resync: Option<u32>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Reject {
    /// Поле `type` в Mumble.proto.
    #[prost(int32, optional, tag = "1")]
    pub kind: Option<i32>,
    #[prost(string, optional, tag = "2")]
    pub reason: Option<String>,
}

/// Значения `Reject.kind`.
pub const REJECT_INVALID_USERNAME: i32 = 2;
pub const REJECT_WRONG_USER_PW: i32 = 3;
pub const REJECT_WRONG_SERVER_PW: i32 = 4;
pub const REJECT_USERNAME_IN_USE: i32 = 5;
pub const REJECT_SERVER_FULL: i32 = 6;

#[derive(Clone, PartialEq, prost::Message)]
pub struct ServerSync {
    #[prost(uint32, optional, tag = "1")]
    pub session: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub max_bandwidth: Option<u32>,
    #[prost(string, optional, tag = "3")]
    pub welcome_text: Option<String>,
    #[prost(uint64, optional, tag = "4")]
    pub permissions: Option<u64>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ChannelState {
    #[prost(uint32, optional, tag = "1")]
    pub channel_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub parent: Option<u32>,
    #[prost(string, optional, tag = "3")]
    pub name: Option<String>,
    #[prost(int32, optional, tag = "9")]
    pub position: Option<i32>,
    #[prost(uint32, optional, tag = "11")]
    pub max_users: Option<u32>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct UserRemove {
    #[prost(uint32, required, tag = "1")]
    pub session: u32,
    #[prost(uint32, optional, tag = "2")]
    pub actor: Option<u32>,
    #[prost(string, optional, tag = "3")]
    pub reason: Option<String>,
    #[prost(bool, optional, tag = "4")]
    pub ban: Option<bool>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct UserState {
    #[prost(uint32, optional, tag = "1")]
    pub session: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub actor: Option<u32>,
    #[prost(string, optional, tag = "3")]
    pub name: Option<String>,
    #[prost(uint32, optional, tag = "5")]
    pub channel_id: Option<u32>,
    #[prost(bool, optional, tag = "6")]
    pub mute: Option<bool>,
    #[prost(bool, optional, tag = "7")]
    pub deaf: Option<bool>,
    #[prost(bool, optional, tag = "8")]
    pub suppress: Option<bool>,
    #[prost(bool, optional, tag = "9")]
    pub self_mute: Option<bool>,
    #[prost(bool, optional, tag = "10")]
    pub self_deaf: Option<bool>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct TextMessage {
    #[prost(uint32, optional, tag = "1")]
    pub actor: Option<u32>,
    #[prost(uint32, repeated, packed = "false", tag = "2")]
    pub session: Vec<u32>,
    #[prost(uint32, repeated, packed = "false", tag = "3")]
    pub channel_id: Vec<u32>,
    #[prost(uint32, repeated, packed = "false", tag = "4")]
    pub tree_id: Vec<u32>,
    #[prost(string, required, tag = "5")]
    pub message: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PermissionDenied {
    #[prost(uint32, optional, tag = "1")]
    pub permission: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub channel_id: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub session: Option<u32>,
    #[prost(string, optional, tag = "4")]
    pub reason: Option<String>,
    #[prost(int32, optional, tag = "5")]
    pub kind: Option<i32>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CryptSetup {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub client_nonce: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub server_nonce: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PermissionQuery {
    #[prost(uint32, optional, tag = "1")]
    pub channel_id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub permissions: Option<u32>,
    #[prost(bool, optional, tag = "3")]
    pub flush: Option<bool>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CodecVersion {
    #[prost(int32, required, tag = "1")]
    pub alpha: i32,
    #[prost(int32, required, tag = "2")]
    pub beta: i32,
    #[prost(bool, required, tag = "3")]
    pub prefer_alpha: bool,
    #[prost(bool, optional, tag = "4")]
    pub opus: Option<bool>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ServerConfig {
    #[prost(uint32, optional, tag = "1")]
    pub max_bandwidth: Option<u32>,
    #[prost(string, optional, tag = "2")]
    pub welcome_text: Option<String>,
    #[prost(bool, optional, tag = "3")]
    pub allow_html: Option<bool>,
    #[prost(uint32, optional, tag = "4")]
    pub message_length: Option<u32>,
    #[prost(uint32, optional, tag = "5")]
    pub image_message_length: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    pub max_users: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn required_fields_roundtrip() {
        let c = CodecVersion { alpha: 0x8000_000Bu32 as i32, beta: 0, prefer_alpha: true, opus: Some(true) };
        let d = CodecVersion::decode(c.encode_to_vec().as_slice()).unwrap();
        assert_eq!(c, d);
        // Поля required кодируются и с нулевыми значениями (официальные клиенты их ждут).
        let r = UserRemove { session: 0, ..Default::default() }.encode_to_vec();
        assert!(!r.is_empty());
        let t = TextMessage { actor: Some(3), channel_id: vec![0], message: "привет".into(), ..Default::default() };
        assert_eq!(TextMessage::decode(t.encode_to_vec().as_slice()).unwrap(), t);
    }
}
