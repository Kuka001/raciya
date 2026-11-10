//! Сообщения управляющего канала Mumble (TCP/TLS). Только те поля, которые нужны клиенту.
//! Номера полей соответствуют Mumble.proto; неизвестные поля prost пропускает.

pub const T_VERSION: u16 = 0;
pub const T_UDPTUNNEL: u16 = 1;
pub const T_AUTHENTICATE: u16 = 2;
pub const T_PING: u16 = 3;
pub const T_REJECT: u16 = 4;
pub const T_SERVERSYNC: u16 = 5;
pub const T_USERREMOVE: u16 = 8;
pub const T_USERSTATE: u16 = 9;
pub const T_PERMISSIONDENIED: u16 = 12;
pub const T_CRYPTSETUP: u16 = 15;

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
    #[prost(int32, optional, tag = "1")]
    pub kind: Option<i32>,
    #[prost(string, optional, tag = "2")]
    pub reason: Option<String>,
}

/// Значения `Reject.kind`.
pub const REJECT_WRONG_USER_PW: i32 = 3;
pub const REJECT_WRONG_SERVER_PW: i32 = 4;
pub const REJECT_INVALID_USERNAME: i32 = 2;

#[derive(Clone, PartialEq, prost::Message)]
pub struct ServerSync {
    #[prost(uint32, optional, tag = "1")]
    pub session: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub max_bandwidth: Option<u32>,
    #[prost(string, optional, tag = "3")]
    pub welcome_text: Option<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct UserRemove {
    #[prost(uint32, tag = "1")]
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
pub struct CryptSetup {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub client_nonce: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub server_nonce: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PermissionDenied {
    #[prost(string, optional, tag = "4")]
    pub reason: Option<String>,
    #[prost(int32, optional, tag = "5")]
    pub kind: Option<i32>,
}
