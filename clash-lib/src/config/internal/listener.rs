use crate::common::utils::default_bool_true;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::{HashMap, HashSet};
#[cfg(feature = "shadowquic")]
use std::hash::Hash;

#[cfg(feature = "shadowquic")]
use shadowquic::config::CongestionControl as SQCongestionControl;

use super::config::BindAddress;

/// A single user entry for SS2022 multi-user inbound.
/// `name` is stored in session metadata as `inboundUser` for traffic
/// attribution. `password` is a base64-encoded 32-byte key (for
/// 2022-blake3-aes-256-gcm).
#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
pub struct InboundUser {
    pub name: String,
    pub password: String,
}

#[cfg(feature = "shadowquic")]
#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct ShadowQuicInboundUser {
    pub username: String,
    pub password: String,
}

#[cfg(feature = "shadowquic")]
#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct ShadowQuicJlsUpstream {
    pub addr: String,
    #[serde(default)]
    pub rate_limit: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct VlessInboundUser {
    pub uuid: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct VlessInboundTransport {
    #[serde(rename = "type")]
    pub typ: String,
    pub path: String,
    #[serde(
        default,
        alias = "early_data_header_name",
        alias = "early-data-header-name"
    )]
    pub early_data_header_name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum InboundOpts {
    #[serde(alias = "http")]
    Http {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
    },
    #[serde(alias = "socks")]
    Socks {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default = "default_bool_true")]
        udp: bool,
    },
    #[serde(alias = "mixed")]
    Mixed {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default = "default_bool_true")]
        udp: bool, // TODO users
    },
    #[cfg(feature = "tproxy")]
    #[serde(alias = "tproxy")]
    TProxy {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default = "default_bool_true")]
        udp: bool,
    },
    #[cfg(feature = "redir")]
    #[serde(alias = "redir")]
    Redir {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
    },
    #[serde(alias = "tunnel")]
    Tunnel {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        network: Vec<String>,
        target: String,
    },
    #[cfg(feature = "shadowsocks")]
    #[serde(alias = "shadowsocks")]
    Shadowsocks {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default = "default_bool_true")]
        udp: bool,
        cipher: String,
        password: String,
        /// Multi-user list for SS2022 EIH. Each entry has a name (FAC user_id)
        /// and a base64-encoded 32-byte user key. When non-empty, EIH is used
        /// to identify which user owns each connection.
        #[serde(default)]
        users: Vec<InboundUser>,
    },
    #[serde(alias = "anytls")]
    Anytls {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        password: String,
        /// File path or inline PEM certificate chain. When absent, an
        /// ephemeral self-signed certificate is generated at startup.
        #[serde(default)]
        certificate: Option<String>,
        /// File path or inline PEM private key. When absent, an ephemeral
        /// self-signed certificate is generated at startup.
        #[serde(rename = "private-key", default)]
        private_key: Option<String>,
        /// Optional multi-user list. When empty, `password` is used directly
        /// (single-user mode). Each entry uses the plaintext password field.
        #[serde(default)]
        users: Vec<InboundUser>,
        /// Optional fallback address (`host:port`) to which unauthenticated
        /// connections are forwarded, providing camouflage against active
        /// probing. When absent, unauthenticated connections are
        /// silently dropped.
        #[serde(default)]
        fallback: Option<String>,
    },
    #[serde(alias = "vless")]
    Vless {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default)]
        uuid: Option<String>,
        #[serde(default)]
        users: Vec<VlessInboundUser>,
        transport: VlessInboundTransport,
    },
    #[cfg(feature = "shadowquic")]
    #[serde(alias = "shadowquic")]
    ShadowQuic {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        users: Vec<ShadowQuicInboundUser>,
        #[serde(default)]
        server_name: Option<String>,
        jls_upstream: ShadowQuicJlsUpstream,
        #[serde(default)]
        alpn: Option<Vec<String>>,
        #[serde(default)]
        zero_rtt: Option<bool>,
        #[serde(default)]
        congestion_control: Option<SQCongestionControl>,
        #[serde(default)]
        initial_mtu: Option<u16>,
        #[serde(default)]
        min_mtu: Option<u16>,
        #[serde(default)]
        gso: Option<bool>,
        #[serde(default)]
        mtu_discovery: Option<bool>,
        #[serde(default)]
        blackhole_detection: Option<bool>,
    },
}

#[cfg(feature = "shadowquic")]
fn debug_eq<T: std::fmt::Debug>(a: &Option<T>, b: &Option<T>) -> bool {
    format!("{a:?}") == format!("{b:?}")
}

#[cfg(feature = "shadowquic")]
fn debug_hash<T: std::fmt::Debug, H: std::hash::Hasher>(
    value: &Option<T>,
    state: &mut H,
) {
    format!("{value:?}").hash(state);
}

/// Equality and hashing for `InboundOpts` intentionally exclude the `users`
/// field of the `Shadowsocks` variant so that a change to the user list
/// does not cause a full listener restart. All structural parameters
/// (address, port, cipher, server password) are still compared.
impl PartialEq for InboundOpts {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                InboundOpts::Http { common_opts: a },
                InboundOpts::Http { common_opts: b },
            ) => a == b,
            (
                InboundOpts::Socks {
                    common_opts: a,
                    udp: ua,
                },
                InboundOpts::Socks {
                    common_opts: b,
                    udp: ub,
                },
            ) => a == b && ua == ub,
            (
                InboundOpts::Mixed {
                    common_opts: a,
                    udp: ua,
                },
                InboundOpts::Mixed {
                    common_opts: b,
                    udp: ub,
                },
            ) => a == b && ua == ub,
            #[cfg(feature = "tproxy")]
            (
                InboundOpts::TProxy {
                    common_opts: a,
                    udp: ua,
                },
                InboundOpts::TProxy {
                    common_opts: b,
                    udp: ub,
                },
            ) => a == b && ua == ub,
            #[cfg(feature = "redir")]
            (
                InboundOpts::Redir { common_opts: a },
                InboundOpts::Redir { common_opts: b },
            ) => a == b,
            (
                InboundOpts::Tunnel {
                    common_opts: a,
                    network: na,
                    target: ta,
                },
                InboundOpts::Tunnel {
                    common_opts: b,
                    network: nb,
                    target: tb,
                },
            ) => a == b && na == nb && ta == tb,
            #[cfg(feature = "shadowsocks")]
            (
                InboundOpts::Shadowsocks {
                    common_opts: a,
                    udp: ua,
                    cipher: ca,
                    password: pa,
                    ..
                },
                InboundOpts::Shadowsocks {
                    common_opts: b,
                    udp: ub,
                    cipher: cb,
                    password: pb,
                    ..
                },
            ) => a == b && ua == ub && ca == cb && pa == pb,
            (
                InboundOpts::Anytls {
                    common_opts: a,
                    password: pa,
                    certificate: ca,
                    private_key: pka,
                    fallback: fa,
                    ..
                },
                InboundOpts::Anytls {
                    common_opts: b,
                    password: pb,
                    certificate: cb,
                    private_key: pkb,
                    fallback: fb,
                    ..
                },
            ) => a == b && pa == pb && ca == cb && pka == pkb && fa == fb,
            (
                InboundOpts::Vless {
                    common_opts: a,
                    uuid: ua,
                    users: users_a,
                    transport: ta,
                },
                InboundOpts::Vless {
                    common_opts: b,
                    uuid: ub,
                    users: users_b,
                    transport: tb,
                },
            ) => a == b && ua == ub && users_a == users_b && ta == tb,
            #[cfg(feature = "shadowquic")]
            (
                InboundOpts::ShadowQuic {
                    common_opts: a,
                    username: ua,
                    password: pa,
                    users: users_a,
                    server_name: sna,
                    jls_upstream: jlsa,
                    alpn: alpna,
                    zero_rtt: zra,
                    congestion_control: cca,
                    initial_mtu: ima,
                    min_mtu: mma,
                    gso: gsoa,
                    mtu_discovery: mda,
                    blackhole_detection: bha,
                },
                InboundOpts::ShadowQuic {
                    common_opts: b,
                    username: ub,
                    password: pb,
                    users: users_b,
                    server_name: snb,
                    jls_upstream: jlsb,
                    alpn: alpnb,
                    zero_rtt: zrb,
                    congestion_control: ccb,
                    initial_mtu: imb,
                    min_mtu: mmb,
                    gso: gsob,
                    mtu_discovery: mdb,
                    blackhole_detection: bhb,
                },
            ) => {
                a == b
                    && ua == ub
                    && pa == pb
                    && users_a == users_b
                    && sna == snb
                    && jlsa == jlsb
                    && alpna == alpnb
                    && zra == zrb
                    && debug_eq(cca, ccb)
                    && ima == imb
                    && mma == mmb
                    && gsoa == gsob
                    && mda == mdb
                    && bha == bhb
            }
            _ => false,
        }
    }
}

impl Eq for InboundOpts {}

impl std::hash::Hash for InboundOpts {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            InboundOpts::Http { common_opts } => common_opts.hash(state),
            InboundOpts::Socks { common_opts, udp } => {
                common_opts.hash(state);
                udp.hash(state);
            }
            InboundOpts::Mixed { common_opts, udp } => {
                common_opts.hash(state);
                udp.hash(state);
            }
            #[cfg(feature = "tproxy")]
            InboundOpts::TProxy { common_opts, udp } => {
                common_opts.hash(state);
                udp.hash(state);
            }
            #[cfg(feature = "redir")]
            InboundOpts::Redir { common_opts } => common_opts.hash(state),
            InboundOpts::Tunnel {
                common_opts,
                network,
                target,
            } => {
                common_opts.hash(state);
                network.hash(state);
                target.hash(state);
            }
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks {
                common_opts,
                udp,
                cipher,
                password,
                ..
            } => {
                common_opts.hash(state);
                udp.hash(state);
                cipher.hash(state);
                password.hash(state);
                // `users` intentionally excluded — handled via watch channel
            }
            InboundOpts::Anytls {
                common_opts,
                password,
                certificate,
                private_key,
                fallback,
                ..
            } => {
                common_opts.hash(state);
                password.hash(state);
                certificate.hash(state);
                private_key.hash(state);
                fallback.hash(state);
                // `users` intentionally excluded — handled via watch channel
            }
            InboundOpts::Vless {
                common_opts,
                uuid,
                users,
                transport,
            } => {
                common_opts.hash(state);
                uuid.hash(state);
                users.hash(state);
                transport.hash(state);
            }
            #[cfg(feature = "shadowquic")]
            InboundOpts::ShadowQuic {
                common_opts,
                username,
                password,
                users,
                server_name,
                jls_upstream,
                alpn,
                zero_rtt,
                congestion_control,
                initial_mtu,
                min_mtu,
                gso,
                mtu_discovery,
                blackhole_detection,
            } => {
                common_opts.hash(state);
                username.hash(state);
                password.hash(state);
                users.hash(state);
                server_name.hash(state);
                jls_upstream.hash(state);
                alpn.hash(state);
                zero_rtt.hash(state);
                debug_hash(congestion_control, state);
                initial_mtu.hash(state);
                min_mtu.hash(state);
                gso.hash(state);
                mtu_discovery.hash(state);
                blackhole_detection.hash(state);
            }
        }
    }
}

impl InboundOpts {
    pub fn validate(&self) -> Result<(), crate::Error> {
        match self {
            InboundOpts::Vless {
                common_opts,
                uuid,
                users,
                transport,
            } => validate_vless_inbound(
                common_opts.name.as_str(),
                uuid.as_deref(),
                users,
                transport,
            ),
            _ => Ok(()),
        }
    }

    pub fn common_opts(&self) -> &CommonInboundOpts {
        match self {
            InboundOpts::Http { common_opts, .. } => common_opts,
            InboundOpts::Socks { common_opts, .. } => common_opts,
            InboundOpts::Mixed { common_opts, .. } => common_opts,
            #[cfg(feature = "tproxy")]
            InboundOpts::TProxy { common_opts, .. } => common_opts,
            InboundOpts::Tunnel { common_opts, .. } => common_opts,
            #[cfg(feature = "redir")]
            InboundOpts::Redir { common_opts, .. } => common_opts,
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks { common_opts, .. } => common_opts,
            InboundOpts::Anytls { common_opts, .. } => common_opts,
            InboundOpts::Vless { common_opts, .. } => common_opts,
            #[cfg(feature = "shadowquic")]
            InboundOpts::ShadowQuic { common_opts, .. } => common_opts,
        }
    }

    pub fn common_opts_mut(&mut self) -> &mut CommonInboundOpts {
        match self {
            InboundOpts::Http { common_opts, .. } => common_opts,
            InboundOpts::Socks { common_opts, .. } => common_opts,
            InboundOpts::Mixed { common_opts, .. } => common_opts,
            #[cfg(feature = "tproxy")]
            InboundOpts::TProxy { common_opts, .. } => common_opts,
            InboundOpts::Tunnel { common_opts, .. } => common_opts,
            #[cfg(feature = "redir")]
            InboundOpts::Redir { common_opts, .. } => common_opts,
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks { common_opts, .. } => common_opts,
            InboundOpts::Anytls { common_opts, .. } => common_opts,
            InboundOpts::Vless { common_opts, .. } => common_opts,
            #[cfg(feature = "shadowquic")]
            InboundOpts::ShadowQuic { common_opts, .. } => common_opts,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            InboundOpts::Http { .. } => "http",
            InboundOpts::Socks { .. } => "socks",
            InboundOpts::Mixed { .. } => "mixed",
            #[cfg(feature = "tproxy")]
            InboundOpts::TProxy { .. } => "tproxy",
            InboundOpts::Tunnel { .. } => "tunnel",
            #[cfg(feature = "redir")]
            InboundOpts::Redir { .. } => "redir",
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks { .. } => "shadowsocks",
            InboundOpts::Anytls { .. } => "anytls",
            InboundOpts::Vless { .. } => "vless",
            #[cfg(feature = "shadowquic")]
            InboundOpts::ShadowQuic { .. } => "shadowquic",
        }
    }
}

fn validate_vless_inbound(
    name: &str,
    uuid: Option<&str>,
    users: &[VlessInboundUser],
    transport: &VlessInboundTransport,
) -> Result<(), crate::Error> {
    if !transport.typ.eq_ignore_ascii_case("ws") {
        return Err(crate::Error::InvalidConfig(format!(
            "vless inbound '{name}': only websocket transport is supported"
        )));
    }

    if transport.path.is_empty() || !transport.path.starts_with('/') {
        return Err(crate::Error::InvalidConfig(format!(
            "vless inbound '{name}': websocket path must be absolute"
        )));
    }

    if uuid.is_none() && users.is_empty() {
        return Err(crate::Error::InvalidConfig(format!(
            "vless inbound '{name}': uuid or users is required"
        )));
    }

    if let Some(header_name) = &transport.early_data_header_name {
        http::HeaderName::from_bytes(header_name.as_bytes()).map_err(|e| {
            crate::Error::InvalidConfig(format!(
                "vless inbound '{name}': invalid early-data-header-name \
                 '{header_name}': {e}"
            ))
        })?;
    }

    let mut seen = HashSet::new();
    if let Some(uuid) = uuid {
        let parsed = parse_vless_uuid(name, uuid)?;
        seen.insert(parsed);
    }
    for user in users {
        let parsed = parse_vless_uuid(name, user.uuid.as_str())?;
        if !seen.insert(parsed) {
            return Err(crate::Error::InvalidConfig(format!(
                "vless inbound '{name}': duplicate uuid {}",
                user.uuid
            )));
        }
    }

    Ok(())
}

fn parse_vless_uuid(name: &str, uuid: &str) -> Result<uuid::Uuid, crate::Error> {
    uuid::Uuid::parse_str(uuid).map_err(|e| {
        crate::Error::InvalidConfig(format!(
            "vless inbound '{name}': invalid uuid {uuid}: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "d4f2ad1c-f6db-481e-91de-9d551f8885c9";

    fn vless_listener() -> InboundOpts {
        InboundOpts::Vless {
            common_opts: CommonInboundOpts {
                name: "vless-ws-in".to_owned(),
                listen: BindAddress::local(),
                allow_lan: false,
                port: 60178,
                fw_mark: None,
            },
            uuid: Some(UUID.to_owned()),
            users: Vec::new(),
            transport: VlessInboundTransport {
                typ: "ws".to_owned(),
                path: "/assets/js/chunks/main.d4f2ad1c.js".to_owned(),
                early_data_header_name: Some("Sec-WebSocket-Protocol".to_owned()),
            },
        }
    }

    #[test]
    fn validate_vless_accepts_ws_listener() {
        assert!(vless_listener().validate().is_ok());
    }

    #[test]
    fn validate_vless_rejects_unsupported_transport() {
        let mut listener = vless_listener();
        if let InboundOpts::Vless { transport, .. } = &mut listener {
            transport.typ = "grpc".to_owned();
        }

        assert!(listener.validate().is_err());
    }

    #[test]
    fn validate_vless_rejects_bad_uuid() {
        let mut listener = vless_listener();
        if let InboundOpts::Vless { uuid, .. } = &mut listener {
            *uuid = Some("not-a-uuid".to_owned());
        }

        assert!(listener.validate().is_err());
    }

    #[test]
    fn validate_vless_rejects_relative_ws_path() {
        let mut listener = vless_listener();
        if let InboundOpts::Vless { transport, .. } = &mut listener {
            transport.path = "relative".to_owned();
        }

        assert!(listener.validate().is_err());
    }

    #[test]
    fn validate_vless_rejects_invalid_early_data_header_name() {
        let mut listener = vless_listener();
        if let InboundOpts::Vless { transport, .. } = &mut listener {
            transport.early_data_header_name = Some("bad header".to_owned());
        }

        assert!(listener.validate().is_err());
    }
}

/// Mirrors `OutboundProxyProviderDef` but for inbound listeners.
/// The provider URL/file must return YAML with a top-level `listeners:` key
/// containing a list of `InboundOpts`-compatible objects.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum InboundProviderDef {
    Http(InboundHttpProvider),
    File(InboundFileProvider),
}

impl InboundProviderDef {
    pub fn set_name(&mut self, name: String) {
        match self {
            InboundProviderDef::Http(p) => p.name = name,
            InboundProviderDef::File(p) => p.name = name,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct InboundHttpProvider {
    #[serde(skip)]
    pub name: String,
    pub url: String,
    pub interval: u64,
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct InboundFileProvider {
    #[serde(skip)]
    pub name: String,
    pub path: String,
    pub interval: Option<u64>,
}

impl TryFrom<HashMap<String, Value>> for InboundProviderDef {
    type Error = crate::Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        use serde::de::value::MapDeserializer;
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or_else(|| {
                crate::Error::InvalidConfig(
                    "missing field `name` in inbound provider".into(),
                )
            })?
            .to_owned();
        InboundProviderDef::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(|e| {
                crate::Error::InvalidConfig(format!("inbound provider {name}: {e}"))
            })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct CommonInboundOpts {
    #[serde(alias = "tag")]
    pub name: String,
    pub listen: BindAddress,
    #[serde(default)]
    pub allow_lan: bool,
    #[serde(alias = "listen-port", alias = "listen_port")]
    pub port: u16,
    /// Linux routing mark
    pub fw_mark: Option<u32>,
}
