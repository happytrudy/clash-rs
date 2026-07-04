use crate::common::utils::default_bool_true;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
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

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Hysteria2Acme {
    pub domain: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default, alias = "cache_dir")]
    pub cache_dir: Option<String>,
    #[serde(default)]
    pub challenge: Hysteria2AcmeChallenge,
    #[serde(default)]
    pub dns: Option<Hysteria2AcmeDns>,
    /// Use Let's Encrypt production when true. The rustls-acme default is
    /// staging, which is safer for testing but not trusted by clients.
    #[serde(default)]
    pub production: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Hysteria2AcmeChallenge {
    #[default]
    #[serde(alias = "tls-alpn-01")]
    TlsAlpn01,
    #[serde(alias = "dns-01")]
    Dns01,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Hysteria2AcmeDns {
    pub provider: Hysteria2AcmeDnsProvider,
    #[serde(default)]
    pub cloudflare: Option<Hysteria2AcmeCloudflareDns>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Hysteria2AcmeDnsProvider {
    Cloudflare,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Hysteria2AcmeCloudflareDns {
    #[serde(default)]
    pub api_token: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default, alias = "email")]
    pub auth_email: Option<String>,
    #[serde(default)]
    pub zone_id: Option<String>,
    #[serde(default)]
    pub ttl: Option<u32>,
    #[serde(default)]
    pub propagation_delay: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Hysteria2InboundObfsKind {
    Salamander,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Hysteria2InboundSalamanderObfs {
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Hysteria2InboundDetailedObfs {
    #[serde(rename = "type")]
    pub typ: Hysteria2InboundObfsKind,
    #[serde(default)]
    pub salamander: Option<Hysteria2InboundSalamanderObfs>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(untagged)]
pub enum Hysteria2InboundObfs {
    Simple(Hysteria2InboundObfsKind),
    Detailed(Hysteria2InboundDetailedObfs),
}

impl Hysteria2InboundObfs {
    pub fn salamander_password<'a>(
        &'a self,
        obfs_password: Option<&'a str>,
    ) -> Option<&'a str> {
        match self {
            Hysteria2InboundObfs::Simple(Hysteria2InboundObfsKind::Salamander) => {
                obfs_password
            }
            Hysteria2InboundObfs::Detailed(obfs) => match obfs.typ {
                Hysteria2InboundObfsKind::Salamander => obfs
                    .salamander
                    .as_ref()
                    .map(|s| s.password.as_str())
                    .or(obfs.password.as_deref())
                    .or(obfs_password),
            },
        }
    }
}

#[derive(
    Serialize, Deserialize, Debug, Clone, Copy, Hash, Eq, PartialEq, Default,
)]
#[serde(rename_all = "kebab-case")]
pub enum Hysteria2SniGuard {
    Disable,
    #[default]
    DnsSan,
    Strict,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Hysteria2MasqueradeType {
    #[serde(rename = "404")]
    NotFound,
    File,
    Proxy,
    String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Hysteria2MasqueradeFile {
    pub dir: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Hysteria2MasqueradeProxy {
    pub url: String,
    #[serde(default, alias = "rewriteHost")]
    pub rewrite_host: bool,
    #[serde(default, alias = "xForwarded")]
    pub x_forwarded: bool,
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Hysteria2MasqueradeString {
    pub content: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default, alias = "statusCode")]
    pub status_code: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Hysteria2Masquerade {
    #[serde(rename = "type")]
    pub typ: Hysteria2MasqueradeType,
    #[serde(default)]
    pub file: Option<Hysteria2MasqueradeFile>,
    #[serde(default)]
    pub proxy: Option<Hysteria2MasqueradeProxy>,
    #[serde(default)]
    pub string: Option<Hysteria2MasqueradeString>,
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
    #[serde(alias = "hysteria2", alias = "hy2")]
    Hysteria2 {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        password: String,
        #[serde(default)]
        certificate: Option<String>,
        #[serde(rename = "private-key", default)]
        private_key: Option<String>,
        #[serde(default)]
        acme: Option<Hysteria2Acme>,
        #[serde(default)]
        users: Vec<InboundUser>,
        #[serde(default)]
        obfs: Option<Hysteria2InboundObfs>,
        #[serde(rename = "obfs-password", alias = "obfs_password", default)]
        obfs_password: Option<String>,
        #[serde(default, alias = "sni_guard", alias = "sniGuard")]
        sni_guard: Hysteria2SniGuard,
        #[serde(default)]
        masquerade: Option<Hysteria2Masquerade>,
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
            (
                InboundOpts::Hysteria2 {
                    common_opts: a,
                    password: pa,
                    certificate: ca,
                    private_key: pka,
                    acme: aa,
                    obfs: oa,
                    obfs_password: opa,
                    sni_guard: sga,
                    masquerade: ma,
                    ..
                },
                InboundOpts::Hysteria2 {
                    common_opts: b,
                    password: pb,
                    certificate: cb,
                    private_key: pkb,
                    acme: ab,
                    obfs: ob,
                    obfs_password: opb,
                    sni_guard: sgb,
                    masquerade: mb,
                    ..
                },
            ) => {
                a == b
                    && pa == pb
                    && ca == cb
                    && pka == pkb
                    && aa == ab
                    && oa == ob
                    && opa == opb
                    && sga == sgb
                    && ma == mb
            }
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
            InboundOpts::Hysteria2 {
                common_opts,
                password,
                certificate,
                private_key,
                acme,
                obfs,
                obfs_password,
                sni_guard,
                masquerade,
                ..
            } => {
                common_opts.hash(state);
                password.hash(state);
                certificate.hash(state);
                private_key.hash(state);
                acme.hash(state);
                obfs.hash(state);
                obfs_password.hash(state);
                sni_guard.hash(state);
                masquerade.hash(state);
                // `users` intentionally excluded — handled via watch channel
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
            InboundOpts::Hysteria2 {
                common_opts,
                password,
                certificate,
                private_key,
                acme,
                users,
                obfs,
                obfs_password,
                sni_guard,
                masquerade,
            } => validate_hysteria2_inbound(
                common_opts.name.as_str(),
                password,
                certificate,
                private_key,
                acme.as_ref(),
                users,
                obfs.as_ref(),
                obfs_password.as_deref(),
                sni_guard,
                masquerade.as_ref(),
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
            InboundOpts::Hysteria2 { common_opts, .. } => common_opts,
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
            InboundOpts::Hysteria2 { common_opts, .. } => common_opts,
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
            InboundOpts::Hysteria2 { .. } => "hysteria2",
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

fn validate_hysteria2_inbound(
    name: &str,
    password: &str,
    certificate: &Option<String>,
    private_key: &Option<String>,
    acme: Option<&Hysteria2Acme>,
    users: &[InboundUser],
    obfs: Option<&Hysteria2InboundObfs>,
    obfs_password: Option<&str>,
    _sni_guard: &Hysteria2SniGuard,
    masquerade: Option<&Hysteria2Masquerade>,
) -> Result<(), crate::Error> {
    if password.is_empty() && users.is_empty() {
        return Err(crate::Error::InvalidConfig(format!(
            "hysteria2 inbound '{name}': password or users is required"
        )));
    }

    match (certificate, private_key) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => {
            return Err(crate::Error::InvalidConfig(format!(
                "hysteria2 inbound '{name}': certificate and private-key must \
                 both be set or both omitted"
            )));
        }
    }

    if acme.is_some() && (certificate.is_some() || private_key.is_some()) {
        return Err(crate::Error::InvalidConfig(format!(
            "hysteria2 inbound '{name}': acme cannot be used with certificate \
             or private-key"
        )));
    }

    if let Some(acme) = acme {
        validate_acme_identifier(
            name,
            acme.domain.as_str(),
            matches!(acme.challenge, Hysteria2AcmeChallenge::Dns01),
        )?;
        if let Some(cache_dir) = acme.cache_dir.as_deref()
            && cache_dir.trim().is_empty()
        {
            return Err(crate::Error::InvalidConfig(format!(
                "hysteria2 inbound '{name}': acme cache-dir cannot be empty"
            )));
        }
        validate_hysteria2_acme_challenge(name, acme)?;
    }

    match (obfs, obfs_password) {
        (Some(obfs), _) => {
            let Some(password) = obfs.salamander_password(obfs_password) else {
                return Err(crate::Error::InvalidConfig(format!(
                    "hysteria2 inbound '{name}': obfs-password or \
                     obfs.salamander.password is required when obfs is enabled"
                )));
            };
            if password.is_empty() {
                return Err(crate::Error::InvalidConfig(format!(
                    "hysteria2 inbound '{name}': obfs password cannot be empty"
                )));
            }
        }
        (None, Some(password)) if !password.is_empty() => {
            return Err(crate::Error::InvalidConfig(format!(
                "hysteria2 inbound '{name}': obfs-password requires obfs: \
                 salamander"
            )));
        }
        (None, _) => {}
    }

    if let Some(masquerade) = masquerade {
        validate_hysteria2_masquerade(name, masquerade)?;
    }

    let mut seen = HashSet::new();
    for user in users {
        if user.name.trim().is_empty() {
            return Err(crate::Error::InvalidConfig(format!(
                "hysteria2 inbound '{name}': user name cannot be empty"
            )));
        }
        if user.password.is_empty() {
            return Err(crate::Error::InvalidConfig(format!(
                "hysteria2 inbound '{name}': user '{}' password cannot be empty",
                user.name
            )));
        }
        if !seen.insert(user.password.clone()) {
            return Err(crate::Error::InvalidConfig(format!(
                "hysteria2 inbound '{name}': duplicate password for user '{}'",
                user.name
            )));
        }
    }

    Ok(())
}

fn validate_hysteria2_masquerade(
    name: &str,
    masquerade: &Hysteria2Masquerade,
) -> Result<(), crate::Error> {
    match masquerade.typ {
        Hysteria2MasqueradeType::NotFound => Ok(()),
        Hysteria2MasqueradeType::File => {
            let Some(file) = masquerade.file.as_ref() else {
                return Err(crate::Error::InvalidConfig(format!(
                    "hysteria2 inbound '{name}': masquerade.file is required \
                     for type: file"
                )));
            };
            if file.dir.trim().is_empty() {
                return Err(crate::Error::InvalidConfig(format!(
                    "hysteria2 inbound '{name}': masquerade.file.dir cannot \
                     be empty"
                )));
            }
            Ok(())
        }
        Hysteria2MasqueradeType::Proxy => {
            let Some(proxy) = masquerade.proxy.as_ref() else {
                return Err(crate::Error::InvalidConfig(format!(
                    "hysteria2 inbound '{name}': masquerade.proxy is required \
                     for type: proxy"
                )));
            };
            let parsed = url::Url::parse(proxy.url.as_str()).map_err(|e| {
                crate::Error::InvalidConfig(format!(
                    "hysteria2 inbound '{name}': invalid masquerade.proxy.url \
                     '{}': {e}",
                    proxy.url
                ))
            })?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(crate::Error::InvalidConfig(format!(
                    "hysteria2 inbound '{name}': masquerade.proxy.url must \
                     use http or https"
                )));
            }
            Ok(())
        }
        Hysteria2MasqueradeType::String => {
            let Some(string) = masquerade.string.as_ref() else {
                return Err(crate::Error::InvalidConfig(format!(
                    "hysteria2 inbound '{name}': masquerade.string is required \
                     for type: string"
                )));
            };
            if string.content.is_empty() {
                return Err(crate::Error::InvalidConfig(format!(
                    "hysteria2 inbound '{name}': masquerade.string.content \
                     cannot be empty"
                )));
            }
            if let Some(status_code) = string.status_code
                && status_code != 0
                && (!(200..=599).contains(&status_code) || status_code == 233)
            {
                return Err(crate::Error::InvalidConfig(format!(
                    "hysteria2 inbound '{name}': masquerade.string.status-code \
                     must be 0 or 200-599 except 233"
                )));
            }
            for (name, value) in &string.headers {
                http::HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
                    crate::Error::InvalidConfig(format!(
                        "hysteria2 inbound: invalid masquerade header name \
                         '{name}': {e}"
                    ))
                })?;
                http::HeaderValue::from_str(value).map_err(|e| {
                    crate::Error::InvalidConfig(format!(
                        "hysteria2 inbound: invalid masquerade header value \
                         for '{name}': {e}"
                    ))
                })?;
            }
            Ok(())
        }
    }
}

fn validate_hysteria2_acme_challenge(
    name: &str,
    acme: &Hysteria2Acme,
) -> Result<(), crate::Error> {
    match acme.challenge {
        Hysteria2AcmeChallenge::TlsAlpn01 => {
            if acme.dns.is_some() {
                return Err(crate::Error::InvalidConfig(format!(
                    "hysteria2 inbound '{name}': acme.dns requires challenge: \
                     dns-01"
                )));
            }
        }
        Hysteria2AcmeChallenge::Dns01 => {
            if acme.domain.parse::<std::net::IpAddr>().is_ok() {
                return Err(crate::Error::InvalidConfig(format!(
                    "hysteria2 inbound '{name}': dns-01 cannot issue \
                     certificates for IP identifiers"
                )));
            }

            let Some(dns) = acme.dns.as_ref() else {
                return Err(crate::Error::InvalidConfig(format!(
                    "hysteria2 inbound '{name}': acme.dns is required for \
                     challenge: dns-01"
                )));
            };
            match dns.provider {
                Hysteria2AcmeDnsProvider::Cloudflare => {
                    let Some(cloudflare) = dns.cloudflare.as_ref() else {
                        return Err(crate::Error::InvalidConfig(format!(
                            "hysteria2 inbound '{name}': acme.dns.cloudflare \
                             is required for provider: cloudflare"
                        )));
                    };
                    let api_token = cloudflare
                        .api_token
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty());
                    let api_key = cloudflare
                        .api_key
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty());
                    let auth_email = cloudflare
                        .auth_email
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty());

                    if api_token.is_none() && api_key.is_none() {
                        return Err(crate::Error::InvalidConfig(format!(
                            "hysteria2 inbound '{name}': cloudflare api-token \
                             or api-key is required"
                        )));
                    }
                    if api_token.is_some() && api_key.is_some() {
                        return Err(crate::Error::InvalidConfig(format!(
                            "hysteria2 inbound '{name}': cloudflare api-token \
                             and api-key are mutually exclusive"
                        )));
                    }
                    if api_token.is_some() && auth_email.is_some() {
                        return Err(crate::Error::InvalidConfig(format!(
                            "hysteria2 inbound '{name}': cloudflare auth-email \
                             is only used with api-key, not api-token"
                        )));
                    }
                    if api_key.is_some() && auth_email.is_none() {
                        return Err(crate::Error::InvalidConfig(format!(
                            "hysteria2 inbound '{name}': cloudflare auth-email \
                             is required when api-key is used"
                        )));
                    }
                    if let Some(zone_id) = cloudflare.zone_id.as_deref()
                        && zone_id.trim().is_empty()
                    {
                        return Err(crate::Error::InvalidConfig(format!(
                            "hysteria2 inbound '{name}': cloudflare zone-id \
                             cannot be empty"
                        )));
                    }
                    if matches!(cloudflare.ttl, Some(2..=59)) {
                        return Err(crate::Error::InvalidConfig(format!(
                            "hysteria2 inbound '{name}': cloudflare ttl must \
                             be 1 for automatic or at least 60 seconds"
                        )));
                    }
                }
            }
        }
    }

    Ok(())
}

fn validate_acme_identifier(
    name: &str,
    domain: &str,
    allow_wildcard: bool,
) -> Result<(), crate::Error> {
    let domain = domain.trim();
    if domain.is_empty() {
        return Err(crate::Error::InvalidConfig(format!(
            "hysteria2 inbound '{name}': acme domain cannot be empty"
        )));
    }

    if domain.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }

    let domain = if let Some(base) = domain.strip_prefix("*.") {
        if !allow_wildcard {
            return Err(crate::Error::InvalidConfig(format!(
                "hysteria2 inbound '{name}': wildcard acme domain requires \
                 challenge: dns-01"
            )));
        }
        base
    } else {
        domain
    };

    if domain.len() > 253
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(crate::Error::InvalidConfig(format!(
            "hysteria2 inbound '{name}': invalid acme domain '{domain}'"
        )));
    }

    Ok(())
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

    fn hysteria2_listener() -> InboundOpts {
        InboundOpts::Hysteria2 {
            common_opts: CommonInboundOpts {
                name: "hy2-in".to_owned(),
                listen: BindAddress::local(),
                allow_lan: false,
                port: 443,
                fw_mark: None,
            },
            password: "secret".to_owned(),
            certificate: None,
            private_key: None,
            acme: Some(Hysteria2Acme {
                domain: "hy2.example.com".to_owned(),
                email: Some("admin@example.com".to_owned()),
                cache_dir: Some("./acme/hysteria2".to_owned()),
                challenge: Hysteria2AcmeChallenge::TlsAlpn01,
                dns: None,
                production: true,
            }),
            users: Vec::new(),
            obfs: None,
            obfs_password: None,
            sni_guard: Hysteria2SniGuard::DnsSan,
            masquerade: None,
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

    #[test]
    fn validate_hysteria2_accepts_acme_listener() {
        assert!(hysteria2_listener().validate().is_ok());
    }

    #[test]
    fn validate_hysteria2_rejects_acme_with_manual_cert() {
        let mut listener = hysteria2_listener();
        if let InboundOpts::Hysteria2 {
            certificate,
            private_key,
            ..
        } = &mut listener
        {
            *certificate = Some("cert.pem".to_owned());
            *private_key = Some("key.pem".to_owned());
        }

        assert!(listener.validate().is_err());
    }

    #[test]
    fn validate_hysteria2_rejects_duplicate_password() {
        let mut listener = hysteria2_listener();
        if let InboundOpts::Hysteria2 { users, .. } = &mut listener {
            users.push(InboundUser {
                name: "alice".to_owned(),
                password: "secret".to_owned(),
            });
            users.push(InboundUser {
                name: "bob".to_owned(),
                password: "secret".to_owned(),
            });
        }

        assert!(listener.validate().is_err());
    }

    #[test]
    fn validate_hysteria2_accepts_simple_salamander_obfs() {
        let mut listener = hysteria2_listener();
        if let InboundOpts::Hysteria2 {
            obfs,
            obfs_password,
            ..
        } = &mut listener
        {
            *obfs = Some(Hysteria2InboundObfs::Simple(
                Hysteria2InboundObfsKind::Salamander,
            ));
            *obfs_password = Some("obfs-secret".to_owned());
        }

        assert!(listener.validate().is_ok());
    }

    #[test]
    fn validate_hysteria2_accepts_official_salamander_obfs() {
        let mut listener = hysteria2_listener();
        if let InboundOpts::Hysteria2 { obfs, .. } = &mut listener {
            *obfs = Some(Hysteria2InboundObfs::Detailed(
                Hysteria2InboundDetailedObfs {
                    typ: Hysteria2InboundObfsKind::Salamander,
                    salamander: Some(Hysteria2InboundSalamanderObfs {
                        password: "obfs-secret".to_owned(),
                    }),
                    password: None,
                },
            ));
        }

        assert!(listener.validate().is_ok());
    }

    #[test]
    fn validate_hysteria2_rejects_obfs_without_password() {
        let mut listener = hysteria2_listener();
        if let InboundOpts::Hysteria2 { obfs, .. } = &mut listener {
            *obfs = Some(Hysteria2InboundObfs::Simple(
                Hysteria2InboundObfsKind::Salamander,
            ));
        }

        assert!(listener.validate().is_err());
    }

    #[test]
    fn parse_hysteria2_official_salamander_obfs_yaml() {
        let listener: InboundOpts = serde_yaml::from_str(
            r#"
type: hysteria2
name: hy2-in
listen: 127.0.0.1
port: 443
password: secret
obfs:
  type: salamander
  salamander:
    password: obfs-secret
"#,
        )
        .unwrap();

        if let InboundOpts::Hysteria2 {
            obfs,
            obfs_password,
            ..
        } = &listener
        {
            assert_eq!(
                obfs.as_ref().and_then(
                    |obfs| obfs.salamander_password(obfs_password.as_deref())
                ),
                Some("obfs-secret")
            );
        } else {
            panic!("expected hysteria2 listener");
        }

        assert!(listener.validate().is_ok());
    }

    #[test]
    fn parse_hysteria2_official_masquerade_and_sni_guard_yaml() {
        let listener: InboundOpts = serde_yaml::from_str(
            r#"
type: hysteria2
name: hy2-in
listen: 127.0.0.1
port: 443
password: secret
sniGuard: strict
masquerade:
  type: string
  string:
    content: "hello"
    statusCode: 204
    headers:
      content-type: text/plain
"#,
        )
        .unwrap();

        if let InboundOpts::Hysteria2 {
            sni_guard,
            masquerade,
            ..
        } = &listener
        {
            assert_eq!(*sni_guard, Hysteria2SniGuard::Strict);
            let masquerade = masquerade.as_ref().unwrap();
            assert_eq!(masquerade.typ, Hysteria2MasqueradeType::String);
            let string = masquerade.string.as_ref().unwrap();
            assert_eq!(string.status_code, Some(204));
            assert_eq!(
                string.headers.get("content-type").map(String::as_str),
                Some("text/plain")
            );
        } else {
            panic!("expected hysteria2 listener");
        }

        assert!(listener.validate().is_ok());
    }

    #[test]
    fn parse_hysteria2_dns01_alias_and_automatic_cloudflare_ttl() {
        let listener: InboundOpts = serde_yaml::from_str(
            r#"
type: hysteria2
name: hy2-in
listen: "::"
allow-lan: true
port: 21835
password: secret
acme:
  domain: h.example.com
  email: admin@example.com
  cache-dir: ./acme/hysteria2
  production: true
  challenge: dns-01
  dns:
    provider: cloudflare
    cloudflare:
      api-token: cf-token
      ttl: 1
      propagation-delay: 30
"#,
        )
        .unwrap();

        if let InboundOpts::Hysteria2 { acme, .. } = &listener {
            let acme = acme.as_ref().unwrap();
            assert_eq!(acme.challenge, Hysteria2AcmeChallenge::Dns01);
            assert_eq!(
                acme.dns
                    .as_ref()
                    .and_then(|dns| dns.cloudflare.as_ref())
                    .and_then(|cloudflare| cloudflare.ttl),
                Some(1)
            );
        } else {
            panic!("expected hysteria2 listener");
        }

        assert!(listener.validate().is_ok());
    }

    #[test]
    fn validate_hysteria2_rejects_reserved_masquerade_status() {
        let mut listener = hysteria2_listener();
        if let InboundOpts::Hysteria2 { masquerade, .. } = &mut listener {
            *masquerade = Some(Hysteria2Masquerade {
                typ: Hysteria2MasqueradeType::String,
                file: None,
                proxy: None,
                string: Some(Hysteria2MasqueradeString {
                    content: "hello".to_owned(),
                    headers: BTreeMap::new(),
                    status_code: Some(233),
                }),
            });
        }

        assert!(listener.validate().is_err());
    }

    #[test]
    fn validate_hysteria2_accepts_cloudflare_dns01_acme() {
        let mut listener = hysteria2_listener();
        if let InboundOpts::Hysteria2 { acme, .. } = &mut listener {
            *acme = Some(Hysteria2Acme {
                domain: "hy2.example.com".to_owned(),
                email: Some("admin@example.com".to_owned()),
                cache_dir: Some("./acme/hysteria2".to_owned()),
                challenge: Hysteria2AcmeChallenge::Dns01,
                dns: Some(Hysteria2AcmeDns {
                    provider: Hysteria2AcmeDnsProvider::Cloudflare,
                    cloudflare: Some(Hysteria2AcmeCloudflareDns {
                        api_token: Some("cf-token".to_owned()),
                        api_key: None,
                        auth_email: None,
                        zone_id: None,
                        ttl: Some(60),
                        propagation_delay: Some(30),
                    }),
                }),
                production: true,
            });
        }

        assert!(listener.validate().is_ok());
    }

    #[test]
    fn validate_hysteria2_accepts_cloudflare_global_api_key_dns01_acme() {
        let listener: InboundOpts = serde_yaml::from_str(
            r#"
type: hysteria2
name: hy2-in
listen: 127.0.0.1
port: 443
password: secret
acme:
  domain: hy2.example.com
  challenge: dns-01
  dns:
    provider: cloudflare
    cloudflare:
      api-key: cf-global-key
      auth-email: account@example.com
"#,
        )
        .unwrap();

        if let InboundOpts::Hysteria2 { acme, .. } = &listener {
            let cloudflare = acme
                .as_ref()
                .unwrap()
                .dns
                .as_ref()
                .unwrap()
                .cloudflare
                .as_ref()
                .unwrap();
            assert_eq!(cloudflare.api_key.as_deref(), Some("cf-global-key"));
            assert_eq!(
                cloudflare.auth_email.as_deref(),
                Some("account@example.com")
            );
        } else {
            panic!("expected hysteria2 listener");
        }

        assert!(listener.validate().is_ok());
    }

    #[test]
    fn validate_hysteria2_accepts_dns01_wildcard_acme() {
        let mut listener = hysteria2_listener();
        if let InboundOpts::Hysteria2 { acme, .. } = &mut listener {
            *acme = Some(Hysteria2Acme {
                domain: "*.example.com".to_owned(),
                email: Some("admin@example.com".to_owned()),
                cache_dir: Some("./acme/hysteria2".to_owned()),
                challenge: Hysteria2AcmeChallenge::Dns01,
                dns: Some(Hysteria2AcmeDns {
                    provider: Hysteria2AcmeDnsProvider::Cloudflare,
                    cloudflare: Some(Hysteria2AcmeCloudflareDns {
                        api_token: Some("cf-token".to_owned()),
                        api_key: None,
                        auth_email: None,
                        zone_id: None,
                        ttl: Some(60),
                        propagation_delay: Some(30),
                    }),
                }),
                production: true,
            });
        }

        assert!(listener.validate().is_ok());
    }

    #[test]
    fn validate_hysteria2_rejects_tls_alpn_wildcard_acme() {
        let mut listener = hysteria2_listener();
        if let InboundOpts::Hysteria2 { acme, .. } = &mut listener
            && let Some(acme) = acme
        {
            acme.domain = "*.example.com".to_owned();
            acme.challenge = Hysteria2AcmeChallenge::TlsAlpn01;
            acme.dns = None;
        }

        assert!(listener.validate().is_err());
    }

    #[test]
    fn validate_hysteria2_rejects_dns01_without_cloudflare_token() {
        let mut listener = hysteria2_listener();
        if let InboundOpts::Hysteria2 { acme, .. } = &mut listener {
            *acme = Some(Hysteria2Acme {
                domain: "hy2.example.com".to_owned(),
                email: None,
                cache_dir: None,
                challenge: Hysteria2AcmeChallenge::Dns01,
                dns: Some(Hysteria2AcmeDns {
                    provider: Hysteria2AcmeDnsProvider::Cloudflare,
                    cloudflare: Some(Hysteria2AcmeCloudflareDns {
                        api_token: None,
                        api_key: None,
                        auth_email: None,
                        zone_id: None,
                        ttl: None,
                        propagation_delay: None,
                    }),
                }),
                production: false,
            });
        }

        assert!(listener.validate().is_err());
    }

    #[test]
    fn validate_hysteria2_rejects_cloudflare_api_key_without_auth_email() {
        let mut listener = hysteria2_listener();
        if let InboundOpts::Hysteria2 { acme, .. } = &mut listener {
            *acme = Some(Hysteria2Acme {
                domain: "hy2.example.com".to_owned(),
                email: None,
                cache_dir: None,
                challenge: Hysteria2AcmeChallenge::Dns01,
                dns: Some(Hysteria2AcmeDns {
                    provider: Hysteria2AcmeDnsProvider::Cloudflare,
                    cloudflare: Some(Hysteria2AcmeCloudflareDns {
                        api_token: None,
                        api_key: Some("cf-global-key".to_owned()),
                        auth_email: None,
                        zone_id: None,
                        ttl: None,
                        propagation_delay: None,
                    }),
                }),
                production: false,
            });
        }

        assert!(listener.validate().is_err());
    }

    #[test]
    fn validate_hysteria2_rejects_cloudflare_api_token_with_auth_email() {
        let mut listener = hysteria2_listener();
        if let InboundOpts::Hysteria2 { acme, .. } = &mut listener {
            *acme = Some(Hysteria2Acme {
                domain: "hy2.example.com".to_owned(),
                email: None,
                cache_dir: None,
                challenge: Hysteria2AcmeChallenge::Dns01,
                dns: Some(Hysteria2AcmeDns {
                    provider: Hysteria2AcmeDnsProvider::Cloudflare,
                    cloudflare: Some(Hysteria2AcmeCloudflareDns {
                        api_token: Some("cf-token".to_owned()),
                        api_key: None,
                        auth_email: Some("account@example.com".to_owned()),
                        zone_id: None,
                        ttl: None,
                        propagation_delay: None,
                    }),
                }),
                production: false,
            });
        }

        assert!(listener.validate().is_err());
    }

    #[test]
    fn validate_hysteria2_rejects_cloudflare_ttl_between_auto_and_minimum() {
        let mut listener = hysteria2_listener();
        if let InboundOpts::Hysteria2 { acme, .. } = &mut listener
            && let Some(acme) = acme
        {
            acme.challenge = Hysteria2AcmeChallenge::Dns01;
            acme.dns = Some(Hysteria2AcmeDns {
                provider: Hysteria2AcmeDnsProvider::Cloudflare,
                cloudflare: Some(Hysteria2AcmeCloudflareDns {
                    api_token: Some("cf-token".to_owned()),
                    api_key: None,
                    auth_email: None,
                    zone_id: None,
                    ttl: Some(30),
                    propagation_delay: None,
                }),
            });
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
