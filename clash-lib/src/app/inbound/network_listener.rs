use crate::{
    common::auth::ThreadSafeAuthenticator,
    config::listener::{InboundOpts, InboundUser},
    proxy::{
        anytls::inbound::{AnytlsInbound, InboundOptions as AnytlsInboundOptions},
        http::HttpInbound,
        hysteria2::inbound::{
            AcmeChallenge as Hysteria2AcmeChallenge,
            AcmeOptions as Hysteria2AcmeOptions,
            CloudflareAuth as Hysteria2CloudflareAuth,
            CloudflareDnsOptions as Hysteria2CloudflareDnsOptions, Hysteria2Inbound,
            InboundOptions as Hysteria2InboundOptions,
            MasqueradeOptions as Hysteria2MasqueradeOptions,
            ObfsOptions as Hysteria2ObfsOptions,
            SniGuardMode as Hysteria2SniGuardMode,
        },
        inbound::InboundHandlerTrait,
        mixed::MixedInbound,
        socks::inbound::SocksInbound,
        tunnel::TunnelInbound,
        vless::inbound::{
            InboundOptions as VlessInboundOptions, VlessInbound,
            VlessInboundUser as RuntimeVlessInboundUser, WsInboundOptions,
        },
    },
};

#[cfg(all(target_os = "linux", feature = "redir"))]
use crate::proxy::redir::RedirInbound;
#[cfg(all(target_os = "linux", feature = "tproxy"))]
use crate::proxy::tproxy::TproxyInbound;

use crate::Dispatcher;
use futures::future::BoxFuture;
use tracing::{error, info, warn};

#[cfg(feature = "shadowquic")]
use crate::proxy::shadowquic::inbound::{
    InboundOptions as ShadowQuicInboundOptions, ShadowQuicInbound,
};
#[cfg(feature = "shadowsocks")]
use crate::proxy::shadowsocks::inbound::{InboundOptions, ShadowsocksInbound};
use std::{path::PathBuf, sync::Arc, time::Duration};

pub(crate) fn build_network_listeners(
    inbound_opts: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    users_rx: Option<tokio::sync::watch::Receiver<Vec<InboundUser>>>,
) -> Option<Vec<BoxFuture<'static, Result<(), crate::Error>>>> {
    let name = &inbound_opts.common_opts().name;
    let addr = inbound_opts.common_opts().listen.0;
    let port = inbound_opts.common_opts().port;

    if let Some(handler) =
        build_handler(inbound_opts, dispatcher, authenticator, users_rx)
    {
        let mut runners: Vec<BoxFuture<'static, Result<(), crate::Error>>> =
            Vec::new();

        if handler.handle_tcp() {
            let tcp_listener = handler.clone();

            let name = name.clone();
            runners.push(Box::pin(async move {
                info!("{} TCP listening at: {}:{}", name, addr, port,);
                tcp_listener
                    .listen_tcp()
                    .await
                    .inspect_err(|x| {
                        error!("handler {} tcp listen failed: {x}", name);
                    })
                    .map_err(|e| e.into())
            }));
        }

        if handler.handle_udp() {
            let udp_listener = handler.clone();
            let name = name.clone();
            runners.push(Box::pin(async move {
                info!("{} UDP listening at: {}:{}", name, addr, port,);
                udp_listener
                    .listen_udp()
                    .await
                    .inspect_err(|x| {
                        error!("handler {} udp listen failed: {x}", name);
                    })
                    .map_err(|e| e.into())
            }));
        }

        if runners.is_empty() {
            warn!("no listener for {}", name);
            return None;
        }
        Some(runners)
    } else {
        None
    }
}

fn build_handler(
    listener: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    #[allow(unused)] users_rx: Option<
        tokio::sync::watch::Receiver<Vec<InboundUser>>,
    >,
) -> Option<Arc<dyn InboundHandlerTrait>> {
    let fw_mark = listener.common_opts().fw_mark;
    match listener {
        InboundOpts::Http { common_opts, .. } => Some(Arc::new(HttpInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),

        InboundOpts::Socks { common_opts, .. } => Some(Arc::new(SocksInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),
        InboundOpts::Mixed { common_opts, .. } => Some(Arc::new(MixedInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),
        #[cfg(feature = "tproxy")]
        InboundOpts::TProxy {
            #[cfg(target_os = "linux")]
            common_opts,
            ..
        } => {
            #[cfg(target_os = "linux")]
            {
                Some(Arc::new(TproxyInbound::new(
                    (common_opts.listen.0, common_opts.port).into(),
                    common_opts.allow_lan,
                    dispatcher,
                    fw_mark,
                )))
            }

            #[cfg(not(target_os = "linux"))]
            {
                warn!("tproxy is not supported on this platform");
                None
            }
        }
        #[cfg(feature = "redir")]
        InboundOpts::Redir {
            #[cfg(target_os = "linux")]
            common_opts,
            ..
        } => {
            #[cfg(target_os = "linux")]
            {
                Some(Arc::new(RedirInbound::new(
                    (common_opts.listen.0, common_opts.port).into(),
                    common_opts.allow_lan,
                    dispatcher,
                    fw_mark,
                )))
            }
            #[cfg(not(target_os = "linux"))]
            {
                warn!("redir is not supported on this platform");
                None
            }
        }
        InboundOpts::Tunnel {
            common_opts,
            network,
            target,
        } => TunnelInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            dispatcher,
            network.clone(),
            target.clone(),
            fw_mark,
        )
        .inspect_err(|x| {
            warn!("tunnel inbound handler failed to create: {x}");
        })
        .map(|x| Arc::new(x) as _)
        .ok(),
        #[cfg(feature = "shadowsocks")]
        InboundOpts::Shadowsocks {
            common_opts,
            udp,
            cipher,
            password,
            users,
        } => {
            // Use the provided watch receiver, or create a static one for
            // non-provider (static config) inbounds whose user list never changes.
            let rx = users_rx
                .unwrap_or_else(|| tokio::sync::watch::channel(users.clone()).1);
            Some(Arc::new(ShadowsocksInbound::new(InboundOptions {
                addr: (common_opts.listen.0, common_opts.port).into(),
                password: password.clone(),
                udp: *udp,
                cipher: cipher.clone(),
                allow_lan: common_opts.allow_lan,
                dispatcher,
                authenticator,
                fw_mark: common_opts.fw_mark,
                users_rx: rx,
            })))
        }
        InboundOpts::Anytls {
            common_opts,
            password,
            certificate,
            private_key,
            fallback,
            users,
        } => {
            let rx = users_rx
                .unwrap_or_else(|| tokio::sync::watch::channel(users.clone()).1);
            match AnytlsInbound::new(AnytlsInboundOptions {
                addr: (common_opts.listen.0, common_opts.port).into(),
                password: password.clone(),
                certificate: certificate.clone(),
                private_key: private_key.clone(),
                fallback: fallback.clone(),
                allow_lan: common_opts.allow_lan,
                dispatcher,
                fw_mark: common_opts.fw_mark,
                users_rx: rx,
            }) {
                Ok(h) => Some(Arc::new(h)),
                Err(e) => {
                    warn!("anytls inbound failed to init: {e}");
                    None
                }
            }
        }
        InboundOpts::Vless {
            common_opts,
            uuid,
            users,
            transport,
        } => {
            if !transport.typ.eq_ignore_ascii_case("ws") {
                warn!(
                    "vless inbound {} only supports websocket transport",
                    common_opts.name
                );
                return None;
            }

            match VlessInbound::new(VlessInboundOptions {
                addr: (common_opts.listen.0, common_opts.port).into(),
                allow_lan: common_opts.allow_lan,
                dispatcher,
                fw_mark: common_opts.fw_mark,
                uuid: uuid.clone(),
                users: users
                    .iter()
                    .map(|user| RuntimeVlessInboundUser {
                        uuid: user.uuid.clone(),
                        name: user.name.clone(),
                    })
                    .collect(),
                ws: WsInboundOptions {
                    path: transport.path.clone(),
                    early_data_header_name: transport.early_data_header_name.clone(),
                },
            }) {
                Ok(h) => Some(Arc::new(h)),
                Err(e) => {
                    warn!("vless inbound failed to init: {e}");
                    None
                }
            }
        }
        InboundOpts::Hysteria2 {
            common_opts,
            password,
            certificate,
            private_key,
            acme,
            obfs,
            obfs_password,
            users,
            sni_guard,
            masquerade,
        } => {
            let rx = users_rx
                .unwrap_or_else(|| tokio::sync::watch::channel(users.clone()).1);
            let acme = acme.as_ref().map(|acme| {
                let challenge = match acme.challenge {
                    crate::config::internal::listener::Hysteria2AcmeChallenge::TlsAlpn01 => {
                        Hysteria2AcmeChallenge::TlsAlpn01
                    }
                    crate::config::internal::listener::Hysteria2AcmeChallenge::Dns01 => {
                        let dns = acme
                            .dns
                            .as_ref()
                            .expect("hysteria2 dns-01 config validated");
                        let cloudflare = dns
                            .cloudflare
                            .as_ref()
                            .expect("hysteria2 cloudflare dns config validated");
                        let auth = match cloudflare.api_key.as_deref() {
                            Some(key) if !key.trim().is_empty() => {
                                Hysteria2CloudflareAuth::GlobalKey {
                                    email: cloudflare
                                        .auth_email
                                        .as_ref()
                                        .expect("cloudflare auth-email validated")
                                        .trim()
                                        .to_owned(),
                                    key: key.trim().to_owned(),
                                }
                            }
                            _ => Hysteria2CloudflareAuth::ApiToken(
                                cloudflare
                                    .api_token
                                    .as_ref()
                                    .expect("cloudflare api-token validated")
                                    .trim()
                                    .to_owned(),
                            ),
                        };
                        Hysteria2AcmeChallenge::Dns01 {
                            cloudflare: Hysteria2CloudflareDnsOptions {
                                auth,
                                zone_id: cloudflare.zone_id.clone(),
                                ttl: cloudflare.ttl,
                                propagation_delay: Duration::from_secs(
                                    cloudflare.propagation_delay.unwrap_or(30),
                                ),
                            },
                        }
                    }
                };
                Hysteria2AcmeOptions {
                    domain: acme.domain.clone(),
                    email: acme.email.clone(),
                    cache_dir: acme
                        .cache_dir
                        .as_ref()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| {
                            default_hysteria2_acme_cache_dir(&acme.domain)
                        }),
                    production: acme.production,
                    challenge,
                }
            });
            let obfs = obfs.as_ref().map(|obfs| {
                let password = obfs
                    .salamander_password(obfs_password.as_deref())
                    .expect("hysteria2 obfs password validated")
                    .to_owned();
                Hysteria2ObfsOptions::Salamander { password }
            });
            let sni_guard = match sni_guard {
                crate::config::internal::listener::Hysteria2SniGuard::Disable => {
                    Hysteria2SniGuardMode::Disable
                }
                crate::config::internal::listener::Hysteria2SniGuard::DnsSan => {
                    Hysteria2SniGuardMode::DnsSan
                }
                crate::config::internal::listener::Hysteria2SniGuard::Strict => {
                    Hysteria2SniGuardMode::Strict
                }
            };
            let masquerade = masquerade
                .as_ref()
                .map(|masquerade| match masquerade.typ {
                    crate::config::internal::listener::Hysteria2MasqueradeType::NotFound => {
                        Hysteria2MasqueradeOptions::NotFound
                    }
                    crate::config::internal::listener::Hysteria2MasqueradeType::File => {
                        let file = masquerade
                            .file
                            .as_ref()
                            .expect("hysteria2 masquerade file config validated");
                        Hysteria2MasqueradeOptions::File {
                            dir: PathBuf::from(&file.dir),
                        }
                    }
                    crate::config::internal::listener::Hysteria2MasqueradeType::Proxy => {
                        let proxy = masquerade
                            .proxy
                            .as_ref()
                            .expect("hysteria2 masquerade proxy config validated");
                        Hysteria2MasqueradeOptions::Proxy {
                            url: proxy.url.clone(),
                            rewrite_host: proxy.rewrite_host,
                            x_forwarded: proxy.x_forwarded,
                            insecure: proxy.insecure,
                        }
                    }
                    crate::config::internal::listener::Hysteria2MasqueradeType::String => {
                        let string = masquerade
                            .string
                            .as_ref()
                            .expect("hysteria2 masquerade string config validated");
                        Hysteria2MasqueradeOptions::String {
                            content: string.content.clone(),
                            headers: string
                                .headers
                                .iter()
                                .map(|(name, value)| (name.clone(), value.clone()))
                                .collect(),
                            status_code: string.status_code,
                        }
                    }
                })
                .unwrap_or_default();

            match Hysteria2Inbound::new(Hysteria2InboundOptions {
                addr: (common_opts.listen.0, common_opts.port).into(),
                password: password.clone(),
                certificate: certificate.clone(),
                private_key: private_key.clone(),
                acme,
                obfs,
                sni_guard,
                masquerade,
                allow_lan: common_opts.allow_lan,
                dispatcher,
                fw_mark: common_opts.fw_mark,
                users_rx: rx,
            }) {
                Ok(h) => Some(Arc::new(h)),
                Err(e) => {
                    warn!("hysteria2 inbound failed to init: {e}");
                    None
                }
            }
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
        } => match ShadowQuicInbound::new(ShadowQuicInboundOptions {
            addr: (common_opts.listen.0, common_opts.port).into(),
            allow_lan: common_opts.allow_lan,
            dispatcher,
            fw_mark: common_opts.fw_mark,
            username: username.clone(),
            password: password.clone(),
            users: users.clone(),
            server_name: server_name.clone(),
            jls_upstream: jls_upstream.clone(),
            alpn: alpn.clone(),
            zero_rtt: *zero_rtt,
            congestion_control: congestion_control.clone(),
            initial_mtu: *initial_mtu,
            min_mtu: *min_mtu,
            gso: *gso,
            mtu_discovery: *mtu_discovery,
            blackhole_detection: *blackhole_detection,
        }) {
            Ok(h) => Some(Arc::new(h)),
            Err(e) => {
                warn!("shadowquic inbound failed to init: {e}");
                None
            }
        },
    }
}

fn default_hysteria2_acme_cache_dir(domain: &str) -> PathBuf {
    let safe_domain: String = domain
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    PathBuf::from("./hysteria2-acme-cache").join(safe_domain)
}
