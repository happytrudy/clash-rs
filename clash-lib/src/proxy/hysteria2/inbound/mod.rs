mod acme_store;
mod dns_acme;

use std::{
    collections::HashMap,
    fmt, io,
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use h3_quinn::Connection as H3QuinnConnection;
use quinn::{Endpoint, EndpointConfig, ServerConfig, TokioRuntime};
use quinn_proto::{TransportConfig, crypto::rustls::QuicServerConfig};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_acme::{AcmeConfig, EventOk, UseChallenge};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, mpsc, watch},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

use super::salamander;
use crate::{
    Dispatcher,
    common::{errors::new_io_error, tls::load_cert_and_key},
    config::internal::listener::InboundUser,
    proxy::{
        datagram::UdpPacket,
        hysteria2::codec::{
            Defragger, Fragments, Hy2TcpReqCodec, Hy2TcpRespEncoder, Hy2TcpRespMsg,
            HysUdpPacket, padding,
        },
        inbound::InboundHandlerTrait,
        utils::{
            ToCanonical, try_create_dualstack_socket,
            try_create_dualstack_tcplistener,
        },
    },
    session::{Network, Session, SocksAddr, Type},
};

const HYSTERIA2_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HYSTERIA2_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const HYSTERIA2_TCP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const HYSTERIA2_ACME_TLS_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_CHANNEL_SIZE: usize = 64;
const MAX_UDP_SESSIONS_PER_CONN: usize = 512;
const MAX_UDP_INFLIGHT_PACKETS_PER_SESSION: usize = 64;
const MAX_UDP_FRAGMENTS_PER_PACKET: u8 = 64;
const UDP_FRAGMENT_TTL: Duration = Duration::from_secs(30);
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const UDP_SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const MAX_MASQUERADE_PROXY_BODY: usize = 1 * 1024 * 1024;
const MAX_MASQUERADE_FILE_SIZE: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SniGuardMode {
    Disable,
    DnsSan,
    Strict,
}

#[derive(Clone, Debug)]
pub struct AcmeOptions {
    pub domain: String,
    pub email: Option<String>,
    pub cache_dir: PathBuf,
    pub production: bool,
    pub challenge: AcmeChallenge,
}

#[derive(Clone, Debug)]
pub enum AcmeChallenge {
    TlsAlpn01,
    Dns01 { cloudflare: CloudflareDnsOptions },
}

#[derive(Clone, Debug)]
pub enum CloudflareAuth {
    ApiToken(String),
    GlobalKey { email: String, key: String },
}

#[derive(Clone, Debug)]
pub struct CloudflareDnsOptions {
    pub auth: CloudflareAuth,
    pub zone_id: Option<String>,
    pub ttl: Option<u32>,
    pub propagation_delay: Duration,
}

#[derive(Clone, Debug)]
pub enum ObfsOptions {
    Salamander { password: String },
}

#[derive(Clone, Debug)]
pub enum MasqueradeOptions {
    Default,
    NotFound,
    File {
        dir: PathBuf,
    },
    Proxy {
        url: String,
        rewrite_host: bool,
        x_forwarded: bool,
        insecure: bool,
    },
    String {
        content: String,
        headers: Vec<(String, String)>,
        status_code: Option<u16>,
    },
}

impl Default for MasqueradeOptions {
    fn default() -> Self {
        Self::Default
    }
}

pub struct InboundOptions {
    pub addr: SocketAddr,
    pub password: String,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    pub acme: Option<AcmeOptions>,
    pub obfs: Option<ObfsOptions>,
    pub sni_guard: SniGuardMode,
    pub masquerade: MasqueradeOptions,
    pub allow_lan: bool,
    pub dispatcher: Arc<Dispatcher>,
    pub fw_mark: Option<u32>,
    pub users_rx: tokio::sync::watch::Receiver<Vec<InboundUser>>,
}

pub struct Hysteria2Inbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
    server_config: ServerConfig,
    password: String,
    obfs: Option<ObfsOptions>,
    masquerade: Arc<Masquerade>,
    users_rx: tokio::sync::watch::Receiver<Vec<InboundUser>>,
    acme_tasks: Option<AcmeTasks>,
}

impl Drop for Hysteria2Inbound {
    fn drop(&mut self) {
        warn!("Hysteria2 inbound listener on {} stopped", self.addr);
    }
}

impl Hysteria2Inbound {
    pub fn new(opts: InboundOptions) -> io::Result<Self> {
        let (server_config, acme_tasks) = build_server_config(
            opts.addr,
            opts.certificate.as_deref(),
            opts.private_key.as_deref(),
            opts.acme.as_ref(),
            opts.sni_guard,
        )?;
        let masquerade = Arc::new(Masquerade::try_from_options(opts.masquerade)?);

        Ok(Self {
            addr: opts.addr,
            allow_lan: opts.allow_lan,
            dispatcher: opts.dispatcher,
            fw_mark: opts.fw_mark,
            server_config,
            password: opts.password,
            obfs: opts.obfs,
            masquerade,
            users_rx: opts.users_rx,
            acme_tasks,
        })
    }

    async fn wait_for_initial_certificate(&self) -> io::Result<()> {
        let Some(mut cert_state) = self
            .acme_tasks
            .as_ref()
            .and_then(AcmeTasks::cert_state_receiver)
        else {
            return Ok(());
        };

        let mut logged_wait = false;
        loop {
            match cert_state.borrow_and_update().clone() {
                dns_acme::Dns01CertState::Ready => return Ok(()),
                dns_acme::Dns01CertState::Failed(err) => {
                    return Err(io::Error::other(format!(
                        "hysteria2 inbound {}: acme dns-01 failed before a \
                         certificate became available: {err}",
                        self.addr
                    )));
                }
                dns_acme::Dns01CertState::Pending => {
                    if !logged_wait {
                        info!(
                            "hysteria2 inbound {}: waiting for dns-01 acme \
                             certificate before accepting QUIC handshakes",
                            self.addr
                        );
                        logged_wait = true;
                    }
                }
            }

            if cert_state.changed().await.is_err() {
                return Err(io::Error::other(format!(
                    "hysteria2 inbound {}: acme dns-01 certificate task exited \
                     before a certificate became available",
                    self.addr
                )));
            }
        }
    }
}

#[async_trait]
impl InboundHandlerTrait for Hysteria2Inbound {
    fn handle_tcp(&self) -> bool {
        false
    }

    fn handle_udp(&self) -> bool {
        true
    }

    async fn listen_tcp(&self) -> io::Result<()> {
        Ok(())
    }

    async fn listen_udp(&self) -> io::Result<()> {
        self.wait_for_initial_certificate().await?;
        let endpoint = create_quic_endpoint(
            self.addr,
            self.server_config.clone(),
            self.obfs.as_ref(),
        )?;
        let local_addr = endpoint.local_addr()?;

        let mut users_rx = self.users_rx.clone();
        let mut user_map =
            build_user_map(&users_rx.borrow_and_update(), &self.password);

        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    let source = incoming.remote_address().to_canonical();
                    let local_ip = incoming
                        .local_ip()
                        .unwrap_or_else(|| local_addr.ip().to_canonical());

                    if !source_allowed(self.allow_lan, source, local_ip) {
                        warn!(
                            "hysteria2 inbound {}: connection from {} rejected \
                             (not allowed, local ip {})",
                            self.addr, source, local_ip
                        );
                        incoming.ignore();
                        continue;
                    }

                    let conn = match timeout(HYSTERIA2_HANDSHAKE_TIMEOUT, incoming).await {
                        Ok(Ok(conn)) => conn,
                        Ok(Err(e)) => {
                            warn!("hysteria2 inbound {}: handshake from {} failed: {e}", self.addr, source);
                            continue;
                        }
                        Err(_) => {
                            warn!("hysteria2 inbound {}: handshake from {} timed out", self.addr, source);
                            continue;
                        }
                    };

                    let dispatcher = self.dispatcher.clone();
                    let fw_mark = self.fw_mark;
                    let users = Arc::clone(&user_map);
                    let masquerade = Arc::clone(&self.masquerade);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(conn, source, dispatcher, fw_mark, users, masquerade).await {
                            debug!("hysteria2 inbound connection {source} ended: {e}");
                        }
                    });
                }

                Ok(()) = users_rx.changed() => {
                    user_map = build_user_map(&users_rx.borrow_and_update(), &self.password);
                    info!(
                        "hysteria2 inbound {}: user list updated ({} users)",
                        self.addr,
                        user_map.len()
                    );
                }
            }
        }

        Ok(())
    }
}

fn build_server_config(
    addr: SocketAddr,
    certificate: Option<&str>,
    private_key: Option<&str>,
    acme: Option<&AcmeOptions>,
    sni_guard: SniGuardMode,
) -> io::Result<(ServerConfig, Option<AcmeTasks>)> {
    let (mut tls_config, acme_tasks) = match (certificate, private_key, acme) {
        (Some(cert), Some(key), None) => {
            let (certs, key) = load_cert_and_key(cert, key)?;
            let dns_names = certificate_dns_names(&certs)?;
            if sni_guard != SniGuardMode::Disable && dns_names.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "hysteria2 TLS certificate has no DNS SAN for SNI guard",
                ));
            }
            let signing_key = any_supported_signing_key(&key).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("hysteria2 TLS private key error: {e}"),
                )
            })?;
            let resolver = guarded_cert_resolver(
                Arc::new(FixedCertResolver::new(CertifiedKey::new(
                    certs,
                    signing_key,
                ))),
                dns_names,
                sni_guard,
            );
            let tls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver);
            (tls_config, None)
        }
        (None, None, Some(acme)) => build_acme_tls_config(addr, acme, sni_guard)?,
        (None, None, None) => {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                    .map_err(|e| {
                        io::Error::other(format!(
                            "failed to generate ephemeral hysteria2 certificate: {e}"
                        ))
                    })?;
            let cert_der =
                rustls::pki_types::CertificateDer::from(cert.der().to_vec());
            let key_der = rustls::pki_types::PrivateKeyDer::try_from(
                signing_key.serialize_der(),
            )
            .map_err(|e| {
                io::Error::other(format!(
                    "failed to serialize ephemeral hysteria2 key: {e}"
                ))
            })?;
            let tls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("hysteria2 TLS config error: {e}"),
                    )
                })?;
            (tls_config, None)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria2 inbound: certificate and private-key must both be \
                 set, both omitted, or replaced by acme",
            ));
        }
    };

    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_config = QuicServerConfig::try_from(tls_config).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("hysteria2 QUIC TLS config error: {e}"),
        )
    })?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_config));
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(300)
            .try_into()
            .expect("valid hysteria2 idle timeout"),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.datagram_receive_buffer_size(Some(16 * 1024 * 1024));
    server_config.transport_config(Arc::new(transport));

    Ok((server_config, acme_tasks))
}

#[derive(Debug)]
struct FixedCertResolver {
    cert: Arc<CertifiedKey>,
}

impl FixedCertResolver {
    fn new(cert: CertifiedKey) -> Self {
        Self {
            cert: Arc::new(cert),
        }
    }
}

impl ResolvesServerCert for FixedCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.cert))
    }
}

#[derive(Debug)]
struct SniGuardResolver {
    inner: Arc<dyn ResolvesServerCert>,
    names: Vec<String>,
    strict: bool,
}

impl SniGuardResolver {
    fn new(
        inner: Arc<dyn ResolvesServerCert>,
        names: impl IntoIterator<Item = String>,
        strict: bool,
    ) -> Self {
        Self {
            inner,
            names: normalize_dns_names(names),
            strict,
        }
    }
}

impl ResolvesServerCert for SniGuardResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?.to_owned();
        let matched = if self.strict {
            let sni = sni.trim_end_matches('.').to_ascii_lowercase();
            self.names.iter().any(|name| name == &sni)
        } else {
            self.names
                .iter()
                .any(|name| dns_name_matches(name.as_str(), sni.as_str()))
        };

        if matched {
            return self.inner.resolve(client_hello);
        }

        debug!(
            "hysteria2 inbound rejected TLS ClientHello with unmatched SNI {sni}"
        );
        None
    }
}

fn guarded_cert_resolver(
    inner: Arc<dyn ResolvesServerCert>,
    names: Vec<String>,
    mode: SniGuardMode,
) -> Arc<dyn ResolvesServerCert> {
    match mode {
        SniGuardMode::Disable => inner,
        SniGuardMode::DnsSan => Arc::new(SniGuardResolver::new(inner, names, false)),
        SniGuardMode::Strict => Arc::new(SniGuardResolver::new(inner, names, true)),
    }
}

fn certificate_dns_names(
    certs: &[CertificateDer<'static>],
) -> io::Result<Vec<String>> {
    let cert = certs.first().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "certificate chain is empty")
    })?;
    let (_, cert) = parse_x509_certificate(cert.as_ref()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("failed to parse certificate for SNI guard: {e}"),
        )
    })?;
    let Some(san) = cert.subject_alternative_name().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("failed to parse certificate SAN for SNI guard: {e}"),
        )
    })?
    else {
        return Ok(Vec::new());
    };

    let names = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(name) => Some((*name).to_owned()),
            _ => None,
        });
    Ok(normalize_dns_names(names))
}

fn normalize_dns_names(names: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut names = names
        .into_iter()
        .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

fn dns_name_matches(pattern: &str, name: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if pattern == name {
        return true;
    }

    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let Some(prefix) = name.strip_suffix(suffix) else {
        return false;
    };
    let Some(label) = prefix.strip_suffix('.') else {
        return false;
    };
    !label.is_empty() && !label.contains('.')
}

#[cfg(feature = "aws-lc-rs")]
fn any_supported_signing_key(
    key: &PrivateKeyDer<'_>,
) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
    rustls::crypto::aws_lc_rs::sign::any_supported_type(key)
}

#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
fn any_supported_signing_key(
    key: &PrivateKeyDer<'_>,
) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
    rustls::crypto::ring::sign::any_supported_type(key)
}

fn build_acme_tls_config(
    addr: SocketAddr,
    acme: &AcmeOptions,
    sni_guard: SniGuardMode,
) -> io::Result<(rustls::ServerConfig, Option<AcmeTasks>)> {
    match &acme.challenge {
        AcmeChallenge::TlsAlpn01 => {
            build_tls_alpn_acme_config(addr, acme, sni_guard)
        }
        AcmeChallenge::Dns01 { cloudflare } => {
            build_dns01_acme_config(acme, cloudflare, sni_guard)
        }
    }
}

fn build_tls_alpn_acme_config(
    addr: SocketAddr,
    acme: &AcmeOptions,
    sni_guard: SniGuardMode,
) -> io::Result<(rustls::ServerConfig, Option<AcmeTasks>)> {
    acme_store::ensure_private_dir_sync(&acme.cache_dir).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "hysteria2 acme: failed to prepare private cache dir {}: {e}",
                acme.cache_dir.display()
            ),
        )
    })?;

    let mut config = AcmeConfig::new([acme.domain.clone()])
        .cache(acme_store::PrivateDirCache::new(acme.cache_dir.clone()))
        .directory_lets_encrypt(acme.production)
        .challenge_type(UseChallenge::TlsAlpn01);

    if let Some(email) = acme.email.as_deref()
        && !email.is_empty()
    {
        let contact = if email.starts_with("mailto:") {
            email.to_owned()
        } else {
            format!("mailto:{email}")
        };
        config = config.contact([contact]);
    }

    let mut state = config.state();
    let resolver = state.resolver();
    let resolver =
        guarded_cert_resolver(resolver, vec![acme.domain.clone()], sni_guard);
    let challenge_config = state.challenge_rustls_config();
    let challenge = spawn_tls_alpn_challenge_listener(addr, challenge_config)?;

    let driver_domain = acme.domain.clone();
    let driver = tokio::spawn(async move {
        while let Some(event) = state.next().await {
            match event {
                Ok(EventOk::DeployedCachedCert) => {
                    info!(
                        "hysteria2 acme: deployed cached certificate for {}",
                        driver_domain
                    );
                }
                Ok(EventOk::DeployedNewCert) => {
                    info!(
                        "hysteria2 acme: deployed new certificate for {}",
                        driver_domain
                    );
                }
                Ok(EventOk::AccountCacheStore | EventOk::CertCacheStore) => {}
                Err(e) => {
                    warn!(
                        "hysteria2 acme: certificate task error for {driver_domain}: {e}"
                    );
                }
            }
        }
    });

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    Ok((tls_config, Some(AcmeTasks::new(vec![driver, challenge]))))
}

fn build_dns01_acme_config(
    acme: &AcmeOptions,
    cloudflare: &CloudflareDnsOptions,
    sni_guard: SniGuardMode,
) -> io::Result<(rustls::ServerConfig, Option<AcmeTasks>)> {
    let resolver = Arc::new(dns_acme::Dns01CertResolver::new());
    let opts = dns_acme::Dns01AcmeOptions {
        domain: acme.domain.clone(),
        email: acme.email.clone(),
        cache_dir: acme.cache_dir.clone(),
        production: acme.production,
        cloudflare: cloudflare.clone(),
    };

    if let Err(e) = dns_acme::load_cached_certificate(&opts, Arc::clone(&resolver)) {
        warn!(
            "hysteria2 acme dns-01: failed to load cached certificate for {}: {e}",
            acme.domain
        );
    }

    let driver_domain = acme.domain.clone();
    let driver_resolver = Arc::clone(&resolver);
    let driver = tokio::spawn(async move {
        dns_acme::run_dns01_acme(opts, driver_resolver).await;
        warn!("hysteria2 acme dns-01: certificate task for {driver_domain} exited");
    });

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(guarded_cert_resolver(
            resolver.clone(),
            vec![acme.domain.clone()],
            sni_guard,
        ));
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    Ok((
        tls_config,
        Some(AcmeTasks::with_cert_state(
            vec![driver],
            resolver.subscribe_state(),
        )),
    ))
}

fn spawn_tls_alpn_challenge_listener(
    addr: SocketAddr,
    config: Arc<rustls::ServerConfig>,
) -> io::Result<JoinHandle<()>> {
    let listener = try_create_dualstack_tcplistener(addr).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "hysteria2 acme: failed to bind TLS-ALPN-01 challenge listener \
                 on TCP {addr}: {e}"
            ),
        )
    })?;

    Ok(tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(config);
        info!("hysteria2 acme: TLS-ALPN-01 challenge listener active on TCP {addr}");

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    warn!("hysteria2 acme: challenge accept error on {addr}: {e}");
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                match timeout(HYSTERIA2_ACME_TLS_TIMEOUT, acceptor.accept(stream))
                    .await
                {
                    Ok(Ok(mut tls_stream)) => {
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls_stream)
                            .await;
                    }
                    Ok(Err(e)) => {
                        debug!(
                            "hysteria2 acme: challenge TLS from {peer} failed: {e}"
                        );
                    }
                    Err(_) => {
                        debug!(
                            "hysteria2 acme: challenge TLS from {peer} timed out"
                        );
                    }
                }
            });
        }
    }))
}

struct AcmeTasks {
    handles: Vec<JoinHandle<()>>,
    cert_state: Option<watch::Receiver<dns_acme::Dns01CertState>>,
}

impl AcmeTasks {
    fn new(handles: Vec<JoinHandle<()>>) -> Self {
        Self {
            handles,
            cert_state: None,
        }
    }

    fn with_cert_state(
        handles: Vec<JoinHandle<()>>,
        cert_state: watch::Receiver<dns_acme::Dns01CertState>,
    ) -> Self {
        Self {
            handles,
            cert_state: Some(cert_state),
        }
    }

    fn cert_state_receiver(
        &self,
    ) -> Option<watch::Receiver<dns_acme::Dns01CertState>> {
        self.cert_state.clone()
    }
}

impl Drop for AcmeTasks {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

fn create_quic_endpoint(
    addr: SocketAddr,
    server_config: ServerConfig,
    obfs: Option<&ObfsOptions>,
) -> io::Result<Endpoint> {
    let (socket, _dualstack) =
        try_create_dualstack_socket(addr, socket2::Type::DGRAM)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    let socket: std::net::UdpSocket = socket.into();
    if let Some(ObfsOptions::Salamander { password }) = obfs {
        let socket =
            salamander::Salamander::new(socket, password.as_bytes().to_vec())?;
        return Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_config),
            Arc::new(socket),
            Arc::new(TokioRuntime),
        );
    }

    Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(TokioRuntime),
    )
}

type UserMap = HashMap<String, Option<String>>;

fn build_user_map(users: &[InboundUser], fallback_password: &str) -> Arc<UserMap> {
    let mut map = HashMap::new();
    if users.is_empty() {
        if !fallback_password.is_empty() {
            map.insert(fallback_password.to_owned(), None);
        }
        return Arc::new(map);
    }

    for user in users {
        map.insert(user.password.clone(), Some(user.name.clone()));
    }
    Arc::new(map)
}

fn source_allowed(allow_lan: bool, source: SocketAddr, local_ip: IpAddr) -> bool {
    allow_lan
        || source.ip() == local_ip
        || (local_ip.is_unspecified() && source.ip().is_loopback())
}

async fn handle_connection(
    conn: quinn::Connection,
    source: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
    users: Arc<UserMap>,
    masquerade: Arc<Masquerade>,
) -> io::Result<()> {
    let inbound_user = timeout(
        HYSTERIA2_AUTH_TIMEOUT,
        authenticate(&conn, users.as_ref(), masquerade.as_ref(), source),
    )
    .await
    .map_err(|_| {
        io::Error::new(io::ErrorKind::TimedOut, "hysteria2 auth timeout")
    })??;

    let conn = Arc::new(conn);
    let udp_sessions = Arc::new(Mutex::new(HashMap::<u32, UdpSessionEntry>::new()));

    let udp_task = tokio::spawn(handle_udp_datagrams(
        Arc::clone(&conn),
        source,
        Arc::clone(&dispatcher),
        fw_mark,
        inbound_user.clone(),
        Arc::clone(&udp_sessions),
    ));
    let udp_cleanup_task =
        tokio::spawn(cleanup_udp_sessions_loop(Arc::clone(&udp_sessions)));

    let tcp_result = handle_tcp_streams(
        Arc::clone(&conn),
        source,
        dispatcher,
        fw_mark,
        inbound_user,
    )
    .await;
    udp_task.abort();
    udp_cleanup_task.abort();
    tcp_result
}

async fn authenticate(
    conn: &quinn::Connection,
    users: &UserMap,
    masquerade: &Masquerade,
    source: SocketAddr,
) -> io::Result<Option<String>> {
    let h3_conn = H3QuinnConnection::new(conn.clone());
    let mut h3_server = h3::server::builder()
        .build::<_, Bytes>(h3_conn)
        .await
        .map_err(|e| io::Error::other(format!("hysteria2 h3 server: {e}")))?;

    let resolver = h3_server
        .accept()
        .await
        .map_err(|e| io::Error::other(format!("hysteria2 auth accept: {e}")))?
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "missing auth request")
        })?;

    let (req, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|e| io::Error::other(format!("hysteria2 auth request: {e}")))?;

    if !is_hysteria_auth_request(&req) {
        send_masquerade_h3_response(&req, &mut stream, masquerade, source).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid hysteria2 auth request",
        ));
    }

    let auth = req
        .headers()
        .get("Hysteria-Auth")
        .and_then(|v| v.to_str().ok());
    let inbound_user = auth
        .and_then(|password| users.get(password).cloned())
        .flatten();
    let authed = auth.is_some_and(|password| users.contains_key(password));

    if !authed {
        send_masquerade_h3_response(&req, &mut stream, masquerade, source).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "hysteria2 authentication failed",
        ));
    }

    let padding = padding(64..=512);
    let padding = http::HeaderValue::from_bytes(&padding).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid hysteria2 response padding: {e}"),
        )
    })?;

    let response = http::Response::builder()
        .status(http::StatusCode::from_u16(233).expect("valid hysteria2 status"))
        .header("Hysteria-CC-RX", "auto")
        .header("Hysteria-UDP", "true")
        .header("Hysteria-Padding", padding)
        .body(())
        .map_err(|e| io::Error::other(format!("hysteria2 auth response: {e}")))?;
    stream.send_response(response).await.map_err(|e| {
        io::Error::other(format!("hysteria2 auth response send: {e}"))
    })?;
    stream.finish().await.map_err(|e| {
        io::Error::other(format!("hysteria2 auth response finish: {e}"))
    })?;

    Ok(inbound_user)
}

fn is_hysteria_auth_request(req: &http::Request<()>) -> bool {
    req.method() == http::Method::POST
        && req.uri().path() == "/auth"
        && req.uri().authority().is_some_and(|authority| {
            authority.as_str().eq_ignore_ascii_case("hysteria")
        })
}

#[derive(Clone)]
enum Masquerade {
    Default,
    NotFound,
    File {
        dir: PathBuf,
    },
    Proxy {
        client: reqwest::Client,
        url: url::Url,
        rewrite_host: bool,
        x_forwarded: bool,
    },
    String {
        body: Bytes,
        headers: Vec<(http::HeaderName, http::HeaderValue)>,
        status: http::StatusCode,
    },
}

struct MasqueradeResponse {
    status: http::StatusCode,
    headers: Vec<(http::HeaderName, http::HeaderValue)>,
    body: Bytes,
}

impl Masquerade {
    fn try_from_options(options: MasqueradeOptions) -> io::Result<Self> {
        match options {
            MasqueradeOptions::Default => Ok(Self::Default),
            MasqueradeOptions::NotFound => Ok(Self::NotFound),
            MasqueradeOptions::File { dir } => Ok(Self::File { dir }),
            MasqueradeOptions::Proxy {
                url,
                rewrite_host,
                x_forwarded,
                insecure,
            } => {
                let url = url::Url::parse(url.as_str()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid hysteria2 masquerade proxy url: {e}"),
                    )
                })?;
                let client = reqwest::Client::builder()
                    .danger_accept_invalid_certs(insecure)
                    .build()
                    .map_err(|e| {
                        io::Error::other(format!(
                            "failed to build hysteria2 masquerade proxy client: {e}"
                        ))
                    })?;
                Ok(Self::Proxy {
                    client,
                    url,
                    rewrite_host,
                    x_forwarded,
                })
            }
            MasqueradeOptions::String {
                content,
                headers,
                status_code,
            } => {
                let status_code = status_code
                    .filter(|status_code| *status_code != 0)
                    .unwrap_or(200);
                let status =
                    http::StatusCode::from_u16(status_code).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "invalid hysteria2 masquerade string status: {e}"
                            ),
                        )
                    })?;
                if status.as_u16() == 233 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "hysteria2 masquerade string status 233 is reserved",
                    ));
                }

                let headers = headers
                    .into_iter()
                    .map(|(name, value)| {
                        let name = http::HeaderName::from_bytes(name.as_bytes())
                            .map_err(|e| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    format!(
                                        "invalid hysteria2 masquerade header \
                                         name: {e}"
                                    ),
                                )
                            })?;
                        let value = http::HeaderValue::from_str(value.as_str())
                            .map_err(|e| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    format!(
                                        "invalid hysteria2 masquerade header \
                                         value: {e}"
                                    ),
                                )
                            })?;
                        Ok((name, value))
                    })
                    .collect::<io::Result<_>>()?;

                Ok(Self::String {
                    body: Bytes::from(content),
                    headers,
                    status,
                })
            }
        }
    }

    async fn response(
        &self,
        req: &http::Request<()>,
    ) -> io::Result<MasqueradeResponse> {
        match self {
            Self::Default => Ok(default_masquerade_response(req)),
            Self::NotFound => Ok(not_found_masquerade_response()),
            Self::String {
                body,
                headers,
                status,
            } => Ok(MasqueradeResponse {
                status: *status,
                headers: headers.clone(),
                body: body.clone(),
            }),
            Self::File { dir } => file_masquerade_response(dir, req).await,
            Self::Proxy { .. } => unreachable!("proxy is handled by send_proxy"),
        }
    }
}

async fn send_masquerade_h3_response(
    req: &http::Request<()>,
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    masquerade: &Masquerade,
    source: SocketAddr,
) -> io::Result<()> {
    if let Masquerade::Proxy {
        client,
        url,
        rewrite_host,
        x_forwarded,
    } = masquerade
    {
        return send_proxy_masquerade_h3_response(
            req,
            stream,
            client,
            url,
            *rewrite_host,
            *x_forwarded,
            source,
        )
        .await;
    }

    let response = masquerade.response(req).await?;
    send_h3_response(req, stream, response).await
}

async fn send_h3_response(
    req: &http::Request<()>,
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    response: MasqueradeResponse,
) -> io::Result<()> {
    let body = response.body;
    let mut builder = http::Response::builder()
        .status(response.status)
        .header("content-length", body.len().to_string());
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }
    let h3_response = builder.body(()).map_err(|e| {
        io::Error::other(format!("hysteria2 masquerade response: {e}"))
    })?;
    stream.send_response(h3_response).await.map_err(|e| {
        io::Error::other(format!("hysteria2 masquerade response send: {e}"))
    })?;
    if req.method() != http::Method::HEAD && !body.is_empty() {
        stream.send_data(body).await.map_err(|e| {
            io::Error::other(format!("hysteria2 masquerade response body: {e}"))
        })?;
    }
    stream.finish().await.map_err(|e| {
        io::Error::other(format!("hysteria2 masquerade response finish: {e}"))
    })
}

fn default_masquerade_response(req: &http::Request<()>) -> MasqueradeResponse {
    const INDEX: &[u8] =
        b"<!doctype html><html><head><title>OK</title></head><body>OK</body></html>\n";
    const NOT_FOUND: &[u8] = b"<!doctype html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>\n";

    if req.method() == http::Method::GET
        && matches!(req.uri().path(), "/" | "/index.html")
    {
        html_masquerade_response(http::StatusCode::OK, Bytes::from_static(INDEX))
    } else {
        html_masquerade_response(
            http::StatusCode::NOT_FOUND,
            Bytes::from_static(NOT_FOUND),
        )
    }
}

fn not_found_masquerade_response() -> MasqueradeResponse {
    const NOT_FOUND: &[u8] =
        b"<!doctype html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>\n";
    html_masquerade_response(
        http::StatusCode::NOT_FOUND,
        Bytes::from_static(NOT_FOUND),
    )
}

fn html_masquerade_response(
    status: http::StatusCode,
    body: Bytes,
) -> MasqueradeResponse {
    MasqueradeResponse {
        status,
        headers: vec![
            (
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                http::header::CACHE_CONTROL,
                http::HeaderValue::from_static("no-store"),
            ),
        ],
        body,
    }
}

async fn file_masquerade_response(
    dir: &Path,
    req: &http::Request<()>,
) -> io::Result<MasqueradeResponse> {
    let Some(path) = masquerade_file_path(dir, req.uri().path()) else {
        return Ok(not_found_masquerade_response());
    };

    let metadata = match tokio::fs::metadata(&path).await {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return Ok(not_found_masquerade_response()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(not_found_masquerade_response());
        }
        Err(e) => return Err(e),
    };
    if metadata.len() > MAX_MASQUERADE_FILE_SIZE {
        return Ok(html_masquerade_response(
            http::StatusCode::PAYLOAD_TOO_LARGE,
            Bytes::from_static(b"payload too large\n"),
        ));
    }

    let body = tokio::fs::read(&path).await?;
    Ok(MasqueradeResponse {
        status: http::StatusCode::OK,
        headers: vec![(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static(content_type_for_path(&path)),
        )],
        body: Bytes::from(body),
    })
}

fn masquerade_file_path(dir: &Path, request_path: &str) -> Option<PathBuf> {
    let mut path = dir.to_path_buf();
    let request_path = request_path.trim_start_matches('/');
    if request_path.is_empty() || request_path.ends_with('/') {
        for segment in request_path
            .split('/')
            .filter(|segment| !segment.is_empty())
        {
            if !safe_path_segment(segment) {
                return None;
            }
            path.push(segment);
        }
        path.push("index.html");
        return Some(path);
    }

    for segment in request_path
        .split('/')
        .filter(|segment| !segment.is_empty())
    {
        if !safe_path_segment(segment) {
            return None;
        }
        path.push(segment);
    }
    Some(path)
}

fn safe_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !Path::new(segment).components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

fn content_type_for_path(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

async fn send_proxy_masquerade_h3_response(
    req: &http::Request<()>,
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    client: &reqwest::Client,
    base_url: &url::Url,
    rewrite_host: bool,
    x_forwarded: bool,
    source: SocketAddr,
) -> io::Result<()> {
    let body = collect_masquerade_request_body(stream).await?;
    let url = masquerade_proxy_url(base_url, req.uri());
    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid masquerade proxy method: {e}"),
            )
        })?;
    let mut builder = client.request(method, url);

    for (name, value) in req.headers() {
        if name != http::header::HOST && !hop_by_hop_header(name) {
            builder = builder.header(name.as_str(), value.as_bytes());
        }
    }
    if !rewrite_host && let Some(authority) = req.uri().authority() {
        builder = builder.header(http::header::HOST.as_str(), authority.as_str());
    }
    if x_forwarded {
        builder = builder
            .header("x-forwarded-for", source.ip().to_string())
            .header("x-forwarded-proto", "https")
            .header(
                "x-forwarded-host",
                req.uri().authority().map_or("", |a| a.as_str()),
            );
    }

    let mut response = builder.body(body).send().await.map_err(|e| {
        io::Error::other(format!("hysteria2 masquerade proxy request: {e}"))
    })?;
    let mut response_builder = http::Response::builder().status(
        http::StatusCode::from_u16(response.status().as_u16()).map_err(|e| {
            io::Error::other(format!("invalid proxy response status: {e}"))
        })?,
    );
    for (name, value) in response.headers() {
        if hop_by_hop_header(name) {
            continue;
        }
        response_builder = response_builder.header(name.as_str(), value.as_bytes());
    }
    let h3_response = response_builder.body(()).map_err(|e| {
        io::Error::other(format!("hysteria2 masquerade proxy response: {e}"))
    })?;
    stream.send_response(h3_response).await.map_err(|e| {
        io::Error::other(format!("hysteria2 masquerade proxy response send: {e}"))
    })?;

    if req.method() != http::Method::HEAD {
        while let Some(chunk) = response.chunk().await.map_err(|e| {
            io::Error::other(format!("hysteria2 masquerade proxy body: {e}"))
        })? {
            if !chunk.is_empty() {
                stream.send_data(chunk).await.map_err(|e| {
                    io::Error::other(format!(
                        "hysteria2 masquerade proxy body send: {e}"
                    ))
                })?;
            }
        }
    }

    stream.finish().await.map_err(|e| {
        io::Error::other(format!("hysteria2 masquerade proxy finish: {e}"))
    })
}

async fn collect_masquerade_request_body(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> io::Result<Bytes> {
    let mut body = BytesMut::new();
    while let Some(mut chunk) = stream.recv_data().await.map_err(|e| {
        io::Error::other(format!("hysteria2 masquerade request body: {e}"))
    })? {
        let len = chunk.remaining();
        if body.len().saturating_add(len) > MAX_MASQUERADE_PROXY_BODY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hysteria2 masquerade request body too large",
            ));
        }
        body.reserve(len);
        while chunk.has_remaining() {
            let bytes = chunk.chunk();
            let len = bytes.len();
            body.extend_from_slice(bytes);
            chunk.advance(len);
        }
    }
    Ok(body.freeze())
}

fn masquerade_proxy_url(base_url: &url::Url, uri: &http::Uri) -> url::Url {
    let mut url = base_url.clone();
    url.set_path(join_masquerade_proxy_path(base_url.path(), uri.path()).as_str());
    url.set_query(uri.query());
    url
}

fn join_masquerade_proxy_path(base_path: &str, request_path: &str) -> String {
    let base = base_path.trim_end_matches('/');
    let request = request_path.trim_start_matches('/');

    match (base.is_empty(), request.is_empty()) {
        (true, true) => "/".to_owned(),
        (true, false) => format!("/{request}"),
        (false, true) => format!("{base}/"),
        (false, false) => format!("{base}/{request}"),
    }
}

fn hop_by_hop_header(name: &http::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

async fn handle_tcp_streams(
    conn: Arc<quinn::Connection>,
    source: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
    inbound_user: Option<String>,
) -> io::Result<()> {
    loop {
        let (send, recv) = conn.accept_bi().await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("hysteria2 accept stream: {e}"),
            )
        })?;

        let dispatcher = dispatcher.clone();
        let inbound_user = inbound_user.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_stream(
                send,
                recv,
                source,
                dispatcher,
                fw_mark,
                inbound_user,
            )
            .await
            {
                debug!("hysteria2 inbound TCP stream from {source} ended: {e}");
            }
        });
    }
}

async fn handle_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    source: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
    inbound_user: Option<String>,
) -> io::Result<()> {
    let (req, pending_read) = {
        let mut reader = FramedRead::new(&mut recv, Hy2TcpReqCodec);
        let req = match timeout(HYSTERIA2_TCP_REQUEST_TIMEOUT, reader.next()).await {
            Ok(Some(Ok(req))) => req,
            Ok(Some(Err(e))) => {
                let _ = send_tcp_response(
                    &mut send,
                    Hy2TcpRespMsg {
                        status: 1,
                        msg: e.to_string(),
                    },
                )
                .await;
                return Err(e);
            }
            Ok(None) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "hysteria2 TCP request stream closed before request",
                ));
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "hysteria2 TCP request timeout",
                ));
            }
        };
        let pending_read = reader.into_parts().read_buf;
        (req, pending_read)
    };

    send_tcp_response(&mut send, Hy2TcpRespMsg::ok()).await?;

    let sess = Session {
        network: Network::Tcp,
        typ: Type::Hysteria2,
        source,
        destination: req.addr,
        so_mark: fw_mark,
        inbound_user,
        ..Default::default()
    };

    dispatcher
        .dispatch_stream(
            sess,
            Box::new(Hysteria2Stream {
                send,
                recv,
                pending_read,
            }),
        )
        .await;
    Ok(())
}

async fn send_tcp_response(
    send: &mut quinn::SendStream,
    response: Hy2TcpRespMsg,
) -> io::Result<()> {
    let mut writer = FramedWrite::new(send, Hy2TcpRespEncoder);
    writer.send(response).await?;
    writer.flush().await
}

async fn handle_udp_datagrams(
    conn: Arc<quinn::Connection>,
    source: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
    inbound_user: Option<String>,
    sessions: Arc<Mutex<HashMap<u32, UdpSessionEntry>>>,
) {
    loop {
        let pkt = match conn.read_datagram().await {
            Ok(pkt) => pkt,
            Err(e) => {
                debug!(
                    "hysteria2 inbound UDP datagram loop ended for {source}: {e}"
                );
                break;
            }
        };

        let mut buf: BytesMut = pkt.into();
        let pkt = match HysUdpPacket::decode(&mut buf) {
            Ok(pkt) => pkt,
            Err(e) => {
                debug!("hysteria2 inbound bad UDP packet from {source}: {e}");
                continue;
            }
        };

        if pkt.frag_count > MAX_UDP_FRAGMENTS_PER_PACKET {
            warn!(
                "hysteria2 inbound UDP packet from {source} dropped: fragment \
                 count {} exceeds limit {}",
                pkt.frag_count, MAX_UDP_FRAGMENTS_PER_PACKET
            );
            continue;
        }

        let session_id = pkt.session_id;
        let complete = {
            let mut guard = sessions.lock().await;
            if !guard.contains_key(&session_id) {
                if guard.len() >= MAX_UDP_SESSIONS_PER_CONN {
                    drop_oldest_udp_session(&mut guard);
                }
                if guard.len() >= MAX_UDP_SESSIONS_PER_CONN {
                    warn!(
                        "hysteria2 inbound UDP packet from {source} dropped: \
                         per-connection session limit reached"
                    );
                    continue;
                }

                let (tx, rx) = mpsc::channel(UDP_CHANNEL_SIZE);
                let datagram = Hysteria2InboundDatagram {
                    conn: Arc::clone(&conn),
                    session_id,
                    next_pkt_id: AtomicU32::new(0),
                    recv_rx: rx,
                };
                guard.insert(
                    session_id,
                    UdpSessionEntry {
                        incoming: tx,
                        defragger: Defragger::new(
                            MAX_UDP_INFLIGHT_PACKETS_PER_SESSION,
                            MAX_UDP_FRAGMENTS_PER_PACKET,
                            UDP_FRAGMENT_TTL,
                        ),
                        last_seen: Instant::now(),
                    },
                );

                let sess = Session {
                    network: Network::Udp,
                    typ: Type::Hysteria2,
                    source,
                    destination: pkt.addr.clone(),
                    so_mark: fw_mark,
                    inbound_user: inbound_user.clone(),
                    ..Default::default()
                };
                let dispatcher = dispatcher.clone();
                tokio::spawn(async move {
                    let _ =
                        dispatcher.dispatch_datagram(sess, Box::new(datagram)).await;
                });
            }

            let Some(entry) = guard.get_mut(&session_id) else {
                continue;
            };
            entry.last_seen = Instant::now();
            entry.defragger.feed(pkt)
        };

        let Some(pkt) = complete else {
            continue;
        };

        let packet = UdpPacket {
            data: pkt.data,
            src_addr: SocksAddr::Ip(source),
            dst_addr: pkt.addr,
            inbound_user: inbound_user.clone(),
        };

        let tx = {
            let guard = sessions.lock().await;
            guard.get(&session_id).map(|entry| entry.incoming.clone())
        };

        if let Some(tx) = tx {
            match tx.try_send(packet) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    debug!(
                        "hysteria2 inbound UDP packet from {source} dropped: \
                         session {session_id} channel is full"
                    );
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    sessions.lock().await.remove(&session_id);
                }
            }
        }
    }
}

async fn cleanup_udp_sessions_loop(
    sessions: Arc<Mutex<HashMap<u32, UdpSessionEntry>>>,
) {
    let mut interval = tokio::time::interval(UDP_SESSION_CLEANUP_INTERVAL);
    loop {
        interval.tick().await;
        prune_idle_udp_sessions(&sessions).await;
    }
}

async fn prune_idle_udp_sessions(
    sessions: &Arc<Mutex<HashMap<u32, UdpSessionEntry>>>,
) {
    let mut guard = sessions.lock().await;
    let before = guard.len();
    guard.retain(|_, entry| entry.last_seen.elapsed() < UDP_SESSION_IDLE_TIMEOUT);
    let removed = before.saturating_sub(guard.len());
    if removed > 0 {
        debug!("hysteria2 inbound pruned {removed} idle UDP sessions");
    }
}

fn drop_oldest_udp_session(sessions: &mut HashMap<u32, UdpSessionEntry>) {
    let Some(oldest) = sessions
        .iter()
        .min_by_key(|(_, entry)| entry.last_seen)
        .map(|(session_id, _)| *session_id)
    else {
        return;
    };
    sessions.remove(&oldest);
}

struct UdpSessionEntry {
    incoming: mpsc::Sender<UdpPacket>,
    defragger: Defragger,
    last_seen: Instant,
}

#[derive(Debug)]
struct Hysteria2InboundDatagram {
    conn: Arc<quinn::Connection>,
    session_id: u32,
    next_pkt_id: AtomicU32,
    recv_rx: mpsc::Receiver<UdpPacket>,
}

impl Sink<UdpPacket> for Hysteria2InboundDatagram {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pkt_id = self.next_pkt_id.fetch_add(1, Ordering::Relaxed) as u16;
        send_hys_datagram(
            &self.conn,
            self.session_id,
            pkt_id,
            item.src_addr,
            Bytes::from(item.data),
        )
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for Hysteria2InboundDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.recv_rx.poll_recv(cx)
    }
}

fn send_hys_datagram(
    conn: &quinn::Connection,
    session_id: u32,
    pkt_id: u16,
    addr: SocksAddr,
    data: Bytes,
) -> io::Result<()> {
    let max_frag_size = conn.max_datagram_size().ok_or_else(|| {
        io::Error::other(
            "hysteria2 max datagram size unavailable; check QUIC datagram support",
        )
    })?;

    let fragments =
        Fragments::try_new(session_id, pkt_id, addr, max_frag_size, data)?;
    for fragment in fragments {
        conn.send_datagram(fragment).map_err(new_io_error)?;
    }
    Ok(())
}

struct Hysteria2Stream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    pending_read: BytesMut,
}

impl fmt::Debug for Hysteria2Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hysteria2Stream").finish()
    }
}

impl AsyncRead for Hysteria2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.pending_read.is_empty() {
            let len = this.pending_read.len().min(buf.remaining());
            buf.put_slice(&this.pending_read.split_to(len));
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut this.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hysteria2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, buf)
            .map_err(Into::into)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_allowed_rejects_public_peer_on_unspecified_fallback() {
        let source = SocketAddr::from(([203, 0, 113, 1], 12345));
        assert!(!source_allowed(false, source, IpAddr::from([0, 0, 0, 0])));
    }

    #[test]
    fn source_allowed_accepts_same_local_ip() {
        let source = SocketAddr::from(([127, 0, 0, 1], 12345));
        assert!(source_allowed(false, source, IpAddr::from([127, 0, 0, 1])));
    }

    #[test]
    fn build_user_map_uses_fallback_only_without_users() {
        let users = build_user_map(&[], "secret");
        assert_eq!(users.get("secret"), Some(&None));
    }

    #[test]
    fn build_user_map_prefers_named_users_when_present() {
        let users = vec![InboundUser {
            name: "alice".to_owned(),
            password: "secret".to_owned(),
        }];
        let map = build_user_map(&users, "fallback");
        assert_eq!(map.get("secret"), Some(&Some("alice".to_owned())));
        assert!(!map.contains_key("fallback"));
    }

    #[test]
    fn official_auth_request_shape_is_accepted() {
        let req = http::Request::post("https://hysteria/auth")
            .body(())
            .unwrap();
        assert!(is_hysteria_auth_request(&req));
    }

    #[test]
    fn non_official_auth_request_shapes_are_rejected() {
        let wrong_method = http::Request::get("https://hysteria/auth")
            .body(())
            .unwrap();
        let wrong_path = http::Request::post("https://hysteria/not-auth")
            .body(())
            .unwrap();
        let wrong_authority = http::Request::post("https://example.com/auth")
            .body(())
            .unwrap();

        assert!(!is_hysteria_auth_request(&wrong_method));
        assert!(!is_hysteria_auth_request(&wrong_path));
        assert!(!is_hysteria_auth_request(&wrong_authority));
    }

    #[test]
    fn sni_guard_matches_exact_and_single_label_wildcard() {
        assert!(dns_name_matches("example.com", "example.com"));
        assert!(dns_name_matches("*.example.com", "hy2.example.com"));
        assert!(!dns_name_matches("*.example.com", "deep.hy2.example.com"));
        assert!(!dns_name_matches("example.com", "hy2.example.com"));
    }

    #[test]
    fn masquerade_file_path_rejects_parent_traversal() {
        let root = Path::new("/srv/www");

        assert_eq!(
            masquerade_file_path(root, "/").unwrap(),
            PathBuf::from("/srv/www/index.html")
        );
        assert_eq!(
            masquerade_file_path(root, "/assets/app.js").unwrap(),
            PathBuf::from("/srv/www/assets/app.js")
        );
        assert!(masquerade_file_path(root, "/../secret").is_none());
        assert!(masquerade_file_path(root, "/assets/../secret").is_none());
    }

    #[test]
    fn masquerade_proxy_url_preserves_base_path() {
        let base = url::Url::parse("https://example.com/base").unwrap();
        let uri: http::Uri = "/assets/app.js?ver=1".parse().unwrap();

        let url = masquerade_proxy_url(&base, &uri);

        assert_eq!(url.as_str(), "https://example.com/base/assets/app.js?ver=1");
    }

    #[test]
    fn masquerade_proxy_url_handles_root_base_path() {
        let base = url::Url::parse("https://example.com/").unwrap();
        let uri: http::Uri = "/assets/app.js".parse().unwrap();

        let url = masquerade_proxy_url(&base, &uri);

        assert_eq!(url.as_str(), "https://example.com/assets/app.js");
    }

    #[test]
    fn masquerade_proxy_url_maps_root_request_under_base_path() {
        let base = url::Url::parse("https://example.com/base/").unwrap();
        let uri: http::Uri = "/".parse().unwrap();

        let url = masquerade_proxy_url(&base, &uri);

        assert_eq!(url.as_str(), "https://example.com/base/");
    }
}
