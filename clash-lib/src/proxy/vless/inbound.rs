use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::BytesMut;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    time::timeout,
};
use tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::{
        handshake::server::{ErrorResponse, Request, Response},
        protocol::WebSocketConfig,
    },
};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::{
    Dispatcher,
    common::errors::{map_io_error, new_io_error},
    proxy::{
        AnyStream,
        inbound::InboundHandlerTrait,
        transport::WebsocketConn,
        utils::{ToCanonical, apply_tcp_options, try_create_dualstack_tcplistener},
    },
    session::{Network, Session, SocksAddr, Type},
};

const VLESS_VERSION: u8 = 0;
const VLESS_COMMAND_TCP: u8 = 1;
const VLESS_COMMAND_UDP: u8 = 2;
const VLESS_COMMAND_MUX: u8 = 3;
const VLESS_ADDR_IPV4: u8 = 1;
const VLESS_ADDR_DOMAIN: u8 = 2;
const VLESS_ADDR_IPV6: u8 = 3;
const MAX_VLESS_ADDON_LEN: usize = 255;
const MAX_WS_EARLY_DATA_LEN: usize = 2048;
const VLESS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const VLESS_WS_MAX_MESSAGE_SIZE: usize = 1024 * 1024;
const VLESS_WS_MAX_FRAME_SIZE: usize = 256 * 1024;

#[derive(Clone, Debug)]
pub struct VlessInboundUser {
    pub uuid: String,
    pub name: Option<String>,
}

pub struct WsInboundOptions {
    pub path: String,
    pub early_data_header_name: Option<String>,
}

pub struct InboundOptions {
    pub addr: SocketAddr,
    pub allow_lan: bool,
    pub dispatcher: Arc<Dispatcher>,
    pub fw_mark: Option<u32>,
    pub uuid: Option<String>,
    pub users: Vec<VlessInboundUser>,
    pub ws: WsInboundOptions,
}

pub struct VlessInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
    users: Arc<HashMap<Uuid, Option<String>>>,
    ws_path: String,
    early_data_header_name: Option<String>,
}

impl Drop for VlessInbound {
    fn drop(&mut self) {
        warn!("VLESS inbound listener on {} stopped", self.addr);
    }
}

impl VlessInbound {
    pub fn new(opts: InboundOptions) -> io::Result<Self> {
        if opts.ws.path.is_empty() || !opts.ws.path.starts_with('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vless ws inbound requires an absolute websocket path",
            ));
        }

        let users = build_user_map(opts.uuid, opts.users)?;
        if users.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vless inbound requires uuid or users",
            ));
        }

        Ok(Self {
            addr: opts.addr,
            allow_lan: opts.allow_lan,
            dispatcher: opts.dispatcher,
            fw_mark: opts.fw_mark,
            users: Arc::new(users),
            ws_path: opts.ws.path,
            early_data_header_name: opts.ws.early_data_header_name,
        })
    }
}

#[async_trait]
impl InboundHandlerTrait for VlessInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> io::Result<()> {
        let listener = try_create_dualstack_tcplistener(self.addr)?;

        loop {
            let (stream, source) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("vless inbound {}: accept error: {e}", self.addr);
                    continue;
                }
            };

            let source = source.to_canonical();
            let local_addr = match stream.local_addr() {
                Ok(addr) => addr.to_canonical(),
                Err(e) => {
                    warn!(
                        "vless inbound {}: failed to get accepted socket local \
                         address: {e}",
                        self.addr
                    );
                    continue;
                }
            };

            if !source_allowed(self.allow_lan, source, local_addr) {
                warn!(
                    "vless inbound {}: connection from {} rejected (not allowed, \
                     local address {})",
                    self.addr, source, local_addr
                );
                continue;
            }

            if let Err(e) = apply_tcp_options(&stream) {
                warn!(
                    "vless inbound {}: failed to apply TCP options: {e}",
                    self.addr
                );
            }

            let dispatcher = self.dispatcher.clone();
            let users = self.users.clone();
            let ws_path = self.ws_path.clone();
            let early_data_header_name = self.early_data_header_name.clone();
            let fw_mark = self.fw_mark;

            tokio::spawn(async move {
                if let Err(e) = handle_connection(
                    stream,
                    source,
                    dispatcher,
                    users,
                    ws_path,
                    early_data_header_name,
                    fw_mark,
                )
                .await
                {
                    warn!("vless inbound connection {source} ended: {e}");
                }
            });
        }
    }

    async fn listen_udp(&self) -> io::Result<()> {
        Ok(())
    }
}

fn build_user_map(
    uuid: Option<String>,
    users: Vec<VlessInboundUser>,
) -> io::Result<HashMap<Uuid, Option<String>>> {
    let mut map = HashMap::new();
    if let Some(uuid) = uuid {
        let parsed = parse_uuid(&uuid)?;
        if map.insert(parsed, None).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("duplicate vless uuid {uuid}"),
            ));
        }
    }

    for user in users {
        let parsed = parse_uuid(&user.uuid)?;
        if map.insert(parsed, user.name).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("duplicate vless uuid {}", user.uuid),
            ));
        }
    }
    Ok(map)
}

fn parse_uuid(uuid: &str) -> io::Result<Uuid> {
    Uuid::parse_str(uuid).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid vless uuid {uuid}: {e}"),
        )
    })
}

fn source_allowed(allow_lan: bool, source: SocketAddr, local: SocketAddr) -> bool {
    allow_lan || source.ip() == local.ip()
}

async fn handle_connection(
    stream: TcpStream,
    source: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    users: Arc<HashMap<Uuid, Option<String>>>,
    ws_path: String,
    early_data_header_name: Option<String>,
    fw_mark: Option<u32>,
) -> io::Result<()> {
    let early_data = Arc::new(Mutex::new(BytesMut::new()));
    let callback_early_data = early_data.clone();
    let callback = move |request: &Request, response: Response| {
        validate_ws_request(
            request,
            response,
            &ws_path,
            early_data_header_name.as_deref(),
            &callback_early_data,
        )
    };

    let stream: AnyStream = Box::new(stream);
    let ws_stream = timeout(
        VLESS_HANDSHAKE_TIMEOUT,
        accept_hdr_async_with_config(stream, callback, Some(vless_ws_config())),
    )
    .await
    .map_err(|_| timeout_error("vless websocket handshake timeout"))?
    .map_err(map_io_error)?;
    let stream: AnyStream = Box::new(WebsocketConn::from_websocket(ws_stream));
    let mut stream = EarlyDataStream::new(stream, take_early_data(early_data)?);

    let request = timeout(
        VLESS_HANDSHAKE_TIMEOUT,
        read_vless_request(&mut stream, &users),
    )
    .await
    .map_err(|_| timeout_error("vless request header timeout"))??;
    match request.command {
        VlessCommand::Tcp => {
            stream.write_all(&[VLESS_VERSION, 0]).await?;
            stream.flush().await?;

            let sess = Session {
                network: Network::Tcp,
                typ: Type::Vless,
                source,
                destination: request.destination,
                so_mark: fw_mark,
                inbound_user: request.inbound_user,
                ..Default::default()
            };
            dispatcher.dispatch_stream(sess, Box::new(stream)).await;
            Ok(())
        }
        VlessCommand::Udp => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "vless inbound UDP over websocket is not supported",
        )),
        VlessCommand::Mux => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "vless inbound mux command is not supported",
        )),
    }
}

fn vless_ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(VLESS_WS_MAX_MESSAGE_SIZE))
        .max_frame_size(Some(VLESS_WS_MAX_FRAME_SIZE))
}

fn timeout_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

fn take_early_data(early_data: Arc<Mutex<BytesMut>>) -> io::Result<BytesMut> {
    let mut guard = early_data
        .lock()
        .map_err(|_| new_io_error("vless ws early data lock poisoned"))?;
    Ok(std::mem::take(&mut *guard))
}

fn validate_ws_request(
    request: &Request,
    mut response: Response,
    path: &str,
    early_data_header_name: Option<&str>,
    early_data: &Arc<Mutex<BytesMut>>,
) -> Result<Response, ErrorResponse> {
    if request.uri().path() != path {
        return Err(error_response(
            http::StatusCode::NOT_FOUND,
            "websocket path not found",
        ));
    }

    if let Some(header_name) = early_data_header_name
        && let Some(value) = request.headers().get(header_name)
    {
        let header_value = value.to_str().map_err(|_| {
            error_response(
                http::StatusCode::BAD_REQUEST,
                "invalid early data header",
            )
        })?;
        let decoded = URL_SAFE_NO_PAD.decode(header_value).map_err(|_| {
            error_response(
                http::StatusCode::BAD_REQUEST,
                "invalid early data encoding",
            )
        })?;
        if decoded.len() > MAX_WS_EARLY_DATA_LEN {
            return Err(error_response(
                http::StatusCode::PAYLOAD_TOO_LARGE,
                "early data too large",
            ));
        }

        let mut early_data = early_data.lock().map_err(|_| {
            error_response(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "early data lock failed",
            )
        })?;
        early_data.extend_from_slice(&decoded);

        if let Ok(header_value) = http::HeaderValue::from_str(header_value)
            && let Ok(header_name) =
                http::HeaderName::from_bytes(header_name.as_bytes())
        {
            response.headers_mut().append(header_name, header_value);
        }
    }

    Ok(response)
}

fn error_response(status: http::StatusCode, body: &str) -> ErrorResponse {
    let mut response = ErrorResponse::new(Some(body.to_owned()));
    *response.status_mut() = status;
    response
}

struct EarlyDataStream {
    inner: AnyStream,
    early_data: BytesMut,
}

impl EarlyDataStream {
    fn new(inner: AnyStream, early_data: BytesMut) -> Self {
        Self { inner, early_data }
    }
}

#[cfg(test)]
mod tests {
    use super::source_allowed;
    use std::net::SocketAddr;

    #[test]
    fn source_allowed_rejects_non_local_source_on_unspecified_listener() {
        let source: SocketAddr = "192.0.2.10:50000".parse().unwrap();
        let accepted_local: SocketAddr = "203.0.113.5:60178".parse().unwrap();

        assert!(!source_allowed(false, source, accepted_local));
    }

    #[test]
    fn source_allowed_accepts_same_local_address() {
        let source: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let accepted_local: SocketAddr = "127.0.0.1:60178".parse().unwrap();

        assert!(source_allowed(false, source, accepted_local));
    }
}

impl AsyncRead for EarlyDataStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.early_data.is_empty() {
            let to_read = buf.remaining().min(self.early_data.len());
            let data = self.early_data.split_to(to_read);
            buf.put_slice(&data);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for EarlyDataStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct VlessRequest {
    command: VlessCommand,
    destination: SocksAddr,
    inbound_user: Option<String>,
}

enum VlessCommand {
    Tcp,
    Udp,
    Mux,
}

async fn read_vless_request(
    stream: &mut (impl AsyncRead + Unpin),
    users: &HashMap<Uuid, Option<String>>,
) -> io::Result<VlessRequest> {
    let version = stream.read_u8().await?;
    if version != VLESS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid vless version: {version}"),
        ));
    }

    let mut uuid_bytes = [0u8; 16];
    stream.read_exact(&mut uuid_bytes).await?;
    let uuid = Uuid::from_bytes(uuid_bytes);
    let inbound_user = users.get(&uuid).cloned().ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, "invalid vless uuid")
    })?;

    let addon_len = stream.read_u8().await? as usize;
    if addon_len > MAX_VLESS_ADDON_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid vless addon length",
        ));
    }
    if addon_len > 0 {
        let mut addon = vec![0u8; addon_len];
        stream.read_exact(&mut addon).await?;
        debug!("vless inbound ignored addon bytes: {}", addon.len());
    }

    let command = match stream.read_u8().await? {
        VLESS_COMMAND_TCP => VlessCommand::Tcp,
        VLESS_COMMAND_UDP => VlessCommand::Udp,
        VLESS_COMMAND_MUX => VlessCommand::Mux,
        command => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported vless command: {command}"),
            ));
        }
    };

    let destination = read_vless_addr(stream).await?;
    Ok(VlessRequest {
        command,
        destination,
        inbound_user,
    })
}

async fn read_vless_addr(
    stream: &mut (impl AsyncRead + Unpin),
) -> io::Result<SocksAddr> {
    let port = stream.read_u16().await?;
    let atyp = stream.read_u8().await?;
    match atyp {
        VLESS_ADDR_IPV4 => {
            let ip = Ipv4Addr::from(stream.read_u32().await?);
            Ok(SocksAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)))
        }
        VLESS_ADDR_IPV6 => {
            let ip = Ipv6Addr::from(stream.read_u128().await?);
            Ok(SocksAddr::Ip(SocketAddr::new(IpAddr::V6(ip), port)))
        }
        VLESS_ADDR_DOMAIN => {
            let domain_len = stream.read_u8().await? as usize;
            if domain_len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "empty vless destination domain",
                ));
            }

            let mut domain = vec![0u8; domain_len];
            stream.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid vless destination domain",
                )
            })?;
            Ok(SocksAddr::Domain(domain, port))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid vless address type: {atyp}"),
        )),
    }
}
