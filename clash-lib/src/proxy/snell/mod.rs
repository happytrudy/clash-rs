mod profile;
mod record;

use std::{
    collections::HashMap,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{Sink, SinkExt, Stream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_util::sync::PollSender;
use tracing::{debug, info};

use crate::{
    Dispatcher,
    config::listener::SnellInboundUser,
    proxy::{AnyInboundDatagram, datagram::UdpPacket, inbound::InboundHandlerTrait},
    session::{Network, Session, SocksAddr, Type},
};

use self::{
    profile::Profile,
    record::{Mode, RecordReader, RecordWriter},
};

const REQUEST_VERSION: u8 = 1;
const COMMAND_PING: u8 = 0;
const COMMAND_CONNECT: u8 = 1;
const COMMAND_CONNECT_V2: u8 = 5;
const COMMAND_UDP: u8 = 6;
const REPLY_TUNNEL: u8 = 0;
const REPLY_PONG: u8 = 1;
const REPLY_ERROR: u8 = 2;
const UDP_FORWARD: u8 = 1;
const ADDRESS_IPV4: u8 = 4;
const ADDRESS_IPV6: u8 = 6;
const DUPLEX_CAPACITY: usize = 256 * 1024;
const RELAY_BUFFER_SIZE: usize = 64 * 1024;

pub struct InboundOptions {
    pub addr: SocketAddr,
    pub version: u8,
    pub psk: String,
    pub users: Vec<SnellInboundUser>,
    pub mode: String,
    pub allow_lan: bool,
    pub dispatcher: Arc<Dispatcher>,
    pub fw_mark: Option<u32>,
}

pub struct SnellInbound {
    addr: SocketAddr,
    psk: Arc<Vec<u8>>,
    users: Arc<HashMap<Vec<u8>, String>>,
    mode: Mode,
    profile: Option<Profile>,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
}

impl SnellInbound {
    pub fn new(options: InboundOptions) -> io::Result<Self> {
        if options.version != 6 {
            return Err(invalid_input("snell inbound only supports version 6"));
        }
        if !(12..=255).contains(&options.psk.len()) {
            return Err(invalid_input(
                "snell v6 psk length must be between 12 and 255 bytes",
            ));
        }
        if !options.allow_lan && !options.addr.ip().is_loopback() {
            return Err(invalid_input(
                "snell inbound with allow-lan disabled must listen on loopback",
            ));
        }
        let mode = Mode::parse(&options.mode)?;
        let psk = options.psk.into_bytes();
        let profile = (mode == Mode::Default).then(|| Profile::new(&psk));
        let mut users = HashMap::with_capacity(options.users.len());
        for (index, user) in options.users.into_iter().enumerate() {
            if user.userkey.is_empty() || user.userkey.len() > 255 {
                return Err(invalid_input(
                    "snell userkey length must be between 1 and 255 bytes",
                ));
            }
            let name = if user.name.is_empty() {
                index.to_string()
            } else {
                user.name
            };
            if users.insert(user.userkey.into_bytes(), name).is_some() {
                return Err(invalid_input("duplicate snell userkey"));
            }
        }
        Ok(Self {
            addr: options.addr,
            psk: Arc::new(psk),
            users: Arc::new(users),
            mode,
            profile,
            dispatcher: options.dispatcher,
            fw_mark: options.fw_mark,
        })
    }

    async fn serve(self: Arc<Self>, stream: TcpStream, source: SocketAddr) {
        if let Err(error) = self.serve_connection(stream, source).await {
            debug!("snell connection from {source} closed: {error}");
        }
    }

    async fn serve_connection(
        self: &Arc<Self>,
        stream: TcpStream,
        source: SocketAddr,
    ) -> io::Result<()> {
        let (read_half, write_half) = stream.into_split();
        let mut reader = RecordReader::new(
            read_half,
            self.mode,
            self.psk.as_ref().clone(),
            self.profile.clone(),
        );
        let mut writer = RecordWriter::new(
            write_half,
            self.mode,
            self.psk.as_ref().clone(),
            self.profile.clone(),
        );
        let first = reader
            .read_record()
            .await?
            .ok_or_else(|| invalid_data("snell request cannot be an EOF record"))?;
        let (mut request, mut initial_payload) = parse_request(first)?;

        loop {
            let inbound_user =
                authenticate_user(&self.users, request.command, &request.client_id)?;
            match request.command {
                COMMAND_PING => {
                    writer.write_payload(&[REPLY_PONG]).await?;
                    return Ok(());
                }
                COMMAND_CONNECT | COMMAND_CONNECT_V2 => {
                    let reusable = request.command == COMMAND_CONNECT_V2;
                    let destination =
                        request.destination.take().ok_or_else(|| {
                            invalid_data(
                                "snell connect request is missing destination",
                            )
                        })?;
                    let outcome = self
                        .relay_tcp(
                            &mut reader,
                            &mut writer,
                            source,
                            destination,
                            inbound_user,
                            initial_payload,
                            reusable,
                        )
                        .await?;
                    if !reusable || outcome == RelayOutcome::Abort {
                        return Ok(());
                    }
                }
                COMMAND_UDP => {
                    if !initial_payload.is_empty() {
                        return Err(invalid_data(
                            "snell UDP request contains an inline datagram",
                        ));
                    }
                    return self
                        .relay_udp(reader, writer, source, inbound_user)
                        .await;
                }
                command => {
                    return Err(invalid_data_owned(format!(
                        "snell unsupported command: {command}"
                    )));
                }
            }

            let next = match reader.read_record().await {
                Ok(Some(record)) => record,
                Ok(None) => return Ok(()),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            (request, initial_payload) = parse_request(next)?;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn relay_tcp<R, W>(
        self: &Arc<Self>,
        reader: &mut RecordReader<R>,
        writer: &mut RecordWriter<W>,
        source: SocketAddr,
        destination: SocksAddr,
        inbound_user: Option<String>,
        initial_payload: Vec<u8>,
        reusable: bool,
    ) -> io::Result<RelayOutcome>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let (clash_stream, relay_stream) = tokio::io::duplex(DUPLEX_CAPACITY);
        let (mut relay_read, mut relay_write) = tokio::io::split(relay_stream);
        let dispatcher = self.dispatcher.clone();
        let session = Session {
            network: Network::Tcp,
            typ: Type::Snell,
            source,
            destination,
            so_mark: self.fw_mark,
            inbound_user,
            ..Default::default()
        };
        let dispatch = tokio::spawn(async move {
            dispatcher
                .dispatch_stream(session, Box::new(clash_stream))
                .await;
        });

        if !initial_payload.is_empty() {
            relay_write.write_all(&initial_payload).await?;
        }
        let mut from_client_open = true;
        let mut from_dispatch_open = true;
        let mut reply_written = false;
        let mut relay_buffer = vec![0u8; RELAY_BUFFER_SIZE];

        while from_client_open || from_dispatch_open {
            tokio::select! {
                record = reader.read_record(), if from_client_open => {
                    match record? {
                        Some(payload) => relay_write.write_all(&payload).await?,
                        None => {
                            relay_write.shutdown().await?;
                            from_client_open = false;
                        }
                    }
                }
                result = relay_read.read(&mut relay_buffer), if from_dispatch_open => {
                    let count = result?;
                    if count == 0 {
                        from_dispatch_open = false;
                        if !reply_written {
                            if reusable {
                                writer.write_payload(&remote_eof_reply()).await?;
                                dispatch.abort();
                                return Ok(RelayOutcome::Abort);
                            }
                            break;
                        }
                        if reusable {
                            writer.write_eof().await?;
                        } else {
                            break;
                        }
                    } else if reply_written {
                        writer.write_payload(&relay_buffer[..count]).await?;
                    } else {
                        let mut reply = Vec::with_capacity(count + 1);
                        reply.push(REPLY_TUNNEL);
                        reply.extend_from_slice(&relay_buffer[..count]);
                        writer.write_payload(&reply).await?;
                        reply_written = true;
                    }
                }
            }
        }

        drop(relay_read);
        drop(relay_write);
        let _ = dispatch.await;
        Ok(RelayOutcome::Complete)
    }

    async fn relay_udp<R, W>(
        self: &Arc<Self>,
        mut reader: RecordReader<R>,
        mut writer: RecordWriter<W>,
        source: SocketAddr,
        inbound_user: Option<String>,
    ) -> io::Result<()>
    where
        R: tokio::io::AsyncRead + Send + Unpin + 'static,
        W: tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        writer.write_payload(&[REPLY_TUNNEL]).await?;
        let (incoming_tx, incoming_rx) = mpsc::channel(64);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<UdpPacket>(64);
        let (reader_done_tx, reader_done_rx) = tokio::sync::oneshot::channel();
        let reader_user = inbound_user.clone();

        tokio::spawn(async move {
            while let Ok(Some(record)) = reader.read_record().await {
                match parse_udp_request(record, source, reader_user.clone()) {
                    Ok(packet) => {
                        if incoming_tx.send(packet).await.is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        debug!("invalid snell UDP request: {error}");
                        break;
                    }
                }
            }
            let _ = reader_done_tx.send(());
        });
        tokio::spawn(async move {
            while let Some(packet) = outgoing_rx.recv().await {
                match encode_udp_response(packet) {
                    Ok(payload) => {
                        if writer.write_packet(&payload).await.is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        debug!("invalid snell UDP response: {error}");
                        break;
                    }
                }
            }
        });

        let datagram = SnellInboundDatagram {
            sender: PollSender::new(outgoing_tx),
            receiver: incoming_rx,
            source,
        };
        let session = Session {
            network: Network::Udp,
            typ: Type::Snell,
            source,
            so_mark: self.fw_mark,
            inbound_user,
            ..Default::default()
        };
        let close_handle = self
            .dispatcher
            .dispatch_datagram(session, Box::new(datagram) as AnyInboundDatagram)
            .await;
        let _ = reader_done_rx.await;
        let _ = close_handle.send(0);
        Ok(())
    }
}

#[async_trait::async_trait]
impl InboundHandlerTrait for SnellInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!("Snell v6 listening at: {}", self.addr);
        let this = Arc::new(Self {
            addr: self.addr,
            psk: self.psk.clone(),
            users: self.users.clone(),
            mode: self.mode,
            profile: self.profile.clone(),
            dispatcher: self.dispatcher.clone(),
            fw_mark: self.fw_mark,
        });
        loop {
            let (stream, source) = listener.accept().await?;
            let service = this.clone();
            tokio::spawn(async move { service.serve(stream, source).await });
        }
    }

    async fn listen_udp(&self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RelayOutcome {
    Complete,
    Abort,
}

struct Request {
    command: u8,
    client_id: Vec<u8>,
    destination: Option<SocksAddr>,
}

fn parse_request(record: Vec<u8>) -> io::Result<(Request, Vec<u8>)> {
    if record.len() < 3 || record[0] != REQUEST_VERSION {
        return Err(invalid_data("snell invalid request version"));
    }
    let command = record[1];
    if command == COMMAND_PING {
        return Ok((
            Request {
                command,
                client_id: Vec::new(),
                destination: None,
            },
            record[3..].to_vec(),
        ));
    }
    let client_len = record[2] as usize;
    if record.len() < 3 + client_len {
        return Err(invalid_data("snell truncated client id"));
    }
    let client_id = record[3..3 + client_len].to_vec();
    let mut offset = 3 + client_len;
    let destination = if matches!(command, COMMAND_CONNECT | COMMAND_CONNECT_V2) {
        Some(read_connect_address(&record, &mut offset)?)
    } else if command == COMMAND_UDP {
        None
    } else {
        return Err(invalid_data_owned(format!(
            "snell unsupported command: {command}"
        )));
    };
    Ok((
        Request {
            command,
            client_id,
            destination,
        },
        record[offset..].to_vec(),
    ))
}

fn authenticate_user(
    users: &HashMap<Vec<u8>, String>,
    command: u8,
    client_id: &[u8],
) -> io::Result<Option<String>> {
    if command == COMMAND_PING || users.is_empty() {
        return Ok(None);
    }
    users
        .get(client_id)
        .cloned()
        .map(Some)
        .ok_or_else(|| invalid_data("snell authentication failed"))
}

fn read_connect_address(data: &[u8], offset: &mut usize) -> io::Result<SocksAddr> {
    let host_len = take_byte(data, offset)? as usize;
    let host = take(data, offset, host_len)?;
    let host = std::str::from_utf8(host)
        .map_err(|_| invalid_data("snell destination is not valid UTF-8"))?;
    let port = u16::from_be_bytes(take(data, offset, 2)?.try_into().unwrap());
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(SocksAddr::Ip(SocketAddr::new(ip, port)))
    } else {
        Ok(SocksAddr::Domain(host.to_owned(), port))
    }
}

fn parse_udp_request(
    data: Vec<u8>,
    source: SocketAddr,
    inbound_user: Option<String>,
) -> io::Result<UdpPacket> {
    let mut offset = 0;
    if take_byte(&data, &mut offset)? != UDP_FORWARD {
        return Err(invalid_data("snell unsupported UDP command"));
    }
    let destination = read_udp_request_address(&data, &mut offset)?;
    Ok(UdpPacket {
        data: data[offset..].to_vec(),
        src_addr: SocksAddr::Ip(source),
        dst_addr: destination,
        inbound_user,
    })
}

fn read_udp_request_address(
    data: &[u8],
    offset: &mut usize,
) -> io::Result<SocksAddr> {
    let first = take_byte(data, offset)?;
    if first != 0 {
        let host = take(data, offset, first as usize)?;
        let host = std::str::from_utf8(host)
            .map_err(|_| invalid_data("snell UDP host is not valid UTF-8"))?;
        let port = u16::from_be_bytes(take(data, offset, 2)?.try_into().unwrap());
        return Ok(SocksAddr::Domain(host.to_owned(), port));
    }
    read_ip_address(data, offset)
}

fn read_ip_address(data: &[u8], offset: &mut usize) -> io::Result<SocksAddr> {
    let family = take_byte(data, offset)?;
    let ip = match family {
        ADDRESS_IPV4 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(take(data, offset, 4)?).unwrap(),
        )),
        ADDRESS_IPV6 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(take(data, offset, 16)?).unwrap(),
        )),
        _ => return Err(invalid_data("snell invalid UDP address family")),
    };
    let port = u16::from_be_bytes(take(data, offset, 2)?.try_into().unwrap());
    Ok(SocksAddr::Ip(SocketAddr::new(ip, port)))
}

fn encode_udp_response(packet: UdpPacket) -> io::Result<Vec<u8>> {
    let SocksAddr::Ip(source) = packet.src_addr else {
        return Err(invalid_data("snell UDP response source must be an IP"));
    };
    let mut output = Vec::with_capacity(packet.data.len() + 19);
    match source.ip() {
        IpAddr::V4(ip) => {
            output.push(ADDRESS_IPV4);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(ADDRESS_IPV6);
            output.extend_from_slice(&ip.octets());
        }
    }
    output.extend_from_slice(&source.port().to_be_bytes());
    output.extend_from_slice(&packet.data);
    Ok(output)
}

fn remote_eof_reply() -> Vec<u8> {
    let message = b"Remote EOF";
    let mut reply = Vec::with_capacity(message.len() + 3);
    reply.extend_from_slice(&[REPLY_ERROR, 0x65, message.len() as u8]);
    reply.extend_from_slice(message);
    reply
}

fn take_byte(data: &[u8], offset: &mut usize) -> io::Result<u8> {
    Ok(take(data, offset, 1)?[0])
}

fn take<'a>(
    data: &'a [u8],
    offset: &mut usize,
    count: usize,
) -> io::Result<&'a [u8]> {
    let end = offset
        .checked_add(count)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| invalid_data("snell truncated request"))?;
    let output = &data[*offset..end];
    *offset = end;
    Ok(output)
}

struct SnellInboundDatagram {
    sender: PollSender<UdpPacket>,
    receiver: mpsc::Receiver<UdpPacket>,
    source: SocketAddr,
}

impl fmt::Debug for SnellInboundDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnellInboundDatagram")
            .field("source", &self.source)
            .finish()
    }
}

impl Stream for SnellInboundDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(context)
    }
}

impl Sink<UdpPacket> for SnellInboundDatagram {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut()
            .sender
            .poll_ready_unpin(context)
            .map_err(io::Error::other)
    }

    fn start_send(self: Pin<&mut Self>, packet: UdpPacket) -> io::Result<()> {
        self.get_mut()
            .sender
            .start_send_unpin(packet)
            .map_err(io::Error::other)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut()
            .sender
            .poll_flush_unpin(context)
            .map_err(io::Error::other)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut()
            .sender
            .poll_close_unpin(context)
            .map_err(io::Error::other)
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_data_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        COMMAND_CONNECT_V2, COMMAND_PING, authenticate_user, parse_request,
    };
    use crate::session::SocksAddr;

    #[test]
    fn parses_v6_multi_user_connect_request() {
        let mut record = vec![1, COMMAND_CONNECT_V2, 4];
        record.extend_from_slice(b"user");
        record.push(11);
        record.extend_from_slice(b"example.com");
        record.extend_from_slice(&443u16.to_be_bytes());
        record.extend_from_slice(b"early data");

        let (request, payload) = parse_request(record).unwrap();
        assert_eq!(request.client_id, b"user");
        assert_eq!(
            request.destination,
            Some(SocksAddr::Domain("example.com".to_owned(), 443))
        );
        assert_eq!(payload, b"early data");
    }

    #[test]
    fn multi_user_ping_does_not_require_userkey() {
        let users = HashMap::from([(b"user-key".to_vec(), "user".to_owned())]);
        assert_eq!(authenticate_user(&users, COMMAND_PING, &[]).unwrap(), None);
        assert!(authenticate_user(&users, COMMAND_CONNECT_V2, &[]).is_err());
    }
}
