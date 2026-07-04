use crate::session::SocksAddr;
use anyhow::anyhow;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn_proto::{VarInt, coding::Codec};
use rand::distr::Distribution;
use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    str::FromStr,
    time::{Duration, Instant},
};
use tokio_util::codec::{Decoder, Encoder};

pub struct Hy2TcpCodec;

/// ### format
///
/// ```text
/// [uint8] Status (0x00 = OK, 0x01 = Error)
/// [varint] Message length
/// [bytes] Message string
/// [varint] Padding length
/// [bytes] Random padding
/// ```
#[derive(Debug)]
pub struct Hy2TcpResp {
    pub status: u8,
    pub msg: String,
}

pub struct Hy2TcpReqCodec;

const MAX_HY2_TCP_ADDR_LEN: usize = 1024;
const MAX_HY2_TCP_PADDING_LEN: usize = 16 * 1024;

#[derive(Debug)]
pub struct Hy2TcpReq {
    pub addr: SocksAddr,
}

impl Decoder for Hy2TcpReqCodec {
    type Error = std::io::Error;
    type Item = Hy2TcpReq;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        let mut offset = 0;
        let Some((req_id, consumed)) = peek_varint(&src[offset..])? else {
            return Ok(None);
        };
        offset += consumed;

        const EXPECTED_REQ_ID: u64 = 0x401;
        if req_id.into_inner() != EXPECTED_REQ_ID {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "unexpected hysteria2 TCP request ID: {:#x}",
                    req_id.into_inner()
                ),
            ));
        }

        let Some((addr_len, consumed)) = peek_varint(&src[offset..])? else {
            return Ok(None);
        };
        offset += consumed;

        let addr_len = usize::try_from(addr_len.into_inner()).map_err(|_| {
            std::io::Error::new(ErrorKind::InvalidData, "address too long")
        })?;
        if addr_len > MAX_HY2_TCP_ADDR_LEN {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "hysteria2 TCP request address length exceeds limit: \
                     {addr_len} > {MAX_HY2_TCP_ADDR_LEN}"
                ),
            ));
        }
        if src.len().saturating_sub(offset) < addr_len {
            return Ok(None);
        }
        let addr_start = offset;
        offset += addr_len;

        let Some((padding_len, consumed)) = peek_varint(&src[offset..])? else {
            return Ok(None);
        };
        offset += consumed;

        let padding_len =
            usize::try_from(padding_len.into_inner()).map_err(|_| {
                std::io::Error::new(ErrorKind::InvalidData, "padding too long")
            })?;
        if padding_len > MAX_HY2_TCP_PADDING_LEN {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "hysteria2 TCP request padding length exceeds limit: \
                     {padding_len} > {MAX_HY2_TCP_PADDING_LEN}"
                ),
            ));
        }
        if src.len().saturating_sub(offset) < padding_len {
            return Ok(None);
        }
        offset += padding_len;

        let addr = to_socksaddr(&src[addr_start..addr_start + addr_len])?;
        src.advance(offset);
        Ok(Some(Hy2TcpReq { addr }))
    }
}

pub struct Hy2TcpRespEncoder;

pub struct Hy2TcpRespMsg {
    pub status: u8,
    pub msg: String,
}

impl Hy2TcpRespMsg {
    pub fn ok() -> Self {
        Self {
            status: 0,
            msg: String::new(),
        }
    }
}

impl Encoder<Hy2TcpRespMsg> for Hy2TcpRespEncoder {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        item: Hy2TcpRespMsg,
        buf: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let padding = padding(64..=512);
        let msg = item.msg.into_bytes();
        let msg_var = VarInt::from_u32(msg.len() as u32);
        let padding_var = VarInt::from_u32(padding.len() as u32);

        buf.reserve(
            1 + var_size(msg_var)
                + msg.len()
                + var_size(padding_var)
                + padding.len(),
        );
        buf.put_u8(item.status);
        msg_var.encode(buf);
        buf.put_slice(&msg);
        padding_var.encode(buf);
        buf.put_slice(&padding);
        Ok(())
    }
}

impl Decoder for Hy2TcpCodec {
    type Error = std::io::Error;
    type Item = Hy2TcpResp;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        if !src.has_remaining() {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        let status = src.get_u8();
        let msg_len = VarInt::decode(src)
            .map_err(|_| ErrorKind::InvalidData)?
            .into_inner() as usize;

        if src.remaining() < msg_len {
            return Err(ErrorKind::UnexpectedEof.into());
        }

        let msg: Vec<u8> = src.split_to(msg_len).into();
        let msg: String = String::from_utf8(msg)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;

        let padding_len = VarInt::decode(src)
            .map_err(|_| ErrorKind::UnexpectedEof)?
            .into_inner() as usize;

        if src.remaining() < padding_len {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        src.advance(padding_len);

        Ok(Hy2TcpResp { status, msg }.into())
    }
}

fn peek_varint(src: &[u8]) -> std::io::Result<Option<(VarInt, usize)>> {
    if src.is_empty() {
        return Ok(None);
    }

    let len = match src[0] >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if src.len() < len {
        return Ok(None);
    }

    let mut bytes = [0u8; 8];
    bytes[8 - len..].copy_from_slice(&src[..len]);
    bytes[8 - len] &= 0x3f;
    let value = u64::from_be_bytes(bytes);
    VarInt::from_u64(value)
        .map(|v| Some((v, len)))
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "invalid varint"))
}

#[inline]
pub fn padding(range: std::ops::RangeInclusive<u32>) -> Vec<u8> {
    let len = rand::random_range(range) as usize;
    rand::distr::Alphanumeric
        .sample_iter(rand::rng())
        .take(len)
        .collect()
}

impl Encoder<&'_ SocksAddr> for Hy2TcpCodec {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        item: &'_ SocksAddr,
        buf: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        const REQ_ID: VarInt = VarInt::from_u32(0x401);

        let padding = padding(64..=512);
        let padding_var = VarInt::from_u32(padding.len() as u32);

        let addr = item.to_string().into_bytes();
        let addr_var = VarInt::from_u32(addr.len() as u32);

        buf.reserve(
            var_size(REQ_ID)
                + var_size(padding_var)
                + var_size(addr_var)
                + addr.len()
                + padding.len(),
        );

        REQ_ID.encode(buf);

        addr_var.encode(buf);
        buf.put_slice(&addr);

        padding_var.encode(buf);
        buf.put_slice(&padding);

        Ok(())
    }
}

/// Compute the number of bytes needed to encode this value
pub fn var_size(var: VarInt) -> usize {
    let x = var.into_inner();
    if x < 2u64.pow(6) {
        1
    } else if x < 2u64.pow(14) {
        2
    } else if x < 2u64.pow(30) {
        4
    } else if x < 2u64.pow(62) {
        8
    } else {
        unreachable!("malformed VarInt");
    }
}

/// ```text
/// [uint32] Session ID
/// [uint16] Packet ID
/// [uint8] Fragment ID
/// [uint8] Fragment count
/// [varint] Address length
/// [bytes] Address string (host:port)
/// [bytes] Payload
/// ```
#[derive(Clone)]
pub struct HysUdpPacket {
    pub session_id: u32,
    pub pkt_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: SocksAddr,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for HysUdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HysUdpPacket")
            .field("session_id", &format_args!("{:#010x}", self.session_id))
            .field("pkt_id", &self.pkt_id)
            .field("frag_id", &self.frag_id)
            .field("frag_count", &self.frag_count)
            .field("addr", &self.addr)
            .field("data_size", &self.data.len())
            .finish()
    }
}

impl HysUdpPacket {
    /// `decode` method, `encode` has been moved to Fragments
    pub fn decode(buf: &mut BytesMut) -> anyhow::Result<Self> {
        if buf.len() < 4 + 2 + 1 + 1 {
            return Err(anyhow!("packet too short"));
        }
        let session_id = buf.get_u32();
        let pkt_id = buf.get_u16();
        let frag_id = buf.get_u8();
        let frag_count = buf.get_u8();
        let addr_len = VarInt::decode(buf)
            .map_err(|_| anyhow!("invalid address length varint"))?
            .into_inner() as usize;
        if buf.remaining() < addr_len {
            return Err(anyhow!(
                "address length {} exceeds remaining packet size {}",
                addr_len,
                buf.remaining()
            ));
        }
        let addr: Vec<u8> = buf.split_to(addr_len).into();
        let data = buf.split().to_vec();
        Ok(Self {
            session_id,
            pkt_id,
            frag_id,
            frag_count,
            addr: to_socksaddr(&addr)?,
            data,
        })
    }
}

pub(super) fn to_socksaddr(bytes: &[u8]) -> std::io::Result<SocksAddr> {
    let addr_str = std::str::from_utf8(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid UTF-8 in address",
        )
    })?;

    // Split the string at ':' to get host and port
    let (host, port_str) = addr_str.rsplit_once(':').ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Address must be in host:port format",
        )
    })?;

    // Parse the port
    let port = port_str.parse::<u16>().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid port number")
    })?;

    // Try parsing as SocketAddr first
    if let Ok(sock_addr) = std::net::SocketAddr::from_str(addr_str) {
        Ok(SocksAddr::Ip(sock_addr))
    } else {
        // If not a valid IP address, treat as domain
        Ok(SocksAddr::Domain(host.to_string(), port))
    }
}

/// Iterator over fragments of a packet
#[derive(Debug)]
pub struct Fragments<'a, P> {
    session_id: u32,
    pkt_id: u16,
    addr: (Vec<u8>, VarInt),
    frag_total: u8,
    next_frag_id: u8,
    next_frag_start: usize,
    payload: P,
    // used for fragment, not a actual field of packet
    max_pkt_size: usize,
    fixed_size: usize,
    _marker: std::marker::PhantomData<&'a P>,
}

impl<'a, P> Fragments<'a, P>
where
    P: AsRef<[u8]> + 'a,
{
    pub fn try_new(
        session_id: u32,
        pkt_id: u16,
        addr: SocksAddr,
        max_pkt_size: usize,
        payload: P,
    ) -> io::Result<Self> {
        let addr = addr.to_string().into_bytes();
        let addr_var = VarInt::from_u32(addr.len() as u32);

        let fixed_size = 4 + 2 + 1 + 1 + addr.len() + var_size(addr_var);
        if max_pkt_size <= fixed_size {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "hysteria2 UDP address is too large for QUIC datagram",
            ));
        }

        let max_data_size = max_pkt_size - fixed_size;
        let frag_total = if payload.as_ref().is_empty() {
            1
        } else {
            payload.as_ref().len().div_ceil(max_data_size)
        };
        let frag_total = u8::try_from(frag_total).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "hysteria2 UDP payload is too large to fragment",
            )
        })?;

        Ok(Self {
            session_id,
            pkt_id,
            addr: (addr, addr_var),
            frag_total,
            next_frag_id: 0,
            next_frag_start: 0,
            payload,
            max_pkt_size,
            fixed_size,
            _marker: std::marker::PhantomData,
        })
    }
}

impl<'a, P> Iterator for Fragments<'a, P>
where
    P: AsRef<[u8]> + 'a,
{
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_frag_id < self.frag_total {
            let max_payload_size = self.max_pkt_size - self.fixed_size;
            let next_frag_end = (self.next_frag_start + max_payload_size)
                .min(self.payload.as_ref().len());
            let payload =
                &self.payload.as_ref()[self.next_frag_start..next_frag_end];

            let mut buf = BytesMut::new();
            buf.reserve(self.fixed_size + payload.len());

            buf.put_u32(self.session_id);
            buf.put_u16(self.pkt_id);
            buf.put_u8(self.next_frag_id);
            buf.put_u8(self.frag_total);
            self.addr.1.encode(&mut buf);
            buf.put_slice(self.addr.0.as_slice());
            buf.put_slice(payload);
            let frag = buf.freeze();

            self.next_frag_id += 1;
            self.next_frag_start = next_frag_end;

            Some(frag)
        } else {
            None
        }
    }
}

impl<P> ExactSizeIterator for Fragments<'_, P>
where
    P: AsRef<[u8]>,
{
    fn len(&self) -> usize {
        self.frag_total.saturating_sub(self.next_frag_id) as usize
    }
}

pub struct Defragger {
    packets: HashMap<u16, FragmentedPacket>,
    max_packets: usize,
    max_fragments_per_packet: u8,
    packet_ttl: Duration,
}

struct FragmentedPacket {
    addr: SocksAddr,
    created_at: Instant,
    frags: Vec<Option<HysUdpPacket>>,
    cnt: u16,
}

impl Default for Defragger {
    fn default() -> Self {
        Self::new(64, 64, Duration::from_secs(30))
    }
}

impl Defragger {
    pub fn new(
        max_packets: usize,
        max_fragments_per_packet: u8,
        packet_ttl: Duration,
    ) -> Self {
        Self {
            packets: HashMap::new(),
            max_packets,
            max_fragments_per_packet,
            packet_ttl,
        }
    }

    pub fn feed(&mut self, pkt: HysUdpPacket) -> Option<HysUdpPacket> {
        if pkt.frag_count == 1 {
            if pkt.frag_id == 0 {
                return Some(pkt);
            }
            tracing::warn!(
                "invalid single fragment id: {}, count: {}",
                pkt.frag_id,
                pkt.frag_count
            );
            return None;
        }
        if pkt.frag_count <= pkt.frag_id {
            tracing::warn!(
                "invalid frag, id, count: {}, {}",
                pkt.frag_id,
                pkt.frag_count
            );
            return None;
        }
        if pkt.frag_count > self.max_fragments_per_packet {
            tracing::warn!(
                "fragment count {} exceeds limit {}",
                pkt.frag_count,
                self.max_fragments_per_packet
            );
            return None;
        }

        self.prune_expired();

        if !self.packets.contains_key(&pkt.pkt_id) {
            if self.packets.len() >= self.max_packets {
                self.drop_oldest_packet();
            }
            if self.packets.len() >= self.max_packets {
                tracing::warn!(
                    "too many in-flight hysteria2 UDP fragmented packets"
                );
                return None;
            }
            self.packets.insert(
                pkt.pkt_id,
                FragmentedPacket {
                    addr: pkt.addr.clone(),
                    created_at: Instant::now(),
                    frags: vec![None; pkt.frag_count as usize],
                    cnt: 0,
                },
            );
        }

        let frag_id = pkt.frag_id as usize;
        let entry = self.packets.get_mut(&pkt.pkt_id)?;
        if pkt.frag_count as usize != entry.frags.len() || pkt.addr != entry.addr {
            tracing::warn!(
                "inconsistent hysteria2 UDP fragment for pkt_id {}",
                pkt.pkt_id
            );
            return None;
        }

        if entry.frags[frag_id].is_some() {
            return None;
        }
        entry.frags[frag_id] = Some(pkt);
        entry.cnt += 1;
        if entry.cnt as usize != entry.frags.len() {
            return None;
        }

        let pkt_id = entry.frags[0].as_ref()?.pkt_id;
        let entry = self.packets.remove(&pkt_id)?;
        let mut iters = entry.frags.into_iter().map(|x| x.unwrap());
        let mut pkt0 = iters.next().unwrap();
        pkt0.frag_count = 1;
        pkt0.frag_id = 0;
        for pkt in iters {
            pkt0.data.extend_from_slice(&pkt.data);
        }
        Some(pkt0)
    }

    fn prune_expired(&mut self) {
        let ttl = self.packet_ttl;
        self.packets
            .retain(|_, packet| packet.created_at.elapsed() < ttl);
    }

    fn drop_oldest_packet(&mut self) {
        let Some(oldest) = self
            .packets
            .iter()
            .min_by_key(|(_, packet)| packet.created_at)
            .map(|(pkt_id, _)| *pkt_id)
        else {
            return;
        };
        self.packets.remove(&oldest);
    }
}

#[test]
fn hy2_resp_parse() {
    let mut src = BytesMut::from(&[0x00, 0x03, 0x61, 0x62, 0x63, 0x00][..]);
    let msg = Hy2TcpCodec.decode(&mut src).unwrap().unwrap();
    assert!(msg.status == 0);
    assert!(msg.msg == "abc");

    let mut src = BytesMut::from(&[0x01, 0x00, 0x00][..]);
    let msg = Hy2TcpCodec.decode(&mut src).unwrap().unwrap();
    assert!(msg.status == 0x1);
    assert!(msg.msg.is_empty());
}

#[test]
fn test_decode_addr() {
    let socket_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 80));
    let addr = SocksAddr::Ip(socket_addr);
    let addr_bytes = addr.to_string().into_bytes();
    let decoded_addr = to_socksaddr(&addr_bytes).unwrap();
    assert_eq!(addr, decoded_addr);

    let addr = SocksAddr::Domain("example.com".to_string(), 80);
    let addr_bytes = addr.to_string().into_bytes();
    let decoded_addr = to_socksaddr(&addr_bytes).unwrap();
    assert_eq!(addr, decoded_addr);
}

#[test]
fn defragger_reassembles_interleaved_packets_by_packet_id() {
    let addr = SocksAddr::Ip(std::net::SocketAddr::from(([127, 0, 0, 1], 53)));
    let packet = |pkt_id, frag_id, data: &[u8]| HysUdpPacket {
        session_id: 1,
        pkt_id,
        frag_id,
        frag_count: 2,
        addr: addr.clone(),
        data: data.to_vec(),
    };

    let mut defragger = Defragger::default();
    assert!(defragger.feed(packet(1, 0, b"he")).is_none());
    assert!(defragger.feed(packet(2, 0, b"wo")).is_none());

    let first = defragger.feed(packet(1, 1, b"llo")).unwrap();
    assert_eq!(first.pkt_id, 1);
    assert_eq!(first.data, b"hello");

    let second = defragger.feed(packet(2, 1, b"rld")).unwrap();
    assert_eq!(second.pkt_id, 2);
    assert_eq!(second.data, b"world");
}

#[test]
fn defragger_rejects_invalid_single_fragment_id() {
    let addr = SocksAddr::Ip(std::net::SocketAddr::from(([127, 0, 0, 1], 53)));
    let pkt = HysUdpPacket {
        session_id: 1,
        pkt_id: 1,
        frag_id: 1,
        frag_count: 1,
        addr,
        data: b"x".to_vec(),
    };

    assert!(Defragger::default().feed(pkt).is_none());
}

#[test]
fn fragments_try_new_emits_one_fragment_for_empty_payload() {
    let addr = SocksAddr::Ip(std::net::SocketAddr::from(([127, 0, 0, 1], 53)));
    let fragments = Fragments::try_new(1, 1, addr, 1200, Bytes::new()).unwrap();
    assert_eq!(fragments.len(), 1);
    assert_eq!(fragments.collect::<Vec<_>>().len(), 1);
}

#[test]
fn tcp_request_decoder_keeps_trailing_stream_payload() {
    let addr = SocksAddr::Domain("example.com".to_owned(), 443);
    let mut buf = BytesMut::new();
    Hy2TcpCodec.encode(&addr, &mut buf).unwrap();
    buf.extend_from_slice(b"first tcp bytes");

    let req = Hy2TcpReqCodec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(req.addr, addr);
    assert_eq!(&buf[..], b"first tcp bytes");
}

#[test]
fn tcp_request_decoder_rejects_oversized_addr_len_before_buffering() {
    let mut buf = BytesMut::new();
    VarInt::from_u32(0x401).encode(&mut buf);
    VarInt::from_u32((MAX_HY2_TCP_ADDR_LEN + 1) as u32).encode(&mut buf);

    let err = Hy2TcpReqCodec.decode(&mut buf).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
}

#[test]
fn tcp_request_decoder_rejects_oversized_padding_len_before_buffering() {
    let addr = SocksAddr::Domain("example.com".to_owned(), 443);
    let addr = addr.to_string();
    let mut buf = BytesMut::new();
    VarInt::from_u32(0x401).encode(&mut buf);
    VarInt::from_u32(addr.len() as u32).encode(&mut buf);
    buf.extend_from_slice(addr.as_bytes());
    VarInt::from_u32((MAX_HY2_TCP_PADDING_LEN + 1) as u32).encode(&mut buf);

    let err = Hy2TcpReqCodec.decode(&mut buf).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
}
