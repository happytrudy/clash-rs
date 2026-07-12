use std::{cmp::min, io, time::SystemTime};

use aes_gcm::Aes128Gcm;
use argon2::{Algorithm, Argon2, Params, Version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common::crypto::AeadCipherHelper;

use super::profile::Profile;

const HEADER_VERSION: u8 = 4;
const HEADER_PLAIN_LEN: usize = 7;
const TAG_LEN: usize = 16;
const HEADER_CIPHER_LEN: usize = HEADER_PLAIN_LEN + TAG_LEN;
const SALT_LEN: usize = 16;
const MAX_PAYLOAD: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Default,
    Unshaped,
    UnsafeRaw,
}

impl Mode {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "" | "default" => Ok(Self::Default),
            "unshaped" => Ok(Self::Unshaped),
            "unsafe-raw" => Ok(Self::UnsafeRaw),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("snell: unknown v6 mode: {value}"),
            )),
        }
    }
}

pub struct RecordReader<R> {
    inner: R,
    mode: Mode,
    psk: Vec<u8>,
    profile: Option<Profile>,
    cipher: Option<Aes128Gcm>,
    nonce: [u8; 12],
    sequence: u32,
}

impl<R: AsyncRead + Unpin> RecordReader<R> {
    pub fn new(
        inner: R,
        mode: Mode,
        psk: Vec<u8>,
        profile: Option<Profile>,
    ) -> Self {
        Self {
            inner,
            mode,
            psk,
            profile,
            cipher: None,
            nonce: [0; 12],
            sequence: 0,
        }
    }

    pub async fn read_record(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.mode {
            Mode::UnsafeRaw => self.read_raw().await,
            Mode::Unshaped => self.read_unshaped().await,
            Mode::Default => self.read_shaped().await,
        }
    }

    async fn read_raw(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut header = [0u8; HEADER_PLAIN_LEN];
        self.inner.read_exact(&mut header).await?;
        let (padding, payload) = parse_header(&header, true)?;
        if padding != 0 {
            return Err(invalid_data("snell: raw record contains padding"));
        }
        if payload == 0 {
            return Ok(None);
        }
        let mut body = vec![0u8; payload];
        self.inner.read_exact(&mut body).await?;
        Ok(Some(body))
    }

    async fn read_unshaped(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.cipher.is_none() {
            let mut salt = [0u8; SALT_LEN];
            self.inner.read_exact(&mut salt).await?;
            self.cipher = Some(make_cipher(&self.psk, &salt)?);
        }
        let mut header = vec![0u8; HEADER_CIPHER_LEN];
        self.inner.read_exact(&mut header).await?;
        decrypt(
            self.cipher.as_ref().unwrap(),
            &mut self.nonce,
            &[],
            &mut header,
        )?;
        let (padding, payload) = parse_header(&header[..HEADER_PLAIN_LEN], true)?;
        if padding != 0 {
            return Err(invalid_data("snell: unshaped record contains padding"));
        }
        if payload == 0 {
            return Ok(None);
        }
        let mut body = vec![0u8; payload + TAG_LEN];
        self.inner.read_exact(&mut body).await?;
        decrypt(
            self.cipher.as_ref().unwrap(),
            &mut self.nonce,
            &[],
            &mut body,
        )?;
        body.truncate(payload);
        Ok(Some(body))
    }

    async fn read_shaped(&mut self) -> io::Result<Option<Vec<u8>>> {
        let profile = self
            .profile
            .as_ref()
            .expect("profile required for default mode");
        if self.cipher.is_none() {
            let mut salt_block = vec![0u8; profile.salt_block_len];
            self.inner.read_exact(&mut salt_block).await?;
            let salt = profile.extract_salt(&salt_block);
            self.cipher = Some(make_cipher(&self.psk, &salt)?);
        }

        let prefix_len = profile.prefix_len(self.sequence);
        let mut prefix = vec![0u8; prefix_len];
        self.inner.read_exact(&mut prefix).await?;
        let mut header = vec![0u8; HEADER_CIPHER_LEN];
        self.inner.read_exact(&mut header).await?;
        decrypt(
            self.cipher.as_ref().unwrap(),
            &mut self.nonce,
            &prefix,
            &mut header,
        )?;
        let (padding_len, payload_len) =
            parse_header(&header[..HEADER_PLAIN_LEN], false)?;
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);

        let mut padding = vec![0u8; padding_len];
        self.inner.read_exact(&mut padding).await?;
        if payload_len == 0 {
            return Ok(None);
        }
        let mut body = vec![0u8; payload_len + TAG_LEN];
        self.inner.read_exact(&mut body).await?;
        profile.mix_payload(sequence, &mut padding, &mut body);
        decrypt(
            self.cipher.as_ref().unwrap(),
            &mut self.nonce,
            &padding,
            &mut body,
        )?;
        body.truncate(payload_len);
        Ok(Some(body))
    }
}

pub struct RecordWriter<W> {
    inner: W,
    mode: Mode,
    psk: Vec<u8>,
    profile: Option<Profile>,
    cipher: Option<Aes128Gcm>,
    nonce: [u8; 12],
    sequence: u32,
    salt: Option<[u8; SALT_LEN]>,
    salt_sent: bool,
    chunk_size: usize,
    last_write: Option<SystemTime>,
}

impl<W: AsyncWrite + Unpin> RecordWriter<W> {
    pub fn new(
        inner: W,
        mode: Mode,
        psk: Vec<u8>,
        profile: Option<Profile>,
    ) -> Self {
        Self {
            inner,
            mode,
            psk,
            profile,
            cipher: None,
            nonce: [0; 12],
            sequence: 0,
            salt: None,
            salt_sent: false,
            chunk_size: 0,
            last_write: None,
        }
    }

    pub async fn write_payload(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        let mut output = Vec::new();
        let mut remaining = payload;
        while !remaining.is_empty() {
            let limit = self.payload_limit();
            let count = min(limit, remaining.len());
            self.append_record(&remaining[..count], &mut output)?;
            remaining = &remaining[count..];
        }
        self.inner.write_all(&output).await
    }

    pub async fn write_packet(&mut self, payload: &[u8]) -> io::Result<()> {
        let limit = self.payload_limit();
        if payload.is_empty() || payload.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell UDP packet exceeds the current record payload limit",
            ));
        }
        let mut output = Vec::new();
        self.append_record(payload, &mut output)?;
        self.inner.write_all(&output).await
    }

    pub async fn write_eof(&mut self) -> io::Result<()> {
        let mut output = Vec::new();
        self.append_record(&[], &mut output)?;
        self.inner.write_all(&output).await?;
        self.inner.flush().await
    }

    fn payload_limit(&mut self) -> usize {
        if self.mode != Mode::Default {
            return MAX_PAYLOAD;
        }
        let profile = self.profile.as_ref().unwrap();
        let now = SystemTime::now();
        let reset = self
            .last_write
            .and_then(|last| now.duration_since(last).ok())
            .is_none_or(|elapsed| {
                elapsed.as_secs() > profile.idle_reset_secs as u64
            });
        if reset || self.chunk_size == 0 {
            self.chunk_size = profile.chunk_initial;
        }
        let mut limit = profile.payload_limit(self.sequence, self.chunk_size);
        if self.sequence == 0 {
            limit = min(limit, profile.first_record_cap);
        }
        self.chunk_size = profile.next_chunk_size(self.chunk_size);
        self.last_write = Some(now);
        limit.clamp(1, MAX_PAYLOAD)
    }

    fn append_record(
        &mut self,
        payload: &[u8],
        output: &mut Vec<u8>,
    ) -> io::Result<()> {
        match self.mode {
            Mode::UnsafeRaw => {
                output.extend_from_slice(&header(0, payload.len()));
                output.extend_from_slice(payload);
            }
            Mode::Unshaped => self.append_unshaped(payload, output)?,
            Mode::Default => self.append_shaped(payload, output)?,
        }
        Ok(())
    }

    fn ensure_cipher(&mut self) -> io::Result<()> {
        if self.cipher.is_none() {
            let salt = rand::random::<[u8; SALT_LEN]>();
            self.cipher = Some(make_cipher(&self.psk, &salt)?);
            self.salt = Some(salt);
        }
        Ok(())
    }

    fn append_unshaped(
        &mut self,
        payload: &[u8],
        output: &mut Vec<u8>,
    ) -> io::Result<()> {
        self.ensure_cipher()?;
        if !self.salt_sent {
            output.extend_from_slice(self.salt.as_ref().unwrap());
            self.salt_sent = true;
        }
        let mut record_header = header(0, payload.len()).to_vec();
        record_header.resize(HEADER_CIPHER_LEN, 0);
        encrypt(
            self.cipher.as_ref().unwrap(),
            &mut self.nonce,
            &[],
            &mut record_header,
        );
        output.extend_from_slice(&record_header);
        if !payload.is_empty() {
            let mut body = payload.to_vec();
            body.resize(payload.len() + TAG_LEN, 0);
            encrypt(
                self.cipher.as_ref().unwrap(),
                &mut self.nonce,
                &[],
                &mut body,
            );
            output.extend_from_slice(&body);
        }
        Ok(())
    }

    fn append_shaped(
        &mut self,
        payload: &[u8],
        output: &mut Vec<u8>,
    ) -> io::Result<()> {
        self.ensure_cipher()?;
        let profile = self.profile.as_ref().unwrap();
        let prefix_len = profile.prefix_len(self.sequence);
        let salt_block_len = usize::from(!self.salt_sent) * profile.salt_block_len;
        let salt_prefix_len = salt_block_len.saturating_sub(SALT_LEN);
        let padding_len = profile.padding_len(
            self.sequence,
            payload.len(),
            prefix_len,
            salt_prefix_len,
            salt_block_len,
        );

        if !self.salt_sent {
            let mut block = vec![0u8; salt_block_len];
            profile.fill_padding(u32::MAX, &mut block);
            profile.write_salt(self.salt.as_ref().unwrap(), &mut block);
            output.extend_from_slice(&block);
            self.salt_sent = true;
        }
        let mut prefix = vec![0u8; prefix_len];
        profile.fill_padding(self.sequence, &mut prefix);
        output.extend_from_slice(&prefix);

        let mut record_header = header(padding_len, payload.len()).to_vec();
        record_header.resize(HEADER_CIPHER_LEN, 0);
        encrypt(
            self.cipher.as_ref().unwrap(),
            &mut self.nonce,
            &prefix,
            &mut record_header,
        );
        output.extend_from_slice(&record_header);

        let mut padding = vec![0u8; padding_len];
        profile.fill_padding(self.sequence, &mut padding);
        if payload.is_empty() {
            output.extend_from_slice(&padding);
        } else {
            let mut body = payload.to_vec();
            body.resize(payload.len() + TAG_LEN, 0);
            encrypt(
                self.cipher.as_ref().unwrap(),
                &mut self.nonce,
                &padding,
                &mut body,
            );
            profile.mix_payload(self.sequence, &mut padding, &mut body);
            output.extend_from_slice(&padding);
            output.extend_from_slice(&body);
        }
        self.sequence = self.sequence.wrapping_add(1);
        Ok(())
    }
}

fn make_cipher(psk: &[u8], salt: &[u8; SALT_LEN]) -> io::Result<Aes128Gcm> {
    let params = Params::new(8, 3, 1, Some(32)).map_err(|error| {
        invalid_data_owned(format!("snell: invalid Argon2 parameters: {error}"))
    })?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(psk, salt, &mut key)
        .map_err(|error| {
            invalid_data_owned(format!("snell: key derivation failed: {error}"))
        })?;
    Ok(Aes128Gcm::new_with_slice(&key[..16]))
}

fn encrypt(cipher: &Aes128Gcm, nonce: &mut [u8; 12], aad: &[u8], data: &mut [u8]) {
    cipher.encrypt_in_place_with_slice(nonce, aad, data);
    increase_nonce(nonce);
}

fn decrypt(
    cipher: &Aes128Gcm,
    nonce: &mut [u8; 12],
    aad: &[u8],
    data: &mut [u8],
) -> io::Result<()> {
    cipher
        .decrypt_in_place_with_slice(nonce, aad, data)
        .map_err(|_| invalid_data("snell: record authentication failed"))?;
    increase_nonce(nonce);
    Ok(())
}

fn increase_nonce(nonce: &mut [u8; 12]) {
    for byte in nonce {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn header(padding_len: usize, payload_len: usize) -> [u8; HEADER_PLAIN_LEN] {
    let mut output = [0u8; HEADER_PLAIN_LEN];
    output[0] = HEADER_VERSION;
    output[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
    output[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
    output
}

fn parse_header(header: &[u8], strict_reserved: bool) -> io::Result<(usize, usize)> {
    if header.len() != HEADER_PLAIN_LEN || header[0] != HEADER_VERSION {
        return Err(invalid_data("snell: invalid record version"));
    }
    if strict_reserved && (header[1] != 0 || header[2] != 0) {
        return Err(invalid_data("snell: reserved record bytes are non-zero"));
    }
    Ok((
        u16::from_be_bytes([header[3], header[4]]) as usize,
        u16::from_be_bytes([header[5], header[6]]) as usize,
    ))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_data_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::{Mode, RecordReader, RecordWriter};
    use crate::proxy::snell::profile::Profile;

    #[tokio::test]
    async fn round_trips_all_v6_record_modes() {
        let psk = b"!dubuxOpopop880@@".to_vec();
        let payload = (0..100_000).map(|value| value as u8).collect::<Vec<_>>();

        for mode in [Mode::Default, Mode::Unshaped, Mode::UnsafeRaw] {
            let profile = (mode == Mode::Default).then(|| Profile::new(&psk));
            let (writer_stream, reader_stream) = tokio::io::duplex(512 * 1024);
            let mut writer =
                RecordWriter::new(writer_stream, mode, psk.clone(), profile.clone());
            let mut reader =
                RecordReader::new(reader_stream, mode, psk.clone(), profile);

            writer.write_payload(&payload).await.unwrap();
            writer.write_eof().await.unwrap();
            let mut received = Vec::new();
            while let Some(record) = reader.read_record().await.unwrap() {
                received.extend_from_slice(&record);
            }
            assert_eq!(received, payload, "mode {mode:?}");
        }
    }

    #[tokio::test]
    async fn shaped_udp_preserves_one_record_boundary() {
        let psk = b"!dubuxOpopop880@@".to_vec();
        let profile = Profile::new(&psk);
        let first_limit = profile.first_record_cap;
        let (writer_stream, _reader_stream) = tokio::io::duplex(4096);
        let mut writer =
            RecordWriter::new(writer_stream, Mode::Default, psk, Some(profile));

        let error = writer
            .write_packet(&vec![0u8; first_limit + 1])
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
