use crate::config::{log_debug, log_warn, STATS};
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use ring::{agreement, rand::SystemRandom};
use sha2::Sha256;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_RECORD_CCS: u8 = 0x14;
pub const TLS_RECORD_APPDATA: u8 = 0x17;

const CLIENT_RANDOM_OFFSET: usize = 11;
const CLIENT_RANDOM_LEN: usize = 32;
const SESSION_ID_OFFSET: usize = 44;
const SESSION_ID_LEN: usize = 32;

const TIMESTAMP_TOLERANCE: i64 = 120;
const TLS_APPDATA_MAX: usize = 16384;

const READ_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_RECORD_TIMEOUT: Duration = Duration::from_secs(10);
const MASKING_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const CCS_FRAME: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

const SH_RANDOM_OFF: usize = 11;
const SH_SESSID_OFF: usize = 44;
const EXT_KEY_SHARE: u16 = 0x0033;
const X25519: u16 = 0x001d;
const X25519_MLKEM768: u16 = 0x11ec;
const FALLBACK_APPDATA_RANGE: std::ops::RangeInclusive<usize> = 64..=160;

type HmacSha256 = Hmac<Sha256>;

pub struct FakeTlsStream {
    pub read: Box<dyn AsyncRead + Send + Unpin>,
    pub write: Box<dyn AsyncWrite + Send + Unpin>,
}

fn verify_client_hello(data: &[u8], secret: &[u8]) -> Option<([u8; 32], [u8; 32], i64)> {
    if data.len() < 43 {
        return None;
    }
    if data[0] != TLS_RECORD_HANDSHAKE {
        return None;
    }
    if data[5] != 0x01 {
        return None;
    }

    let mut client_random = [0u8; 32];
    client_random
        .copy_from_slice(&data[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN]);

    let mut zeroed = data.to_vec();
    for b in &mut zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN] {
        *b = 0;
    }

    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(&zeroed);
    if mac.clone().verify_truncated_left(&client_random[..28]).is_err() {
        return None;
    }

    let expected = mac.finalize().into_bytes();
    let mut ts_bytes = [0u8; 4];
    for i in 0..4 {
        ts_bytes[i] = client_random[28 + i] ^ expected[28 + i];
    }
    let timestamp = u32::from_le_bytes(ts_bytes) as i64;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if (now - timestamp).abs() > TIMESTAMP_TOLERANCE {
        return None;
    }

    let mut session_id = [0u8; 32];
    if data.len() >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43] == 0x20 {
        session_id
            .copy_from_slice(&data[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]);
    }

    Some((client_random, session_id, timestamp))
}

// ClientHello parsing and first-flight layout adapted from Flowseal v1.11.4
// (proxy/fake_tls.py). See LICENSE.Flowseal.
fn take<'a>(input: &mut &'a [u8], count: usize) -> Option<&'a [u8]> {
    let (head, tail) = input.split_at_checked(count)?;
    *input = tail;
    Some(head)
}

fn take_u16(input: &mut &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(take(input, 2)?.try_into().ok()?))
}

fn hello_parameters(data: &[u8]) -> Option<(u16, bool)> {
    let mut hello = data.get(43..)?;
    let session_len = *take(&mut hello, 1)?.first()? as usize;
    take(&mut hello, session_len)?;
    let suite_len = take_u16(&mut hello)? as usize;
    let suites = take(&mut hello, suite_len)?;
    let suite = [0x1301u16, 0x1303, 0x1302].into_iter()
        .find(|suite| suites.chunks_exact(2).any(|bytes| bytes == suite.to_be_bytes()))
        .unwrap_or(0x1301);
    let compression_len = *take(&mut hello, 1)?.first()? as usize;
    take(&mut hello, compression_len)?;
    let extensions_len = take_u16(&mut hello)? as usize;
    let mut extensions = take(&mut hello, extensions_len)?;
    while !extensions.is_empty() {
        let kind = take_u16(&mut extensions)?;
        let len = take_u16(&mut extensions)? as usize;
        let mut extension = take(&mut extensions, len)?;
        if kind == EXT_KEY_SHARE {
            let entries_len = take_u16(&mut extension)? as usize;
            let mut entries = take(&mut extension, entries_len)?;
            while !entries.is_empty() {
                let group = take_u16(&mut entries)?;
                let key_len = take_u16(&mut entries)? as usize;
                take(&mut entries, key_len)?;
                if group == X25519_MLKEM768 && key_len == 1216 {
                    return Some((suite, true));
                }
            }
        }
    }
    Some((suite, false))
}

fn build_server_hello(
    secret: &[u8], client_random: &[u8; 32], session_id: &[u8; 32],
    (suite, hybrid): (u16, bool), profiled_len: usize,
) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut share = if hybrid { vec![0; 1088] } else { Vec::new() };
    rng.fill_bytes(&mut share);
    if let Ok(public) = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new())
        .and_then(|secret| secret.compute_public_key())
    {
        share.extend_from_slice(public.as_ref());
    } else {
        let mut public = [0u8; 32];
        rng.fill_bytes(&mut public);
        public[31] &= 0x7f;
        share.extend_from_slice(&public);
    }

    let group = if hybrid { X25519_MLKEM768 } else { X25519 };
    let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
    extensions.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
    extensions.extend_from_slice(&((4 + share.len()) as u16).to_be_bytes());
    extensions.extend_from_slice(&group.to_be_bytes());
    extensions.extend_from_slice(&(share.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&share);

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0; 32]);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&suite.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut response = vec![TLS_RECORD_HANDSHAKE, 0x03, 0x03];
    response.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    response.push(0x02);
    response.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    response.extend_from_slice(&body);
    response.extend_from_slice(&CCS_FRAME);

    let encrypted_size = if profiled_len == 0 {
        rng.gen_range(FALLBACK_APPDATA_RANGE)
    } else {
        profiled_len.clamp(64, TLS_APPDATA_MAX)
    };
    response.extend_from_slice(&[TLS_RECORD_APPDATA, 0x03, 0x03]);
    response.extend_from_slice(&(encrypted_size as u16).to_be_bytes());
    let offset = response.len();
    response.resize(offset + encrypted_size, 0);
    rng.fill_bytes(&mut response[offset..]);

    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(client_random);
    mac.update(&response);
    response[SH_RANDOM_OFF..SH_RANDOM_OFF + 32].copy_from_slice(&mac.finalize().into_bytes());
    response
}

pub async fn probe_appdata_len(domain: &str) -> Option<usize> {
    let probe = async {
        let mut config = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let server = rustls_pki_types::ServerName::try_from(domain.to_owned()).ok()?;
        let mut client = rustls::ClientConnection::new(Arc::new(config), server).ok()?;
        let mut hello = Vec::new();
        client.write_tls(&mut hello).ok()?;
        let mut conn = TcpStream::connect((domain, 443)).await.ok()?;
        conn.write_all(&hello).await.ok()?;
        // Limit both the record count and the time spent reading the first flight.
        for _ in 0..8 {
            let mut header = [0; 5];
            conn.read_exact(&mut header).await.ok()?;
            let size = u16::from_be_bytes([header[3], header[4]]) as usize;
            match header[0] {
                TLS_RECORD_APPDATA => return (size != 0).then_some(size),
                TLS_RECORD_HANDSHAKE | TLS_RECORD_CCS if size <= TLS_APPDATA_MAX => {
                    conn.read_exact(&mut vec![0; size]).await.ok()?;
                }
                _ => return None,
            }
        }
        None
    };
    tokio::time::timeout(Duration::from_secs(5), probe).await.ok().flatten()
}

fn wrap_tls_record(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / TLS_APPDATA_MAX + 1));
    let mut offset = 0;
    while offset < data.len() {
        let end = std::cmp::min(offset + TLS_APPDATA_MAX, data.len());
        let chunk = &data[offset..end];
        out.push(TLS_RECORD_APPDATA);
        out.push(0x03);
        out.push(0x03);
        out.push((chunk.len() >> 8) as u8);
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
        offset = end;
    }
    out
}

struct TlsRecordReader {
    inner: ReadHalf<TcpStream>,
    buf: Vec<u8>,
    pos: usize,
    read_left: usize,
}

impl TlsRecordReader {
    fn new(inner: ReadHalf<TcpStream>) -> Self {
        TlsRecordReader {
            inner,
            buf: Vec::new(),
            pos: 0,
            read_left: 0,
        }
    }

    fn compact(&mut self) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn next_payload(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            loop {
                if self.read_left > 0 {
                    let want = std::cmp::min(self.read_left, 16384);
                    let mut chunk = vec![0u8; want];
                    let n = self.inner.read(&mut chunk).await?;
                    if n == 0 {
                        return Ok(Vec::new());
                    }
                    chunk.truncate(n);
                    self.read_left -= n;
                    return Ok(chunk);
                }

                let mut hdr = [0u8; 5];
                self.inner.read_exact(&mut hdr).await?;
                let rtype = hdr[0];
                let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;

                if rtype == TLS_RECORD_CCS {
                    if rec_len > 0 {
                        let mut junk = vec![0u8; rec_len];
                        self.inner.read_exact(&mut junk).await?;
                    }
                    continue;
                }

                if rtype != TLS_RECORD_APPDATA {
                    return Ok(Vec::new());
                }

                let want = std::cmp::min(rec_len, 65536);
                let mut chunk = vec![0u8; want];
                let n = self.inner.read(&mut chunk).await?;
                if n == 0 {
                    return Ok(Vec::new());
                }
                chunk.truncate(n);
                if rec_len > n {
                    self.read_left = rec_len - n;
                }
                return Ok(chunk);
            }
        })
    }
}

impl AsyncRead for TlsRecordReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            let avail = this.buf.len() - this.pos;
            if avail > 0 {
                let n = std::cmp::min(avail, buf.remaining());
                let src = &this.buf[this.pos..this.pos + n];
                buf.put_slice(src);
                this.pos += n;
                if this.pos == this.buf.len() {
                    this.buf.clear();
                    this.pos = 0;
                }
                return std::task::Poll::Ready(Ok(()));
            }

            this.compact();
            let polled = {
                let mut fut = this.next_payload();
                Pin::new(&mut fut).poll(cx)
            };
            match polled {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => {
                    return std::task::Poll::Ready(Err(
                        if e.kind() == std::io::ErrorKind::UnexpectedEof {
                            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "faketls eof")
                        } else {
                            e
                        },
                    ))
                }
                std::task::Poll::Ready(Ok(payload)) => {
                    if payload.is_empty() {
                        return std::task::Poll::Ready(Ok(()));
                    }
                    this.buf = payload;
                    this.pos = 0;
                }
            }
        }
    }
}

struct TlsRecordWriter {
    inner: WriteHalf<TcpStream>,
}

impl TlsRecordWriter {
    fn new(inner: WriteHalf<TcpStream>) -> Self {
        TlsRecordWriter { inner }
    }
}

impl AsyncWrite for TlsRecordWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let wrapped = wrap_tls_record(buf);
        match Pin::new(&mut this.inner).poll_write(cx, &wrapped) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Ok(n)) => {
                std::task::Poll::Ready(Ok(if n >= buf.len() { buf.len() } else { n }))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub async fn server_handshake(
    mut conn: TcpStream,
    first: u8,
    secret: &[u8],
    masking: &str,
    label: &str,
    profiled_len: usize,
) -> Option<FakeTlsStream> {
    let mut hdr_rest = [0u8; 4];
    match tokio::time::timeout(READ_HANDSHAKE_TIMEOUT, conn.read_exact(&mut hdr_rest)).await {
        Ok(Ok(_)) => {}
        _ => {
            log_debug(&format!("[{}] incomplete TLS record header", label));
            return None;
        }
    }

    let mut tls_header = [0u8; 5];
    tls_header[0] = first;
    tls_header[1..5].copy_from_slice(&hdr_rest);
    let record_len = u16::from_be_bytes([tls_header[3], tls_header[4]]) as usize;

    let mut body = vec![0u8; record_len];
    match tokio::time::timeout(READ_RECORD_TIMEOUT, conn.read_exact(&mut body)).await {
        Ok(Ok(_)) => {}
        _ => {
            log_debug(&format!("[{}] incomplete TLS record body", label));
            return None;
        }
    }

    let mut client_hello = Vec::with_capacity(5 + record_len);
    client_hello.extend_from_slice(&tls_header);
    client_hello.extend_from_slice(&body);

    match verify_client_hello(&client_hello, secret) {
        Some((client_random, session_id, ts)) => {
            log_debug(&format!("[{}] Fake TLS handshake ok (ts={})", label, ts));
            let params = hello_parameters(&client_hello).unwrap_or((0x1301, false));
            let server_hello = build_server_hello(secret, &client_random, &session_id, params, profiled_len);
            let delay_ms = rand::thread_rng().gen_range(8..=24);
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            if conn.write_all(&server_hello).await.is_err() {
                return None;
            }
            let _ = conn.flush().await;

            let (r, w) = tokio::io::split(conn);
            Some(FakeTlsStream {
                read: Box::new(TlsRecordReader::new(r)),
                write: Box::new(TlsRecordWriter::new(w)),
            })
        }
        None => {
            log_debug(&format!(
                "[{}] Fake TLS verify failed (size={} rec={}) -> masking",
                label,
                client_hello.len(),
                record_len
            ));
            proxy_to_masking_domain(conn, client_hello, masking, label).await;
            None
        }
    }
}

async fn proxy_to_masking_domain(conn: TcpStream, initial: Vec<u8>, domain: &str, label: &str) {
    let upstream = match tokio::time::timeout(
        MASKING_CONNECT_TIMEOUT,
        TcpStream::connect((domain, 443u16)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            log_warn(&format!(
                "[{}] masking: cannot connect to {}:443",
                label, domain
            ));
            return;
        }
    };

    log_debug(&format!("[{}] masking -> {}:443", label, domain));
    STATS
        .connections_masked
        .fetch_add(1, Ordering::Relaxed);

    let mut upstream = upstream;
    if upstream.write_all(&initial).await.is_err() {
        return;
    }

    let (mut c_read, mut c_write) = tokio::io::split(conn);
    let (mut u_read, mut u_write) = tokio::io::split(upstream);

    let up = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut c_read, &mut u_write).await;
        let _ = u_write.shutdown().await;
    });
    let down = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut u_read, &mut c_write).await;
        let _ = c_write.shutdown().await;
    });

    let _ = tokio::join!(up, down);
}
