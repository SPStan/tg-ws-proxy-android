use crate::config::{DC_DEFAULT_IPS, PROTO_TAG_ABRIDGED, PROTO_TAG_SECURE, STATS};
use crate::crypto::TrackedStream;
use crate::{linfo, lwarn};
use reqwest::{Client, Version};
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

// MTProto framing and CF /api protocol adapted from Flowseal v1.11.4,
// proxy/cf_h2.py. See LICENSE.Flowseal.
const MAX_PACKET: usize = 4 * 1024 * 1024;
const MAX_PADDING: usize = 256;
const MAX_PENDING: usize = 8;
const COOLDOWN: Duration = Duration::from_secs(30);
const SETUP_TIMEOUT: Duration = Duration::from_secs(8);

fn invalid(message: &str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

async fn read_plain<R: AsyncRead + Unpin>(
    reader: &mut R, cipher: &mut TrackedStream, buffer: &mut [u8],
) -> io::Result<()> {
    reader.read_exact(buffer).await?;
    cipher.xor(buffer);
    Ok(())
}

async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R, cipher: &mut TrackedStream, protocol: u32,
) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    let length = if protocol == PROTO_TAG_ABRIDGED {
        read_plain(reader, cipher, &mut header[..1]).await?;
        let words = header[0] & 0x7f;
        if words == 0x7f {
            read_plain(reader, cipher, &mut header[..3]).await?;
            (u32::from_le_bytes(header) as usize) * 4
        } else {
            (words as usize) * 4
        }
    } else {
        read_plain(reader, cipher, &mut header).await?;
        (u32::from_le_bytes(header) & 0x7fff_ffff) as usize
    };
    let allowed_padding = if protocol == PROTO_TAG_SECURE { MAX_PADDING } else { 0 };
    if !(24..=MAX_PACKET + allowed_padding).contains(&length) {
        return Err(invalid("MTProto packet length is out of range"));
    }

    let mut body = vec![0; length];
    read_plain(reader, cipher, &mut body).await?;
    if protocol == PROTO_TAG_SECURE {
        let (packet_length, max_padding) = if body[..8] == [0; 8] {
            let plaintext = u32::from_le_bytes(body[16..20].try_into().unwrap()) as usize;
            (plaintext.saturating_add(20), MAX_PADDING)
        } else {
            (24 + ((length - 24) / 16) * 16, 15)
        };
        if !(24..=length).contains(&packet_length) || length - packet_length > max_padding {
            return Err(invalid("Invalid MTProto padding"));
        }
        body.truncate(packet_length);
    }
    if body.len() > MAX_PACKET || body.len() % 4 != 0 {
        return Err(invalid("Invalid MTProto packet alignment"));
    }
    Ok(body)
}

fn encode_reply(body: &[u8], protocol: u32) -> Vec<u8> {
    let mut packet = Vec::with_capacity(body.len() + 7);
    if protocol == PROTO_TAG_ABRIDGED {
        let words = (body.len() / 4) as u32;
        if words < 0x7f {
            packet.push(words as u8);
        } else {
            packet.push(0x7f);
            packet.extend_from_slice(&words.to_le_bytes()[..3]);
        }
        packet.extend_from_slice(body);
    } else {
        use rand::RngCore;
        let mut padding = [0; 4];
        let padding_len = if protocol == PROTO_TAG_SECURE {
            rand::thread_rng().fill_bytes(&mut padding);
            (padding[0] % 4) as usize
        } else {
            0
        };
        packet.extend_from_slice(&((body.len() + padding_len) as u32).to_le_bytes());
        packet.extend_from_slice(body);
        packet.extend_from_slice(&padding[..padding_len]);
    }
    packet
}

#[derive(Default)]
struct DomainState {
    lane: Option<Arc<Lane>>,
    failed_until: Option<Instant>,
}

#[derive(Default)]
pub struct CfH2Pool {
    domains: Mutex<HashMap<String, Arc<Mutex<DomainState>>>>,
}

impl CfH2Pool {
    pub async fn open(&self, dc: i32, label: &str) -> Option<Arc<Lane>> {
        if !DC_DEFAULT_IPS.contains_key(&dc) {
            return None;
        }
        let ordered = crate::balancer::BALANCER.read().get_domains_for_dc(dc);
        let deadline = tokio::time::Instant::now() + SETUP_TIMEOUT;
        for base in ordered {
            let host = format!("kws{dc}.{base}");
            let entry = self.domains.lock().await.entry(host.clone()).or_default().clone();
            let Ok(mut state) = tokio::time::timeout_at(deadline, entry.lock()).await else {
                break;
            };
            if state.failed_until.is_some_and(|until| Instant::now() < until) {
                continue;
            }
            let lane = if let Some(lane) = &state.lane {
                lane.clone()
            } else {
                let result = tokio::time::timeout_at(deadline, Lane::open(&host)).await;
                match result {
                    Ok(Ok(lane)) => {
                        let lane = Arc::new(lane);
                        state.lane = Some(lane.clone());
                        lane
                    }
                    Ok(Err(err)) => {
                        state.failed_until = Some(Instant::now() + COOLDOWN);
                        lwarn!("[{}] H2 preflight {}: {}", label, host, err);
                        continue;
                    }
                    Err(_) => {
                        state.failed_until = Some(Instant::now() + COOLDOWN);
                        lwarn!("[{}] H2 preflight {}: timeout", label, host);
                        break;
                    }
                }
            };
            crate::balancer::BALANCER.write().update_domain_for_dc(dc, &base);
            linfo!("[{}] DC{} media -> CF HTTP/2 {}", label, dc, host);
            return Some(lane);
        }
        None
    }
}

enum Reply {
    Data(Vec<u8>),
    TransportError(i32),
}

pub struct Lane {
    client: Client,
    url: String,
    requests: Arc<Semaphore>,
}

impl Lane {
    async fn open(host: &str) -> io::Result<Self> {
        let client = Client::builder()
            .http2_prior_knowledge()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .retry(reqwest::retry::never())
            .connect_timeout(SETUP_TIMEOUT)
            .timeout(Duration::from_secs(65))
            .build().map_err(io::Error::other)?;
        let url = format!("https://{host}/api");
        let response = client.head(&url).send().await.map_err(io::Error::other)?;
        let status = response.status();
        if response.version() != Version::HTTP_2 ||
            !(status.is_success() || matches!(status.as_u16(), 405 | 501))
        {
            return Err(invalid(&format!("expected HTTP/2 /api, got {:?} {status}", response.version())));
        }
        Ok(Self { client, url, requests: Arc::new(Semaphore::new(MAX_PENDING)) })
    }

    async fn post(&self, packet: Vec<u8>) -> io::Result<Reply> {
        STATS.bytes_up.fetch_add(packet.len() as i64, Ordering::Relaxed);
        let mut response = self.client.post(&self.url)
            .header("content-type", "application/octet-stream")
            .header("accept-encoding", "identity")
            .body(packet).send().await.map_err(io::Error::other)?;
        let status = response.status().as_u16();
        if response.version() != Version::HTTP_2 {
            return Err(invalid("CF /api did not negotiate HTTP/2"));
        }
        if matches!(status, 403 | 404 | 429 | 444) {
            return Ok(Reply::TransportError(-i32::from(status)));
        }
        if status != 200 {
            return Err(invalid(&format!("CF /api returned HTTP {status}")));
        }
        if response.headers().get("content-type").is_some_and(|value| {
            value.to_str().is_ok_and(|text| text.to_ascii_lowercase().contains("text/html"))
        }) || response.headers().get("content-encoding").is_some_and(|value| value != "identity") {
            return Err(invalid("CF /api did not return binary MTProto"));
        }
        let declared = response.content_length();
        if declared.is_some_and(|length| length > MAX_PACKET as u64) {
            return Err(invalid("CF /api response exceeds packet bound"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(io::Error::other)? {
            if body.len() + chunk.len() > MAX_PACKET {
                return Err(invalid("CF /api response exceeds packet bound"));
            }
            body.extend_from_slice(&chunk);
        }
        if body.len() % 4 != 0 || declared.is_some_and(|length| length != body.len() as u64) {
            return Err(invalid("CF /api response has invalid MTProto length"));
        }
        if let Ok(bytes) = <[u8; 4]>::try_from(body.as_slice()) {
            let code = i32::from_le_bytes(bytes);
            if code < 0 {
                return Ok(Reply::TransportError(code));
            }
        }
        Ok(Reply::Data(body))
    }
}

pub async fn bridge<R, W>(
    mut reader: R, mut writer: W, lane: Arc<Lane>, protocol: u32,
    (mut decrypt, mut encrypt): (TrackedStream, TrackedStream), cancel: CancellationToken,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (packets, mut incoming) = mpsc::channel(1);
    let upload = async move {
        loop {
            let packet = read_packet(&mut reader, &mut decrypt, protocol).await?;
            if packets.send(packet).await.is_err() {
                return Ok(());
            }
        }
    };
    let download = async {
        let mut pending = JoinSet::new();
        loop {
            tokio::select! {
                Some(packet) = incoming.recv(), if pending.len() < MAX_PENDING => {
                    let lane = lane.clone();
                    pending.spawn(async move {
                        let permit = lane.requests.clone().acquire_owned().await.map_err(io::Error::other)?;
                        Ok::<_, io::Error>((lane.post(packet).await?, permit))
                    });
                }
                Some(result) = pending.join_next(), if !pending.is_empty() => {
                    let (reply, _permit) = result.map_err(io::Error::other)??;
                    let (body, terminal) = match reply {
                        Reply::Data(body) => (body, false),
                        Reply::TransportError(code) => (code.to_le_bytes().to_vec(), true),
                    };
                    if !body.is_empty() {
                        let mut frame = encode_reply(&body, protocol);
                        encrypt.xor(&mut frame);
                        writer.write_all(&frame).await?;
                        STATS.bytes_down.fetch_add(body.len() as i64, Ordering::Relaxed);
                    }
                    if terminal {
                        return Ok(());
                    }
                }
            }
        }
    };
    tokio::select! {
        _ = cancel.cancelled() => Ok(()),
        result = upload => result,
        result = download => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PROTO_TAG_INTERMEDIATE;
    use crate::crypto::new_aes_ctr;

    #[tokio::test]
    async fn padded_plaintext_preserves_payload_and_removes_padding() {
        let mut body = vec![0; 24];
        body[16..20].copy_from_slice(&4u32.to_le_bytes());
        let mut frame = 280u32.to_le_bytes().to_vec();
        frame.extend_from_slice(&body);
        frame.extend_from_slice(&[1; 256]);
        new_aes_ctr(&[0; 32], &[0; 16]).xor(&mut frame);
        let decoded = read_packet(&mut frame.as_slice(), &mut new_aes_ctr(&[0; 32], &[0; 16]), PROTO_TAG_SECURE)
            .await.unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn transport_error_keeps_native_framing() {
        let body = (-429i32).to_le_bytes();
        assert_eq!(encode_reply(&body, PROTO_TAG_ABRIDGED), [&[1], body.as_slice()].concat());
        assert_eq!(encode_reply(&body, PROTO_TAG_INTERMEDIATE), [&[4, 0, 0, 0], body.as_slice()].concat());
    }
}
