use super::*;
use std::process::Command;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn test_tls() -> (TlsAcceptor, Arc<ClientConfig>) {
    let dir = std::env::temp_dir().join(format!("tgwsproxy-{}", rand::random::<u64>()));
    std::fs::create_dir(&dir).unwrap();
    let cert = dir.join("cert.der");
    let key = dir.join("key.der");
    assert!(Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-noenc", "-days", "1", "-subj", "/CN=localhost", "-addext",
            "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE",
            "-outform", "DER", "-out",
        ])
        .arg(&cert)
        .arg("-keyout")
        .arg(dir.join("key.pem"))
        .output().unwrap().status.success());
    assert!(Command::new("openssl")
        .args(["pkcs8", "-topk8", "-nocrypt", "-outform", "DER", "-in"])
        .arg(dir.join("key.pem"))
        .arg("-out")
        .arg(&key)
        .status().unwrap().success());
    let cert = CertificateDer::from(std::fs::read(cert).unwrap());
    let key = rustls_pki_types::PrivatePkcs8KeyDer::from(std::fs::read(key).unwrap());
    std::fs::remove_dir_all(dir).unwrap();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth().with_single_cert(vec![cert.clone()], key.into()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let client = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    (TlsAcceptor::from(Arc::new(server)), Arc::new(client))
}

async fn serve_upgrade<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, path: String) {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        request.push(stream.read_u8().await.unwrap());
        assert!(request.len() < 8192);
    }
    let request = String::from_utf8(request).unwrap();
    assert!(request.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
    assert!(request.contains("\r\nUpgrade: websocket\r\n"));
    assert!(request.contains("\r\nHost: localhost\r\n"));
    stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();

    assert_eq!(stream.read_u8().await.unwrap(), 0x82);
    assert_eq!(stream.read_u8().await.unwrap(), 0x84);
    let mut mask = [0; 4];
    let mut data = [0; 4];
    stream.read_exact(&mut mask).await.unwrap();
    stream.read_exact(&mut data).await.unwrap();
    xor_mask_in_place(&mut data, &mask);
    assert_eq!(&data, b"ping");
    stream.write_all(b"\x82\x04pong").await.unwrap();
}

#[tokio::test]
async fn cloudflare_upgrades_and_exchanges_data_in_both_modes() {
    let (server, client) = test_tls();
    for path in ["/apiws", "/apiws?dst=149.154.167.51&dc=2"] {
        for tls in [false, true] {
            let route = WsRoute::Cloudflare { tls };
            assert_eq!(route.port(), if tls { 443 } else { 80 });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = server.clone();
            let server_task = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut byte = [0];
                assert_eq!(socket.peek(&mut byte).await.unwrap(), 1);
                assert_eq!(byte[0], if tls { 0x16 } else { b'G' });
                if tls {
                    serve_upgrade(server.accept(socket).await.unwrap(), path.into()).await;
                } else {
                    serve_upgrade(socket, path.into()).await;
                }
            });
            let ws = connect_endpoint("127.0.0.1", port, "localhost", path,
                Duration::from_secs(3), None, route.secure().then(|| client.clone())).await.unwrap();
            assert_eq!(ws.secure, tls);
            ws.send(b"ping").await.unwrap();
            assert_eq!(ws.recv_with_timeout(Duration::from_secs(3)).await.unwrap(), b"pong");
            server_task.await.unwrap();
        }
    }
    assert_eq!(WsRoute::Telegram.port(), 443);
    assert!(WsRoute::Telegram.secure());
}

#[tokio::test]
async fn ws_redirect_has_a_reason_and_wss_rejects_unknown_ca() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        stream.write_all(b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://localhost/apiws\r\n\r\n").await.unwrap();
    });
    let result = connect_endpoint("127.0.0.1", port, "localhost", "/apiws",
        Duration::from_secs(3), None, None).await;
    assert!(matches!(result, Err(error) if error.compact().contains("redirects to HTTPS")));
    server_task.await.unwrap();

    let (server, _) = test_tls();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        assert!(server.accept(socket).await.is_err());
        assert!(tokio::time::timeout(Duration::from_millis(100), listener.accept()).await.is_err());
    });
    let result = connect_endpoint("127.0.0.1", port, "localhost", "/apiws",
        Duration::from_secs(3), None, Some(WsRoute::Cloudflare { tls: true }.tls_config())).await;
    assert!(matches!(result, Err(WsError::Io(error)) if error.to_string().contains("UnknownIssuer")));
    server_task.await.unwrap();
}
