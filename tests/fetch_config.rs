use std::{io::BufReader, sync::Arc};

use rustls::{Certificate, PrivateKey, ServerConfig};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};
use tokio_rustls::TlsAcceptor;

const JWT: &str = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.";
const USER_AGENT: &str = "openid-federation-test/1.0";

struct CustomConfig;

impl openid_federation::FetchConfig for CustomConfig {
    const VERIFY_TLS: bool = false;

    fn user_agent() -> Option<String> {
        Some(USER_AGENT.to_owned())
    }
}

fn assert_user_agent(request: &str) {
    assert!(
        request
            .lines()
            .any(|line| { line.eq_ignore_ascii_case(&format!("user-agent: {USER_AGENT}")) }),
        "configured User-Agent missing from request: {request}"
    );
}

async fn spawn_https_server() -> (String, oneshot::Receiver<String>) {
    let certificates = rustls_pemfile::certs(&mut BufReader::new(
        include_bytes!("fixtures/localhost-cert.pem").as_slice(),
    ))
    .unwrap()
    .into_iter()
    .map(Certificate)
    .collect();
    let private_key = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(
        include_bytes!("fixtures/localhost-key.pem").as_slice(),
    ))
    .unwrap()
    .into_iter()
    .next()
    .map(PrivateKey)
    .unwrap();
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let url = format!(
        "https://localhost:{}/",
        listener.local_addr().unwrap().port()
    );
    let (sender, receiver) = oneshot::channel();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = acceptor.accept(stream).await else {
                // The verified client rejects this self-signed certificate.
                continue;
            };
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|part| part == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{JWT}",
                JWT.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            let _ = sender.send(String::from_utf8_lossy(&request).into_owned());
            break;
        }
    });
    (url, receiver)
}

#[tokio::test]
async fn async_fetch_respects_tls_verification() {
    let (url, _request) = spawn_https_server().await;
    assert!(
        openid_federation::fetch_jwt_async::<serde_json::Value, openid_federation::DefaultConfig>(
            &url
        )
        .await
        .is_err()
    );
    let jwt = openid_federation::fetch_jwt_async::<
        serde_json::Value,
        openid_federation::NoVerifyConfig,
    >(&url)
    .await
    .expect("NoVerifyConfig should accept a self-signed certificate");
    assert_eq!(jwt.payload_unverified().insecure()["sub"], "test");
}

#[tokio::test]
async fn blocking_fetch_respects_tls_verification() {
    let (url, _request) = spawn_https_server().await;
    let verified_url = url.clone();
    assert!(
        tokio::task::spawn_blocking(move || {
            openid_federation::fetch_jwt::<serde_json::Value, openid_federation::DefaultConfig>(
                &verified_url,
            )
        })
        .await
        .unwrap()
        .is_err()
    );
    let jwt = tokio::task::spawn_blocking(move || {
        openid_federation::fetch_jwt::<serde_json::Value, openid_federation::NoVerifyConfig>(&url)
    })
    .await
    .unwrap()
    .expect("NoVerifyConfig should accept a self-signed certificate");
    assert_eq!(jwt.payload_unverified().insecure()["sub"], "test");
}

#[tokio::test]
async fn async_fetch_sends_configured_user_agent() {
    let (url, request) = spawn_https_server().await;
    openid_federation::fetch_jwt_async::<serde_json::Value, CustomConfig>(&url)
        .await
        .unwrap();
    assert_user_agent(&request.await.unwrap());
}

#[tokio::test]
async fn blocking_fetch_sends_configured_user_agent() {
    let (url, request) = spawn_https_server().await;
    tokio::task::spawn_blocking(move || {
        openid_federation::fetch_jwt::<serde_json::Value, CustomConfig>(&url)
    })
    .await
    .unwrap()
    .unwrap();
    assert_user_agent(&request.await.unwrap());
}
