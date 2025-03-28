use quinn::{Endpoint, ServerConfig};
use std::{
    ascii,
    error::Error,
    fs::{self, File},
    io::{ BufReader},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{self, Path, PathBuf},
    str,
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use tracing::{error, info, info_span,instrument};
use tracing_futures::Instrument as _;
mod common;
mod json;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cert = "cert.pem";
    let file = File::open(Path::new(cert)).expect(format!("cannot open {}", cert).as_str());
    let mut br = BufReader::new(file);
    let cetrs = rustls_pemfile::certs(&mut br).unwrap();

    let key = "key.pem";
    let filek = File::open(Path::new(key)).expect(format!("cannot open {}", key).as_str());
    let mut brk = BufReader::new(filek);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut brk).unwrap();

    let certificate = rustls::Certificate(cetrs[0].clone());
    let private_key = rustls::PrivateKey(keys[0].clone());

    let cert_chain = vec![certificate];

    let server_config = ServerConfig::with_single_cert(cert_chain, private_key)?;

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    let mut buf = [0u8; 1024];


    let root =   Arc::<Path>::from(PathBuf::from("./"));
    while let Some(income_conn) = endpoint.accept().await {
        info!("connection incoming");
        let fut = handle_connection(root.clone(), income_conn);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                error!("connection failed: {reason}", reason = e.to_string())
            }
        });
    }
    endpoint.wait_idle().await;
    eprintln!("END");
    Ok(())
}

#[instrument]
async fn handle_connection(root: Arc<Path>, conn: quinn::Connecting) -> Result<()> {
    let connection = conn.await?;
    let span = info_span!(
        "connection",
        remote = %connection.remote_address(),
        protocol = %connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );
    async {
        info!("established");

        // Each stream initiated by the client constitutes a new request.
        loop {
            let stream = connection.accept_bi().await;
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            let fut = handle_request(root.clone(), stream);
            tokio::spawn(
                async move {
                    if let Err(e) = fut.await {
                        error!("failed: {reason}", reason = e.to_string());
                    }
                }
                .instrument(info_span!("request")),
            );
        }
    }
    .instrument(span)
    .await?;
    Ok(())
}

#[instrument]
async fn handle_request(
    root: Arc<Path>,
    (mut send, recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let req = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed reading request: {}", e))?;
    let mut escaped = String::new();
    for &x in &req[..] {
        let part = ascii::escape_default(x).collect::<Vec<_>>();
        escaped.push_str(str::from_utf8(&part).unwrap());
    }
    info!(content = %escaped);
    // Execute the request
    let resp = process_get(&root, &req).unwrap_or_else(|e| {
        error!("failed: {}", e);
        format!("failed to process request: {e}\n").into_bytes()
    });
    // Write the response
    send.write_all(&resp)
        .await
        .map_err(|e| anyhow!("failed to send response: {}", e))?;
    // Gracefully terminate the stream
    send.finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
    info!("complete");
    Ok(())
}

fn process_get(root: &Path, x: &[u8]) -> Result<Vec<u8>> {
    if x.len() < 4 || &x[0..4] != b"GET " {
        bail!("missing GET");
    }
    if x[4..].len() < 2 || &x[x.len() - 2..] != b"\r\n" {
        bail!("missing \\r\\n");
    }
    let x = &x[4..x.len() - 2];
    let end = x.iter().position(|&c| c == b' ').unwrap_or(x.len());
    let path = str::from_utf8(&x[..end]).context("path is malformed UTF-8")?;
    let path = Path::new(&path);

    let mut real_path = PathBuf::from(root);
    let mut components = path.components();
    match components.next() {
        Some(path::Component::RootDir) => {}
        _ => {
            bail!("path must be absolute");
        }
    }
    for c in components {
        match c {
            path::Component::Normal(x) => {
                real_path.push(x);
            }
            x => {
                bail!("illegal component in path: {:?}", x);
            }
        }
    }
    let data = fs::read(&real_path).context("failed reading file")?;
    Ok(data)
}
