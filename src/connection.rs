use anyhow::{anyhow, Result};
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ClientConfig, ClientConnection, RootCertStore, ServerName};
use std::{net::TcpStream, sync::Arc};

pub struct CertificateVerifier;

impl ServerCertVerifier for CertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

pub fn get_certificate_der(domain: String, port: u16) -> Result<Vec<u8>> {
    let addr = format!("{domain}:{port}");
    let server_name = ServerName::try_from(domain.as_str())?;

    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(CertificateVerifier));

    let mut session = ClientConnection::new(Arc::new(config), server_name)?;
    let mut socket = TcpStream::connect(addr)?;

    while session.peer_certificates().is_none() {
        session.write_tls(&mut socket)?;
        session.read_tls(&mut socket)?;
        session.process_new_packets()?;
    }

    let certificates = session
        .peer_certificates()
        .expect("peer certificates should be set");
    let first_certificate = certificates
        .first()
        .ok_or(anyhow!("first certificate missing"))?;
    let first_certificate = first_certificate.0.to_vec();

    Ok(first_certificate)
}
