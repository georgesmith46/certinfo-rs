use anyhow::Result;
use x509_parser::prelude::*;

pub struct Certificate {
    pub sans: Option<String>,
    pub issuer: String,
    pub issue_date: Option<String>,
    pub expiry_date: Option<String>,
}

fn get_sans(cert: &X509Certificate) -> Option<String> {
    cert.subject_alternative_name().ok().and_then(|res| {
        res.map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|x| match x {
                    GeneralName::DNSName(dns) => Some(dns.to_string()),
                    _ => None,
                })
                .collect::<Vec<String>>()
                .join(" ")
        })
    })
}

fn get_issuer(cert: &X509Certificate) -> String {
    cert.issuer().to_string()
}

fn get_issue_date(cert: &X509Certificate) -> Option<String> {
    cert.validity().not_before.to_rfc2822().ok()
}

fn get_expiry_date(cert: &X509Certificate) -> Option<String> {
    cert.validity().not_after.to_rfc2822().ok()
}

pub fn parse_der(certificate_der: Vec<u8>) -> Result<Certificate> {
    let (_, certificate) = X509Certificate::from_der(&certificate_der)?;

    Ok(Certificate {
        sans: get_sans(&certificate),
        issuer: get_issuer(&certificate),
        issue_date: get_issue_date(&certificate),
        expiry_date: get_expiry_date(&certificate),
    })
}
