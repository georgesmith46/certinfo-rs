use x509_parser::prelude::*;

pub struct Cert {
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

pub fn parse_der(cert_der: Vec<u8>) -> Result<Cert, &'static str> {
    let res = X509Certificate::from_der(&cert_der);

    match res {
        Ok((_, certificate)) => Ok(Cert {
            sans: get_sans(&certificate),
            issuer: get_issuer(&certificate),
            issue_date: get_issue_date(&certificate),
            expiry_date: get_expiry_date(&certificate),
        }),
        _ => Err("Unable to parse certificate"),
    }
}
