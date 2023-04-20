use anyhow::Result;
use clap::Parser;
use colored::*;

mod certificate;
mod connection;

/// Prints the TLS certificate information for a TCP connection
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Domain name (e.g. google.com)
    #[arg(value_parser)]
    domain: String,

    /// Port
    #[arg(short, long, default_value_t = 443)]
    port: u16,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let certificate_der = connection::get_certificate_der(args.domain, args.port)?;
    let certificate = certificate::parse_der(certificate_der)?;

    println!("{} {}", "Issuer:".bold().cyan(), certificate.issuer);
    println!(
        "{} {}",
        "SANS:".bold().cyan(),
        certificate.sans.unwrap_or_else(|| String::from("missing"))
    );
    println!(
        "{} {}",
        "Issued:".bold().cyan(),
        certificate
            .issue_date
            .unwrap_or_else(|| String::from("missing"))
    );
    println!(
        "{} {}",
        "Expires:".bold().cyan(),
        certificate
            .expiry_date
            .unwrap_or_else(|| String::from("missing"))
    );

    Ok(())
}
