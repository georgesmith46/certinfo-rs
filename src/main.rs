use clap::Parser;
use colored::*;

mod cert;
mod tcp;

/// Prints the certificate information for a HTTPS connection
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Host name (e.g. google.com)
    #[clap(short, long, value_parser)]
    host: String,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let cert_der = tcp::get_cert(args.host)?;
    let certificate = cert::parse_der(cert_der).unwrap();

    println!("{} {}", "Issuer:".bold().cyan(), certificate.issuer);
    println!(
        "{} {}",
        "SANS:".bold().cyan(),
        certificate.sans.unwrap_or(String::from("missing"))
    );
    println!(
        "{} {}",
        "Issued:".bold().cyan(),
        certificate.issue_date.unwrap_or(String::from("missing"))
    );
    println!(
        "{} {}",
        "Expires:".bold().cyan(),
        certificate.expiry_date.unwrap_or(String::from("missing"))
    );

    Ok(())
}
