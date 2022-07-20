use hex_literal::hex;
use std::io::prelude::*;
use std::{
    io::{self, BufReader, BufWriter},
    net::TcpStream,
};

struct BufTcpStream {
    input: BufReader<TcpStream>,
    output: BufWriter<TcpStream>,
}

impl BufTcpStream {
    fn new(stream: TcpStream) -> io::Result<Self> {
        let input = BufReader::new(stream.try_clone()?);
        let output = BufWriter::new(stream);

        Ok(Self { input, output })
    }
}

const HELLO_1: [u8; 71] = hex!("03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 20 cc a8 cc a9 c0 2f c0 30 c0 2b c0 2c c0 13 c0 09 c0 14 c0 0a 00 9c 00 9d 00 2f 00 35 c0 12 00 0a 01 00");
const HELLO_2: [u8; 60] = hex!("00 05 00 05 01 00 00 00 00 00 0a 00 0a 00 08 00 1d 00 17 00 18 00 19 00 0b 00 02 01 00 00 0d 00 12 00 10 04 01 04 03 05 01 05 03 06 01 06 03 02 01 02 03 ff 01 00 01 00 00 12 00 00");

fn send_hello(stream: &mut BufWriter<TcpStream>, host: String) -> std::io::Result<()> {
    let server_name = host.as_bytes();
    let server_name_len = server_name.len() as u8;
    let server_name_meta: [u8; 9] = [
        0,
        0,
        0,
        server_name_len + 5,
        0,
        server_name_len + 3,
        0,
        0,
        server_name_len,
    ];
    let extensions_len = (server_name_meta.len() + server_name.len() + HELLO_2.len()) as u16;
    let extensions_meta: [u8; 2] = [(extensions_len >> 8) as u8, extensions_len as u8];
    let full_len = (HELLO_1.len()
        + extensions_meta.len()
        + server_name_meta.len()
        + server_name.len()
        + HELLO_2.len()) as u16;
    let handshake_header: [u8; 4] = [1, 0, (full_len >> 8) as u8, full_len as u8];
    let record_len = full_len + 4;
    let record_header: [u8; 5] = [22, 3, 1, (record_len >> 8) as u8, record_len as u8];

    stream.write_all(&record_header)?;
    stream.write_all(&handshake_header)?;
    stream.write_all(&HELLO_1)?;
    stream.write_all(&extensions_meta)?;
    stream.write_all(&server_name_meta)?;
    stream.write_all(server_name)?;
    stream.write_all(&HELLO_2)?;

    stream.flush()?;

    Ok(())
}

fn get_next_message(stream: &mut BufReader<TcpStream>) -> std::io::Result<Vec<u8>> {
    let mut head = [0u8; 5];
    stream.read_exact(&mut head)?;
    let first = head[3] as usize;
    let second = head[4] as usize;
    let mut output = vec![0u8; (first << 8) | second];
    stream.read_exact(&mut output)?;

    Ok(output)
}

fn connect(host: &str) -> std::io::Result<BufTcpStream> {
    match std::env::var("HTTP_PROXY") {
        Ok(proxy) => {
            let connect_host = match proxy.split_once("//") {
                Some((_, h)) => h,
                _ => &proxy,
            };
            let mut stream = BufTcpStream::new(TcpStream::connect(connect_host)?)?;
            stream.output.write_all(
                format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes(),
            )?;
            stream.output.flush()?;
            let mut response = String::new();
            stream.input.read_line(&mut response)?;
            stream.input.read_line(&mut response)?;

            Ok(stream)
        }
        _ => Ok(BufTcpStream::new(TcpStream::connect(format!(
            "{host}:443"
        ))?)?),
    }
}

pub fn get_cert(host: String) -> std::io::Result<Vec<u8>> {
    let mut stream = connect(&host)?;
    send_hello(&mut stream.output, host)?;
    get_next_message(&mut stream.input)?;
    let mut cert = get_next_message(&mut stream.input)?;
    cert.drain(0..10);

    Ok(cert)
}
