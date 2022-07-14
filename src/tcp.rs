use hex_literal::hex;
use std::io::prelude::*;
use std::net::TcpStream;

const HELLO_1: [u8; 71] = hex!("03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 20 cc a8 cc a9 c0 2f c0 30 c0 2b c0 2c c0 13 c0 09 c0 14 c0 0a 00 9c 00 9d 00 2f 00 35 c0 12 00 0a 01 00");
const HELLO_2: [u8; 60] = hex!("00 05 00 05 01 00 00 00 00 00 0a 00 0a 00 08 00 1d 00 17 00 18 00 19 00 0b 00 02 01 00 00 0d 00 12 00 10 04 01 04 03 05 01 05 03 06 01 06 03 02 01 02 03 ff 01 00 01 00 00 12 00 00");

fn send_hello(stream: &mut TcpStream, host: String) -> std::io::Result<()> {
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

    stream.write(&record_header)?;
    stream.write(&handshake_header)?;
    stream.write(&HELLO_1)?;
    stream.write(&extensions_meta)?;
    stream.write(&server_name_meta)?;
    stream.write(&server_name)?;
    stream.write(&HELLO_2)?;

    Ok(())
}

fn get_next_message(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut head = [0u8; 5];
    stream.read_exact(&mut head)?;
    let first = head[3] as usize;
    let second = head[4] as usize;
    let mut output = vec![0u8; (first << 8) | second];
    stream.read_exact(&mut output)?;

    Ok(output)
}

pub fn get_cert(host: String) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(format!("{host}:443"))?;
    send_hello(&mut stream, host)?;
    get_next_message(&mut stream)?;
    let mut cert = get_next_message(&mut stream)?;
    cert.drain(0..10);

    Ok(cert)
}
