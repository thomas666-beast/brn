use std::env;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use brn::file_download::download_to;
use brn::{ConnectionTimeouts, PendingClient};

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn main() -> io::Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() != 5 {
        return Err(invalid(
            "usage: file_download <server-address> <server-name> \
            <ca-cert.der> <32-hex-file-id> <local-output>",
        ));
    }
    let address: SocketAddr = args[0]
        .to_str()
        .ok_or_else(|| invalid("address must be UTF-8"))?
        .parse()
        .map_err(|error| invalid(format!("invalid address: {error}")))?;
    let server_name = args[1]
        .to_str()
        .ok_or_else(|| invalid("server name must be UTF-8"))?;
    let ca = fs::read(PathBuf::from(&args[2]))?;
    let id_text = args[3]
        .to_str()
        .ok_or_else(|| invalid("ID must be UTF-8"))?;
    if id_text.len() != 32 || !id_text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("ID must contain exactly 32 hexadecimal characters"));
    }
    let mut id = [0_u8; 16];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&id_text[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid("invalid file ID"))?;
    }
    let destination = PathBuf::from(&args[4]);
    let mut staging_name = destination.as_os_str().to_os_string();
    staging_name.push(".part");
    let staging = PathBuf::from(staging_name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&staging)?;
    let result = download_to(
        || {
            let timeouts = ConnectionTimeouts::new(
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_secs(10),
            )?;
            PendingClient::connect(
                address,
                server_name,
                &[ca.as_slice()],
                Duration::from_secs(5),
                timeouts,
            )?
            .authenticate(b"brn-file-example-only", Duration::from_secs(10))?
            .establish_keys(Duration::from_secs(10))
        },
        id,
        &mut output,
        10_000_000_000,
        Duration::from_secs(10),
    );
    drop(output);
    let info = match result {
        Ok(info) => info,
        Err(error) => {
            eprintln!(
                "Download failed; unverified partial output retained at {}",
                staging.display()
            );
            return Err(error);
        }
    };
    fs::hard_link(&staging, &destination)?;
    if let Err(error) = fs::remove_file(&staging) {
        eprintln!("Downloaded successfully, but staging cleanup failed: {error}");
    }
    println!(
        "Verified {} bytes; original filename: {}",
        info.size, info.original_name
    );
    println!("Saved to {}", destination.display());
    Ok(())
}
