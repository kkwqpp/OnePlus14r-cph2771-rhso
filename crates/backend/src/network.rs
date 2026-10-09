//! One verified-TLS GET with numeric-address dial, bounded DNS, framing and time.
//! No proxy, redirect, retry, upload, cookies or address override is exposed.
use crate::{
    error::{Error, Result},
    fs,
};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
pub struct Response {
    pub headers: BTreeMap<String, Vec<String>>,
    pub body: zeroize::Zeroizing<Vec<u8>>,
}
// Enforce the absolute deadline for every low-level operation, including TLS
// handshake reads/writes. A per-read timeout alone permits a dribbling peer.
struct DeadlineSocket {
    socket: TcpStream,
    deadline: Instant,
}
impl DeadlineSocket {
    fn remaining(&self) -> std::io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request deadline",
            ))
        } else {
            Ok(left)
        }
    }
}
impl Read for DeadlineSocket {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(b)
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.remaining()?;
        self.socket.flush()
    }
}
pub fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let n = u32::from(v);
            if v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_multicast()
                || v.is_broadcast()
            {
                return false;
            }
            for (base, bits) in [
                (0, 8),
                (0x64400000, 10),
                (0xc0000000, 24),
                (0xc0000200, 24),
                (0xc0586300, 24),
                (0xc6120000, 15),
                (0xc6336400, 24),
                (0xcb007100, 24),
                (0xe0000000, 4),
                (0xf0000000, 4),
            ] {
                if n >> (32 - bits) == base >> (32 - bits) {
                    return false;
                }
            }
            true
        }
        IpAddr::V6(v) => {
            if let Some(v) = v.to_ipv4_mapped() {
                return public_address(IpAddr::V4(v));
            }
            let n = u128::from(v);
            if n >> 125 != 1 {
                return false;
            }
            for (base, bits) in [
                (0x20010000000000000000000000000000u128, 23),
                (0x20010db8000000000000000000000000, 32),
                (0x20020000000000000000000000000000, 16),
                (0x3fff0000000000000000000000000000, 20),
            ] {
                if n >> (128 - bits) == base >> (128 - bits) {
                    return false;
                }
            }
            true
        }
    }
}
fn trust_error() -> Error {
    Error::new(
        "E_API_TLS",
        "System TLS trust-store ownership, path or bounded contents could not be verified.",
    )
}
/// Fixed Android aliases only; a versioned Conscrypt APEX target is accepted.
#[doc(hidden)]
pub fn approved_android_trust_path(alias: &Path, resolved: &Path) -> bool {
    let Some(path) = resolved.to_str() else {
        return false;
    };
    if alias == Path::new("/system/etc/security/cacerts") {
        return path == "/system/etc/security/cacerts";
    }
    if alias != Path::new("/apex/com.android.conscrypt/cacerts") {
        return false;
    }
    if path == "/apex/com.android.conscrypt/cacerts" {
        return true;
    }
    path.strip_prefix("/apex/com.android.conscrypt@")
        .and_then(|v| v.strip_suffix("/cacerts"))
        .is_some_and(|v| !v.is_empty() && v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit()))
}
/// Fixture seam also used by Android production code. It always starts empty;
/// no Mozilla roots or user-added CA directories enter this pool.
#[doc(hidden)]
pub struct SystemTrustLoad {
    pub roots: rustls::RootCertStore,
    pub usable_certificates: usize,
    pub skipped_files: usize,
    pub skipped_certificates: usize,
}
#[doc(hidden)]
pub fn load_system_root_directories(paths: &[PathBuf], owner: i32) -> Result<SystemTrustLoad> {
    if paths.len() > 2 {
        return Err(trust_error());
    }
    let mut out = SystemTrustLoad {
        roots: rustls::RootCertStore::empty(),
        usable_certificates: 0,
        skipped_files: 0,
        skipped_certificates: 0,
    };
    let mut total = 0;
    for path in paths {
        if !path.is_absolute() {
            return Err(trust_error());
        }
        fs::no_links(path).map_err(|_| trust_error())?;
        if !std::fs::metadata(path).is_ok_and(|m| m.is_dir()) {
            return Err(trust_error());
        }
        let m = fs::metadata(path).map_err(|_| trust_error())?;
        if m.uid != owner || m.mode & 0o22 != 0 {
            return Err(trust_error());
        }
        // Iterate with a count before collecting; an enormous store cannot
        // allocate an unbounded entry list or evade the combined bound.
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(path).map_err(|_| trust_error())? {
            total += 1;
            if total > 1000 {
                return Err(trust_error());
            }
            entries.push(entry.map_err(|_| trust_error())?);
        }
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let p = entry.path();
            let acceptable = entry
                .file_name()
                .to_str()
                .is_some_and(|n| !n.is_empty() && n.len() <= 128)
                && fs::no_links(&p).is_ok()
                && std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_file())
                && fs::metadata(&p).is_ok_and(|m| m.uid == owner && m.mode & 0o22 == 0);
            if !acceptable {
                out.skipped_files += 1;
                continue;
            }
            let Ok(bytes) = fs::bounded(&p, 16 << 10) else {
                out.skipped_files += 1;
                continue;
            };
            let before = out.usable_certificates;
            let mut pem = bytes.as_slice();
            for (index, cert) in rustls_pemfile::certs(&mut pem).enumerate() {
                if index >= 32 {
                    out.skipped_certificates += 1;
                    break;
                }
                match cert {
                    Ok(cert) => {
                        if out.roots.add(cert).is_ok() {
                            out.usable_certificates += 1;
                        } else {
                            out.skipped_certificates += 1;
                        }
                    }
                    Err(_) => out.skipped_certificates += 1,
                }
            }
            if out.usable_certificates == before {
                out.skipped_files += 1;
            }
        }
    }
    if out.roots.is_empty() {
        return Err(Error::new(
            "E_API_TLS",
            "No usable Android system TLS roots remain; verification was not bypassed.",
        ));
    }
    Ok(out)
}
fn roots() -> Result<rustls::RootCertStore> {
    #[cfg(target_os = "android")]
    {
        let mut paths = Vec::new();
        for alias in [
            Path::new("/apex/com.android.conscrypt/cacerts"),
            Path::new("/system/etc/security/cacerts"),
        ] {
            match std::fs::canonicalize(alias) {
                Ok(path) => {
                    if !approved_android_trust_path(alias, &path) {
                        return Err(trust_error());
                    }
                    paths.push(path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(trust_error()),
            }
        }
        Ok(load_system_root_directories(&paths, 0)?.roots)
    }
    #[cfg(not(target_os = "android"))]
    {
        let mut pool = rustls::RootCertStore::empty();
        pool.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Ok(pool)
    }
}
fn destination_host(url: &url::Url) -> Result<(String, String, Option<IpAddr>)> {
    let serialized = url
        .host_str()
        .ok_or_else(|| Error::new("E_API_CONFIG", "The configured HTTPS host is invalid."))?
        .to_owned();
    let (host, literal) = match url.host() {
        Some(url::Host::Domain(v)) => (v.to_owned(), None),
        Some(url::Host::Ipv4(v)) => (v.to_string(), Some(IpAddr::V4(v))),
        Some(url::Host::Ipv6(v)) => (v.to_string(), Some(IpAddr::V6(v))),
        None => {
            return Err(Error::new(
                "E_API_CONFIG",
                "The configured HTTPS host is invalid.",
            ));
        }
    };
    Ok((host, serialized, literal))
}
pub fn get(
    url: &url::Url,
    headers: &[(String, String)],
    max: usize,
    guarded: bool,
) -> Result<Response> {
    let deadline = Instant::now() + Duration::from_secs(15);
    // url::host_str serializes an IPv6 literal with brackets. DNS resolution and
    // TLS IP verification take the numeric address; HTTP Host keeps the brackets.
    let (host, host_header_name, literal) = destination_host(url)?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Error::new("E_API_CONFIG", "The configured HTTPS port is invalid."))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::new(
            "E_API_CONFIG",
            "Only verified HTTPS GET sources are supported.",
        ));
    }
    let addresses = if let Some(ip) = literal {
        vec![SocketAddr::new(ip, port)]
    } else {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let h = host.clone();
        std::thread::spawn(move || {
            let r = (h.as_str(), port)
                .to_socket_addrs()
                .map(|v| v.take(17).collect::<Vec<_>>());
            let _ = tx.send(r);
        });
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now())).map_err(|_|Error::new("E_API_DNS","Configured source DNS resolution failed or timed out; no credentials are displayed."))?.map_err(|_|Error::new("E_API_DNS","Configured source DNS resolution failed; no credentials are displayed."))?
    };
    if addresses.is_empty()
        || addresses.len() > 16
        || guarded && addresses.iter().any(|a| !public_address(a.ip()))
    {
        return Err(Error::new(
            "E_API_SSRF",
            "Source DNS/address policy rejected the destination; no private-network request was made.",
        ));
    }
    let address: SocketAddr = addresses[0];
    let socket = TcpStream::connect_timeout(
        &address,
        deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(8)),
    )
    .map_err(|_| {
        Error::new(
            "E_API_HTTP",
            "Configured source connection failed; no retry was made.",
        )
    })?;
    socket.set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
    socket.set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| Error::new("E_API_TLS", "Verified HTTPS transport is unavailable."))?
        .with_root_certificates(roots()?)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host)
        .map_err(|_| Error::new("E_API_CONFIG", "The configured HTTPS host is invalid."))?;
    let conn = rustls::ClientConnection::new(Arc::new(cfg), name)
        .map_err(|_| Error::new("E_API_TLS", "Verified HTTPS transport is unavailable."))?;
    let mut stream = rustls::StreamOwned::new(conn, DeadlineSocket { socket, deadline });
    let mut path = url.path().to_owned();
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
    }
    let host_header = if port == 443 {
        host_header_name
    } else {
        format!("{host_header_name}:{port}")
    };
    let mut request = zeroize::Zeroizing::new(format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nAccept-Encoding: identity\r\n"
    ));
    for (k, v) in headers {
        if k.contains(['\r', '\n', ':']) || v.contains(['\r', '\n']) {
            return Err(Error::new(
                "E_API_CONFIG",
                "Source request headers are invalid.",
            ));
        }
        request.push_str(k);
        request.push_str(": ");
        request.push_str(v);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).map_err(tls_io)?;
    stream.flush().map_err(tls_io)?;
    read_response(&mut stream, max, guarded)
}
fn tls_io(e: std::io::Error) -> Error {
    if e.get_ref()
        .is_some_and(|e| e.downcast_ref::<rustls::Error>().is_some())
    {
        Error::new(
            "E_API_TLS",
            "Configured source TLS verification failed; verification was not bypassed.",
        )
    } else {
        Error::new(
            "E_API_HTTP",
            "Configured source request failed or timed out; no retry was made.",
        )
    }
}
const HEADER_MAX: usize = 32768;
const CHUNK_LINE_MAX: usize = 4096;
type Headers = BTreeMap<String, Vec<String>>;
enum Framing {
    Length(usize),
    Chunked,
    Eof,
}

// This byte-wise header reader intentionally does not read body bytes before
// header policy is accepted. rustls buffers decrypted records internally.
fn read_head<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0];
    loop {
        if head.len() == HEADER_MAX {
            return Err(format_error());
        }
        reader.read_exact(&mut byte).map_err(tls_io)?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            head.truncate(head.len() - 4);
            return Ok(head);
        }
    }
}
fn header_token(v: &str) -> bool {
    !v.is_empty()
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}
fn parse_head(head: &[u8], max: usize) -> Result<(Headers, Framing)> {
    let head = std::str::from_utf8(head).map_err(|_| format_error())?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    if status_line.bytes().any(|b| b < 32 || b == 127) {
        return Err(format_error());
    }
    let status = status_line.split_whitespace().collect::<Vec<_>>();
    if status.len() < 2 || !matches!(status[0], "HTTP/1.0" | "HTTP/1.1") || status[1] != "200" {
        return Err(Error::new(
            "E_API_HTTP",
            "Configured source returned a non-success response; no redirect or retry was used.",
        ));
    }
    let mut headers = BTreeMap::<String, Vec<String>>::new();
    for l in lines {
        let (k, v) = l.split_once(':').ok_or_else(format_error)?;
        if !header_token(k)
            || l.starts_with([' ', '\t'])
            || v.bytes().any(|b| b < 32 && b != b'\t' || b == 127)
        {
            return Err(format_error());
        }
        headers
            .entry(k.to_ascii_lowercase())
            .or_default()
            .push(v.trim().into());
    }
    if headers.get("content-length").is_some_and(|v| v.len() != 1)
        || headers
            .get("transfer-encoding")
            .is_some_and(|v| v.len() != 1)
        || headers.contains_key("content-length") && headers.contains_key("transfer-encoding")
    {
        return Err(format_error());
    }
    let framing = if let Some(v) = headers.get("transfer-encoding") {
        if !v[0].eq_ignore_ascii_case("chunked") {
            return Err(format_error());
        }
        Framing::Chunked
    } else if let Some(v) = headers.get("content-length") {
        if v[0].is_empty() || !v[0].bytes().all(|b| b.is_ascii_digit()) {
            return Err(format_error());
        }
        let n = v[0].parse::<usize>().map_err(|_| format_error())?;
        if n == 0 || n > max {
            return Err(limit_error());
        }
        Framing::Length(n)
    } else {
        Framing::Eof
    };
    Ok((headers, framing))
}
fn response_policy(headers: &Headers, xml_source: bool) -> Result<()> {
    if xml_source {
        if !crate::api::xml_headers(headers) {
            return Err(Error::new(
                "E_API_FORMAT",
                "Configured source must return uncompressed raw XML with a supported content type.",
            ));
        }
    } else {
        if headers
            .get("cache-control")
            .into_iter()
            .flatten()
            .flat_map(|s| s.split(','))
            .any(|v| {
                v.trim()
                    .split('=')
                    .next()
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("no-store"))
            })
        {
            return Err(Error::new(
                "E_PUBLIC_FEED",
                "Public response forbids caching. Existing evidence was preserved without storing the new response.",
            ));
        }
        if !crate::media_type::json_headers(headers) {
            return Err(Error::new(
                "E_PUBLIC_FEED",
                "Google public-feed response was not the verified uncompressed JSON format.",
            ));
        }
    }
    Ok(())
}
fn read_chunk_line<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0];
    loop {
        if line.len() == CHUNK_LINE_MAX + 2 {
            return Err(format_error());
        }
        reader.read_exact(&mut byte).map_err(tls_io)?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
    }
}
fn read_chunks<R: Read>(reader: &mut R, max: usize) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut out = zeroize::Zeroizing::new(Vec::new());
    for _ in 0..4096 {
        let line = read_chunk_line(reader)?;
        let line = std::str::from_utf8(&line).map_err(|_| format_error())?;
        if line.bytes().any(|b| b < 32 || b == 127) {
            return Err(format_error());
        }
        let raw_size = line.split(';').next().unwrap_or("");
        if raw_size.is_empty() || !raw_size.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format_error());
        }
        let n = usize::from_str_radix(raw_size, 16).map_err(|_| format_error())?;
        if n == 0 {
            // Trailer fields are unsupported; the empty terminator is required.
            let mut end = [0; 2];
            reader.read_exact(&mut end).map_err(tls_io)?;
            if end != *b"\r\n" {
                return Err(format_error());
            }
            return Ok(out);
        }
        if n > max.saturating_sub(out.len()) {
            return Err(limit_error());
        }
        let old = out.len();
        out.resize(old + n, 0);
        reader.read_exact(&mut out[old..]).map_err(tls_io)?;
        let mut end = [0; 2];
        reader.read_exact(&mut end).map_err(tls_io)?;
        if end != *b"\r\n" {
            return Err(format_error());
        }
    }
    Err(format_error())
}
fn read_body<R: Read>(
    reader: &mut R,
    framing: Framing,
    max: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let out = match framing {
        Framing::Length(n) => {
            let mut b = zeroize::Zeroizing::new(vec![0; n]);
            reader.read_exact(&mut b).map_err(tls_io)?;
            b
        }
        Framing::Chunked => read_chunks(reader, max)?,
        // A response with no framing needs a clean EOF. A TLS peer which omits
        // close_notify cannot provide reliable truncation detection in this case.
        Framing::Eof => {
            let mut b = zeroize::Zeroizing::new(Vec::new());
            let mut buf = zeroize::Zeroizing::new([0; 8192]);
            loop {
                let limit = buf.len().min(max.saturating_sub(b.len()).saturating_add(1));
                let n = reader.read(&mut buf[..limit]).map_err(tls_io)?;
                if n == 0 {
                    break;
                }
                b.extend_from_slice(&buf[..n]);
                if b.len() > max {
                    return Err(limit_error());
                }
            }
            b
        }
    };
    if out.is_empty() || out.len() > max {
        return Err(limit_error());
    }
    Ok(out)
}
/// Pure bounded response reader used by the verified transport. This accepts no
/// destination or connection override and sends no request. Framed responses
/// finish at their declared end; unframed responses require a clean bounded EOF.
pub fn read_response<R: Read>(reader: &mut R, max: usize, xml_source: bool) -> Result<Response> {
    let head = read_head(reader)?;
    let (headers, framing) = parse_head(&head, max)?;
    response_policy(&headers, xml_source)?;
    let body = read_body(reader, framing, max)?;
    Ok(Response { headers, body })
}
pub fn parse_response(raw: &[u8], max: usize) -> Result<Response> {
    let mut reader = std::io::Cursor::new(raw);
    let head = read_head(&mut reader)?;
    let (headers, framing) = parse_head(&head, max)?;
    let body = read_body(&mut reader, framing, max)?;
    if reader.position() != raw.len() as u64 {
        return Err(format_error());
    }
    Ok(Response { headers, body })
}
fn limit_error() -> Error {
    Error::new(
        "E_API_LIMIT",
        "Source response is empty or exceeds its private byte bound.",
    )
}
fn format_error() -> Error {
    Error::new(
        "E_API_FORMAT",
        "Configured source response has invalid or ambiguous HTTP framing.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_destination_names_are_numeric_for_dial_and_tls() {
        for (text, host, serialized, numeric) in [
            (
                "https://[2606:4700:4700::1111]:8443/x",
                "2606:4700:4700::1111",
                "[2606:4700:4700::1111]",
                true,
            ),
            ("https://1.1.1.1/x", "1.1.1.1", "1.1.1.1", true),
            (
                "https://example.invalid/x",
                "example.invalid",
                "example.invalid",
                false,
            ),
        ] {
            let (h, s, ip) = destination_host(&url::Url::parse(text).unwrap()).unwrap();
            assert_eq!(h, host);
            assert_eq!(s, serialized);
            assert_eq!(ip.is_some(), numeric);
            let name = rustls::pki_types::ServerName::try_from(h).unwrap();
            assert_eq!(
                matches!(name, rustls::pki_types::ServerName::IpAddress(_)),
                numeric
            );
        }
    }
    #[test]
    fn deadline_socket_stops_dribbling_low_level_reads() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            for _ in 0..30 {
                if peer.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let socket = TcpStream::connect(address).unwrap();
        let start = Instant::now();
        let mut stream = DeadlineSocket {
            socket,
            deadline: start + Duration::from_millis(60),
        };
        let mut count = 0;
        let mut b = [0];
        loop {
            match stream.read(&mut b) {
                Ok(1) => count += 1,
                Err(e) => {
                    assert!(matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ));
                    break;
                }
                v => panic!("unexpected read {v:?}"),
            }
        }
        assert!(count > 0 && count < 30);
        assert!(start.elapsed() < Duration::from_millis(500));
        // Writes and flushes also reject an elapsed deadline before socket I/O.
        assert_eq!(
            stream.write(b"private").unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            stream.flush().unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        drop(stream);
        writer.join().unwrap();
    }
}
