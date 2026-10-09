use rhso::network;
use std::io::{self, Read};

// A source which fragments every read and refuses reads past the declared test
// boundary. Complete framed responses must not need TCP EOF/TLS close_notify.
struct Pieces {
    data: Vec<u8>,
    at: usize,
    piece: usize,
    eof: bool,
}
impl Pieces {
    fn never_eof(data: impl AsRef<[u8]>, piece: usize) -> Self {
        Self {
            data: data.as_ref().to_vec(),
            at: 0,
            piece,
            eof: false,
        }
    }
    fn clean_eof(data: impl AsRef<[u8]>) -> Self {
        Self {
            data: data.as_ref().to_vec(),
            at: 0,
            piece: 3,
            eof: true,
        }
    }
}
impl Read for Pieces {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if self.at == self.data.len() {
            if self.eof {
                return Ok(0);
            }
            panic!("reader touched body or waited for EOF past boundary");
        }
        let n = b.len().min(self.piece).min(self.data.len() - self.at);
        b[..n].copy_from_slice(&self.data[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}
fn xml_head(extra: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n{extra}\r\n")
}

#[test]
fn complete_length_response_finishes_without_eof_for_fragmented_reads() {
    for piece in [1, 2, 7, 8192] {
        let bytes = format!("{}<Keybox/>", xml_head("Content-Length: 9\r\n"));
        let mut r = Pieces::never_eof(&bytes, piece);
        let out = network::read_response(&mut r, 9, true).unwrap();
        assert_eq!(&*out.body, b"<Keybox/>");
        assert_eq!(r.at, bytes.len());
    }
}
#[test]
fn complete_chunked_response_finishes_without_eof_or_trailer_read() {
    for piece in [1, 3, 8192] {
        let bytes = format!(
            "{}4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
            xml_head("Transfer-Encoding: chunked\r\n")
        );
        let mut r = Pieces::never_eof(&bytes, piece);
        let out = network::read_response(&mut r, 9, true).unwrap();
        assert_eq!(&*out.body, b"Wikipedia");
        assert_eq!(r.at, bytes.len());
    }
}
#[test]
fn header_policy_rejects_before_reading_any_body() {
    for (head,xml,code) in [
        ("HTTP/1.1 302 Found\r\nLocation: https://other.invalid\r\n\r\n".into(),true,"E_API_HTTP"),
        (xml_head("Content-Length: 99\r\n"),true,"E_API_LIMIT"),
        (xml_head("Content-Length: 0\r\n"),true,"E_API_LIMIT"),
        (xml_head("Content-Length: +1\r\n"),true,"E_API_FORMAT"),
        (xml_head("Content-Length: 1\r\nContent-Length: 1\r\n"),true,"E_API_FORMAT"),
        (xml_head("Content-Length: 1\r\nTransfer-Encoding: chunked\r\n"),true,"E_API_FORMAT"),
        (xml_head("Content-Encoding: gzip\r\n"),true,"E_API_FORMAT"),
        ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n".into(),true,"E_API_FORMAT"),
        ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n".into(),false,"E_PUBLIC_FEED"),
        ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n\r\n".into(),false,"E_PUBLIC_FEED"),
        ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: max-age=600\r\nCache-Control: no-store\r\n\r\n".into(),false,"E_PUBLIC_FEED"),
        ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store=\"field\"\r\n\r\n".into(),false,"E_PUBLIC_FEED"),
    ] {
        let mut r=Pieces::never_eof(&head,8192);
        let e=network::read_response(&mut r,9,xml).err().unwrap();assert_eq!(e.code,code,"{head}");assert_eq!(r.at,head.len());
    }
}
#[test]
fn header_bound_is_enforced_before_unbounded_header_or_body_read() {
    let prefix = "HTTP/1.1 200 OK\r\nX-Long: ";
    let mut bytes = prefix.as_bytes().to_vec();
    bytes.resize(32768, b'a');
    let mut r = Pieces::never_eof(&bytes, 8192);
    assert_eq!(
        network::read_response(&mut r, 9, true).err().unwrap().code,
        "E_API_FORMAT"
    );
    assert_eq!(r.at, 32768);
}
#[test]
fn chunk_size_bound_and_syntax_reject_before_chunk_body() {
    for (line, code) in [
        ("a\r\n", "E_API_LIMIT"),
        ("+1\r\n", "E_API_FORMAT"),
        ("xyz\r\n", "E_API_FORMAT"),
        ("1;bad\u{7f}\r\n", "E_API_FORMAT"),
    ] {
        let bytes = format!("{}{line}", xml_head("Transfer-Encoding: chunked\r\n"));
        let mut r = Pieces::never_eof(&bytes, 1);
        assert_eq!(
            network::read_response(&mut r, 9, true).err().unwrap().code,
            code
        );
        assert_eq!(r.at, bytes.len());
    }
    let mut bytes = xml_head("Transfer-Encoding: chunked\r\n").into_bytes();
    bytes.resize(bytes.len() + 4098, b'1');
    let mut r = Pieces::never_eof(&bytes, 1);
    assert_eq!(
        network::read_response(&mut r, 9, true).err().unwrap().code,
        "E_API_FORMAT"
    );
    assert_eq!(r.at, bytes.len());
}
#[test]
fn valid_header_tokens_and_json_mime_are_supported_without_private_reflection() {
    let bytes=b"HTTP/1.1 200 OK\r\nContent-Type: Application/JSON; charset=utf-8\r\nX_custom: value\r\nContent-Length: 2\r\n\r\n{}";
    let mut r = Pieces::never_eof(bytes, 2);
    assert_eq!(
        &*network::read_response(&mut r, 2, false).unwrap().body,
        b"{}"
    );
    for body in [
        b"HTTP/1.1 200 OK\r\nX: private\x01secret\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nBad Name: secret\r\n\r\n",
    ] {
        let mut r = Pieces::never_eof(body, 1);
        let e = network::read_response(&mut r, 9, true).err().unwrap();
        assert_eq!(e.code, "E_API_FORMAT");
        assert!(!e.message.contains("secret"));
    }
}
#[test]
fn unframed_responses_need_clean_eof_and_cannot_exceed_body_bound() {
    let bytes = format!("{}<Keybox/>", xml_head(""));
    let mut r = Pieces::clean_eof(&bytes);
    assert_eq!(
        &*network::read_response(&mut r, 9, true).unwrap().body,
        b"<Keybox/>"
    );
    let mut r = Pieces::never_eof(&bytes, 1);
    assert_eq!(
        network::read_response(&mut r, 8, true).err().unwrap().code,
        "E_API_LIMIT"
    );
    struct Truncated(Pieces);
    impl Read for Truncated {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            if self.0.at == self.0.data.len() {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "no close_notify",
                ))
            } else {
                self.0.read(b)
            }
        }
    }
    let mut r = Truncated(Pieces::never_eof(&bytes, 1));
    assert_eq!(
        network::read_response(&mut r, 9, true).err().unwrap().code,
        "E_API_HTTP"
    );
}
#[test]
fn strict_full_buffer_parser_rejects_framed_extra_bytes_and_truncation() {
    for bytes in [
        format!("{}xextra", xml_head("Content-Length: 1\r\n")),
        format!("{}x", xml_head("Content-Length: 2\r\n")),
        format!(
            "{}1\r\nx\r\n0\r\n\r\nextra",
            xml_head("Transfer-Encoding: chunked\r\n")
        ),
        format!("{}1\r\nxXX", xml_head("Transfer-Encoding: chunked\r\n")),
    ] {
        assert!(network::parse_response(bytes.as_bytes(), 20).is_err());
    }
}
