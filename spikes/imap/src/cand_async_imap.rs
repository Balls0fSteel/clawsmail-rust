//! Candidate A: `async-imap` (tokio runtime), parsing by `imap-proto`.
//!
//! What is here is the glue `cm-imap` would need on top of async-imap: TLS connect, SASL-IR,
//! the BODYSTRUCTURE converter, and a raw command path for responses the typed helpers drop
//! (APPENDUID, COPYUID, X-GM-THRID, SELECT ... QRESYNC).

use std::fmt;
use std::sync::Arc;

use async_imap::imap_proto::{
    self, AttributeValue, BodyStructure, ContentEncoding, Response, ResponseCode, Status,
};
use async_imap::{Authenticator, Client, Session};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::mime::{self, MimePart};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Requirement 1: implicit TLS (port 993) with rustls and the platform verifier.
pub async fn connect_tls(host: &str, port: u16) -> Result<Client<TlsStream<TcpStream>>, Error> {
    let config = crate::tls::client_config()?;
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect((host, port)).await?;
    tcp.set_nodelay(true)?;
    let name = ServerName::try_from(host.to_string())?;
    let tls = connector.connect(name, tcp).await?;
    let mut client = Client::new(tls);
    // async-imap does not read the greeting itself.
    client.read_response().await?.ok_or("connection closed before greeting")?;
    Ok(client)
}

/// Plain TCP, for the fake server. Same `Client` type parameterised over the stream.
pub async fn connect_plain(host: &str, port: u16) -> Result<(Client<TcpStream>, String), Error> {
    let tcp = TcpStream::connect((host, port)).await?;
    let mut client = Client::new(tcp);
    let greeting = client.read_response().await?.ok_or("connection closed before greeting")?;
    let text = format!("{:?}", greeting.parsed());
    Ok((client, text))
}

pub fn xoauth2_payload(user: &str, token: &str) -> String {
    format!("user={user}\x01auth=Bearer {token}\x01\x01")
}

/// Answers every challenge with an empty response, which is how a client acknowledges the
/// XOAUTH2 error challenge (the server then sends the tagged NO). Records the decoded
/// challenge so the caller can show Google's/Microsoft's JSON error.
#[derive(Default)]
pub struct EmptyResponder {
    pub last_challenge: Option<String>,
}

impl Authenticator for &mut EmptyResponder {
    type Response = Vec<u8>;
    fn process(&mut self, challenge: &[u8]) -> Vec<u8> {
        self.last_challenge = Some(String::from_utf8_lossy(challenge).into_owned());
        Vec::new()
    }
}

/// Classic XOAUTH2 without an initial response: the payload is sent after the `+`.
pub struct XOAuth2 {
    pub user: String,
    pub token: String,
    sent: bool,
}

impl XOAuth2 {
    pub fn new(user: &str, token: &str) -> Self {
        Self { user: user.into(), token: token.into(), sent: false }
    }
}

impl Authenticator for &mut XOAuth2 {
    type Response = Vec<u8>;
    fn process(&mut self, _challenge: &[u8]) -> Vec<u8> {
        if self.sent {
            Vec::new() // second challenge = error JSON; acknowledge with an empty line
        } else {
            self.sent = true;
            xoauth2_payload(&self.user, &self.token).into_bytes()
        }
    }
}

/// Requirement 2: AUTHENTICATE XOAUTH2 with SASL-IR.
///
/// async-imap has no SASL-IR support, but it formats `AUTHENTICATE {auth_type}` verbatim, so
/// passing `"XOAUTH2 <base64>"` as the mechanism produces a correct one-line SASL-IR command.
/// If the server rejects the token it sends a `+ <base64 JSON>` challenge; the responder sends
/// an empty line and the tagged NO comes back as an error.
pub async fn authenticate_xoauth2_ir<T>(
    client: Client<T>,
    user: &str,
    token: &str,
    responder: &mut EmptyResponder,
) -> Result<Session<T>, (async_imap::error::Error, Client<T>)>
where
    T: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send,
{
    let ir = B64.encode(xoauth2_payload(user, token));
    client.authenticate(format!("XOAUTH2 {ir}"), responder).await
}

/// AUTHENTICATE PLAIN with SASL-IR, same trick.
pub async fn authenticate_plain_ir<T>(
    client: Client<T>,
    user: &str,
    pass: &str,
) -> Result<Session<T>, (async_imap::error::Error, Client<T>)>
where
    T: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send,
{
    let ir = B64.encode(format!("\0{user}\0{pass}"));
    let mut r = EmptyResponder::default();
    client.authenticate(format!("PLAIN {ir}"), &mut r).await
}

// ---------------------------------------------------------------------------------------------
// Raw command path
// ---------------------------------------------------------------------------------------------

/// All responses of one command: untagged ones in order, then the tagged completion.
///
/// async-imap's `ResponseData` type is `pub(crate)` (it can be received but not named), so the
/// raw frames are kept as bytes (`ResponseData::borrow_owner`) and re-parsed with imap-proto on
/// demand.
pub struct RawResult {
    pub untagged: Vec<Vec<u8>>,
    pub tagged: Vec<u8>,
}

fn parse(frame: &[u8]) -> Response<'_> {
    Response::parse(frame).expect("frame was parsed once already").1
}

impl RawResult {
    pub fn untagged(&self) -> impl Iterator<Item = Response<'_>> {
        self.untagged.iter().map(|f| parse(f))
    }

    pub fn tagged(&self) -> Response<'_> {
        parse(&self.tagged)
    }

    pub fn ok(&self) -> bool {
        matches!(self.tagged(), Response::Done { status: Status::Ok, .. })
    }

    pub fn tagged_code(&self) -> Option<ResponseCode<'_>> {
        match self.tagged() {
            Response::Done { outcome, .. } => outcome.code,
            _ => None,
        }
    }

    /// Response codes of untagged `* OK [...]` lines.
    pub fn untagged_codes(&self) -> Vec<ResponseCode<'_>> {
        self.untagged()
            .filter_map(|r| match r {
                Response::Data { status: Status::Ok, outcome } => outcome.code,
                _ => None,
            })
            .collect()
    }
}

/// Send any command text and collect every response until its tagged completion. This is the
/// escape hatch for everything async-imap's typed helpers cannot express or throw away.
pub async fn raw_command<T>(session: &mut Session<T>, command: &str) -> Result<RawResult, Error>
where
    T: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send,
{
    let id = session.run_command(command).await?;
    read_until_tagged(session, &id).await
}

async fn read_until_tagged<T>(
    session: &mut Session<T>,
    id: &imap_proto::RequestId,
) -> Result<RawResult, Error>
where
    T: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send,
{
    let mut untagged = Vec::new();
    loop {
        let resp = session.read_response().await?.ok_or("connection closed")?;
        let raw = resp.borrow_owner().to_vec();
        if matches!(resp.parsed(), Response::Done { tag, .. } if tag == id) {
            return Ok(RawResult { untagged, tagged: raw });
        }
        untagged.push(raw);
    }
}

/// Requirement 8: APPEND that returns APPENDUID. `Session::append` returns `()` and drops the
/// response code, so this writes the command and the literal itself.
pub async fn append_uid<T>(
    session: &mut Session<T>,
    mailbox: &str,
    flags: &str,
    message: &[u8],
) -> Result<Option<(u32, u32)>, Error>
where
    T: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send,
{
    let id = session
        .run_command(format!("APPEND {} ({flags}) {{{}}}", quote(mailbox), message.len()))
        .await?;
    // Untagged responses (EXISTS, FETCH, ...) may arrive before the continuation request; skip
    // them. A tagged response here means the server refused the APPEND outright.
    loop {
        let resp = session.read_response().await?.ok_or("connection closed")?;
        match resp.parsed() {
            Response::Continue { .. } => break,
            Response::Done { tag, .. } if *tag == id => {
                return Err(format!("APPEND refused: {:?}", resp.parsed()).into());
            }
            _ => {}
        }
    }
    let stream: &mut T = AsMut::<T>::as_mut(session);
    stream.write_all(message).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await?;
    let res = read_until_tagged(session, &id).await?;
    if !res.ok() {
        return Err(format!("APPEND failed: {:?}", res.tagged()).into());
    }
    Ok(match res.tagged_code() {
        Some(ResponseCode::AppendUid(validity, uids)) => first_uid(&uids).map(|uid| (validity, uid)),
        _ => None,
    })
}

fn first_uid(set: &[imap_proto::rfc4315::UidSetMember]) -> Option<u32> {
    use imap_proto::rfc4315::UidSetMember;
    set.first().map(|m| match m {
        UidSetMember::Uid(u) => *u,
        UidSetMember::UidRange(r) => *r.start(),
    })
}

/// COPYUID from either the tagged response (UID COPY) or an untagged OK (UID MOVE, RFC 6851).
pub fn copyuid(res: &RawResult) -> Option<(u32, Vec<u32>, Vec<u32>)> {
    use imap_proto::rfc4315::UidSetMember;
    let expand = |s: &[UidSetMember]| -> Vec<u32> {
        s.iter()
            .flat_map(|m| match m {
                UidSetMember::Uid(u) => vec![*u],
                UidSetMember::UidRange(r) => r.clone().collect(),
            })
            .collect()
    };
    res.tagged_code().into_iter().chain(res.untagged_codes()).find_map(|c| match c {
        ResponseCode::CopyUid(v, from, to) => Some((v, expand(&from), expand(&to))),
        _ => None,
    })
}

pub fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Requirement 9: X-GM-THRID has no accessor on `Fetch` (and its parsed response is private),
/// so it is read from the raw path.
pub fn gmail_thread_ids(res: &RawResult) -> Vec<(u32, u64)> {
    res.untagged()
        .filter_map(|r| match r {
            Response::Fetch(_, attrs) => {
                let uid = attrs.iter().find_map(|a| match a {
                    AttributeValue::Uid(u) => Some(*u),
                    _ => None,
                })?;
                let thr = attrs.iter().find_map(|a| match a {
                    AttributeValue::GmailThrId(t) => Some(*t),
                    _ => None,
                })?;
                Some((uid, thr))
            }
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// BODYSTRUCTURE -> MimePart
// ---------------------------------------------------------------------------------------------

/// Requirement 4: convert imap-proto's BODYSTRUCTURE into the neutral tree.
pub fn to_mime_tree(bs: &BodyStructure<'_>) -> MimePart {
    let root = mime::root_section(matches!(bs, BodyStructure::Multipart { .. }));
    convert(bs, root)
}

fn params(p: &imap_proto::BodyParams<'_>) -> Vec<(String, String)> {
    p.as_ref()
        .map(|v| v.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.to_string())).collect())
        .unwrap_or_default()
}

fn encoding(e: &ContentEncoding<'_>) -> String {
    match e {
        ContentEncoding::SevenBit => "7bit".into(),
        ContentEncoding::EightBit => "8bit".into(),
        ContentEncoding::Binary => "binary".into(),
        ContentEncoding::Base64 => "base64".into(),
        ContentEncoding::QuotedPrintable => "quoted-printable".into(),
        ContentEncoding::Other(o) => o.to_ascii_lowercase(),
    }
}

fn convert(bs: &BodyStructure<'_>, section: String) -> MimePart {
    let common = match bs {
        BodyStructure::Basic { common, .. }
        | BodyStructure::Text { common, .. }
        | BodyStructure::Message { common, .. }
        | BodyStructure::Multipart { common, .. } => common,
    };
    let mime_type =
        format!("{}/{}", common.ty.ty, common.ty.subtype).to_ascii_lowercase();
    let mut part = MimePart::new(section.clone(), mime_type);
    part.params = params(&common.ty.params);
    part.disposition = common.disposition.as_ref().map(|d| d.ty.to_ascii_lowercase());
    let disp_params = common.disposition.as_ref().map(|d| params(&d.params)).unwrap_or_default();
    match bs {
        BodyStructure::Basic { other, .. } => {
            single(&mut part, other);
        }
        BodyStructure::Text { other, lines, .. } => {
            single(&mut part, other);
            part.lines = Some(*lines);
        }
        BodyStructure::Message { other, body, lines, .. } => {
            single(&mut part, other);
            part.lines = Some(*lines);
            let multi = matches!(**body, BodyStructure::Multipart { .. });
            part.children.push(convert(body, mime::embedded_section(&section, multi)));
        }
        BodyStructure::Multipart { bodies, .. } => {
            for (i, b) in bodies.iter().enumerate() {
                part.children.push(convert(b, mime::child_section(&section, i)));
            }
        }
    }
    if !matches!(bs, BodyStructure::Multipart { .. }) {
        part.resolve_filename(&disp_params);
    }
    part
}

fn single(part: &mut MimePart, other: &imap_proto::BodyContentSinglePart<'_>) {
    part.encoding = encoding(&other.transfer_encoding);
    part.size = other.octets;
    part.content_id = other.id.as_ref().map(|s| s.to_string());
}
