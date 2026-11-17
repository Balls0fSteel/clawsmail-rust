//! Candidate B: the duesee / pimalaya stack.
//!
//! * `imap-codec` / `imap-types`: parser, serializer and typed messages.
//! * `imap-next`: sans-I/O client state machine (literals, AUTHENTICATE, IDLE flows).
//! * `imap-client`: tokio client with one `Task` per command and convenience methods.
//!
//! What is here is the glue `cm-imap` would need: the BODYSTRUCTURE converter, a generic
//! `CollectTask` that captures everything a command returns (imap-client's own tasks drop
//! untagged data they do not expect, such as VANISHED, EXPUNGE during STORE and COPYUID in an
//! untagged OK), and an IDLE loop written directly against imap-next, because
//! `imap_client::tokio::Client::idle` throws away the data that woke it.

use std::num::NonZeroU32;
use std::time::Duration;

use imap_client::imap_next::{
    client::{Client as NextClient, Event, Options},
    imap_types::{
        IntoStatic,
        body::{BasicFields, BodyStructure, SpecificFields},
        command::{Command, CommandBody},
        core::{IString, NString, Tag},
        mailbox::Mailbox,
        response::{Data, Status, StatusBody, StatusKind, Tagged},
    },
};
use imap_client::stream::Stream;
use imap_client::tasks::Task;
use tokio::net::TcpStream;

use crate::mime::{self, MimePart};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Requirement 1: implicit TLS with rustls. imap-client builds the rustls config itself with
/// `rustls_platform_verifier::ConfigVerifierExt::with_platform_verifier()` (verifier 0.6) and
/// connects the TCP socket itself; neither the config nor the socket can be injected.
pub async fn connect_tls(host: &str) -> Result<imap_client::client::tokio::Client, Error> {
    Ok(imap_client::client::tokio::Client::rustls(host, 993, false, None).await?)
}

/// The same requirement at the imap-next level, which does accept our own TLS stream (and
/// therefore our own `ClientConfig`, proxy, timeouts).
pub async fn connect_tls_next(
    host: &str,
    port: u16,
) -> Result<Stream<tokio_rustls::client::TlsStream<TcpStream>>, Error> {
    use std::sync::Arc;
    use tokio_rustls::rustls::pki_types::ServerName;
    let config = crate::tls::client_config()?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect((host, port)).await?;
    let tls = connector.connect(ServerName::try_from(host.to_string())?, tcp).await?;
    Ok(Stream::new(tls))
}

pub fn mailbox_name(m: &Mailbox<'_>) -> String {
    match m {
        Mailbox::Inbox => "INBOX".into(),
        Mailbox::Other(o) => String::from_utf8_lossy(o.as_ref()).into_owned(),
    }
}

pub fn istring(s: &IString<'_>) -> String {
    String::from_utf8_lossy(s.as_ref()).into_owned()
}

pub fn nstring(s: &NString<'_>) -> Option<String> {
    s.0.as_ref().map(istring)
}

pub fn nstring_bytes(s: &NString<'_>) -> Option<Vec<u8>> {
    s.0.as_ref().map(|i| i.as_ref().to_vec())
}

// ---------------------------------------------------------------------------------------------
// CollectTask: run any typed command and keep everything it returns
// ---------------------------------------------------------------------------------------------

#[derive(Debug)]
pub struct Collected {
    pub data: Vec<Data<'static>>,
    pub untagged: Vec<StatusBody<'static>>,
    pub tagged: StatusBody<'static>,
}

impl Collected {
    pub fn ok(&self) -> bool {
        self.tagged.kind == StatusKind::Ok
    }
}

/// A `Task` that claims every untagged response that reaches it.
pub struct CollectTask {
    body: CommandBody<'static>,
    data: Vec<Data<'static>>,
    untagged: Vec<StatusBody<'static>>,
}

impl CollectTask {
    pub fn new(body: CommandBody<'_>) -> Self {
        Self { body: body.into_static(), data: Vec::new(), untagged: Vec::new() }
    }
}

impl Task for CollectTask {
    type Output = Collected;

    fn command_body(&self) -> CommandBody<'static> {
        self.body.clone()
    }

    fn process_data(&mut self, data: Data<'static>) -> Option<Data<'static>> {
        self.data.push(data);
        None
    }

    fn process_untagged(&mut self, status_body: StatusBody<'static>) -> Option<StatusBody<'static>> {
        self.untagged.push(status_body);
        None
    }

    fn process_tagged(self, tagged: StatusBody<'static>) -> Collected {
        Collected { data: self.data, untagged: self.untagged, tagged }
    }
}

// ---------------------------------------------------------------------------------------------
// IDLE on imap-next directly
// ---------------------------------------------------------------------------------------------

/// A minimal driver over imap-next: own connection, own tags, every event visible.
pub struct NextConn {
    pub stream: Stream<TcpStream>,
    pub client: NextClient,
    next_tag: u32,
}

impl NextConn {
    pub async fn connect(host: &str, port: u16) -> Result<Self, Error> {
        let tcp = TcpStream::connect((host, port)).await?;
        let mut me = Self {
            stream: Stream::new(tcp),
            client: NextClient::new(Options::default()),
            next_tag: 1,
        };
        loop {
            if let Event::GreetingReceived { .. } = me.stream.next(&mut me.client).await? {
                return Ok(me);
            }
        }
    }

    fn tag(&mut self) -> Tag<'static> {
        let t = Tag::try_from(format!("N{}", self.next_tag)).unwrap();
        self.next_tag += 1;
        t
    }

    /// Run a command and return its data and tagged status.
    pub async fn run(&mut self, body: CommandBody<'static>) -> Result<(Vec<Data<'static>>, StatusBody<'static>), Error> {
        let tag = self.tag();
        self.client.enqueue_command(Command { tag: tag.clone(), body });
        let mut data = Vec::new();
        loop {
            match self.stream.next(&mut self.client).await? {
                Event::DataReceived { data: d } => data.push(d),
                Event::StatusReceived { status: Status::Tagged(Tagged { tag: t, body }) } if t == tag => {
                    return Ok((data, body));
                }
                Event::CommandRejected { status: Status::Tagged(Tagged { body, .. }), .. } => {
                    return Ok((data, body));
                }
                _ => {}
            }
        }
    }

    /// Requirement 6: IDLE until `want` data responses arrived or `max_wait` passed, then DONE.
    pub async fn idle(&mut self, want: usize, max_wait: Duration) -> Result<IdleOutcome, Error> {
        self.idle_until(want, tokio::time::sleep(max_wait)).await
    }

    /// IDLE until `want` data responses arrived or `stop` resolves (timeout, user cancel,
    /// shutdown), then send DONE and wait for the tagged completion. Returns every data
    /// response received while idling.
    pub async fn idle_until(
        &mut self,
        want: usize,
        stop: impl std::future::Future<Output = ()>,
    ) -> Result<IdleOutcome, Error> {
        let tag = self.tag();
        self.client.enqueue_command(Command { tag: tag.clone(), body: CommandBody::Idle });
        let mut out = IdleOutcome::default();
        let mut stop = std::pin::pin!(stop);
        let mut done_requested = false;
        loop {
            let event = if done_requested {
                self.stream.next(&mut self.client).await?
            } else {
                tokio::select! {
                    ev = self.stream.next(&mut self.client) => ev?,
                    () = &mut stop => {
                        // Cancellation point: dropping the pending `next` mid-read is safe
                        // because tokio's read is cancel-safe and imap-next buffers input.
                        out.stopped = true;
                        self.client.set_idle_done();
                        done_requested = true;
                        continue;
                    }
                }
            };
            match event {
                Event::IdleAccepted { .. } => out.accepted = true,
                Event::IdleRejected { .. } => return Ok(out),
                Event::DataReceived { data } => {
                    out.data.push(data);
                    if out.data.len() >= want && !done_requested {
                        self.client.set_idle_done();
                        done_requested = true;
                    }
                }
                Event::StatusReceived { status: Status::Tagged(Tagged { tag: t, body }) } if t == tag => {
                    out.completed = Some(body);
                    return Ok(out);
                }
                _ => {}
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct IdleOutcome {
    pub accepted: bool,
    /// The stop future fired (timeout or cancel) before enough data arrived.
    pub stopped: bool,
    pub data: Vec<Data<'static>>,
    pub completed: Option<StatusBody<'static>>,
}

// ---------------------------------------------------------------------------------------------
// BODYSTRUCTURE -> MimePart
// ---------------------------------------------------------------------------------------------

/// Requirement 4: convert imap-types' BODYSTRUCTURE into the neutral tree.
pub fn to_mime_tree(bs: &BodyStructure<'_>) -> MimePart {
    let root = mime::root_section(matches!(bs, BodyStructure::Multi { .. }));
    convert(bs, root)
}

fn params(p: &[(IString<'_>, IString<'_>)]) -> Vec<(String, String)> {
    p.iter().map(|(k, v)| (istring(k).to_ascii_lowercase(), istring(v))).collect()
}

fn convert(bs: &BodyStructure<'_>, section: String) -> MimePart {
    match bs {
        BodyStructure::Multi { bodies, subtype, extension_data } => {
            let mut part = MimePart::new(section.clone(), format!("multipart/{}", istring(subtype).to_ascii_lowercase()));
            if let Some(ext) = extension_data {
                part.params = params(&ext.parameter_list);
                if let Some(d) = ext.tail.as_ref().and_then(|t| t.disposition.as_ref()) {
                    part.disposition = Some(istring(&d.0).to_ascii_lowercase());
                }
            }
            for (i, b) in bodies.as_ref().iter().enumerate() {
                part.children.push(convert(b, mime::child_section(&section, i)));
            }
            part
        }
        BodyStructure::Single { body, extension_data } => {
            let (ty, sub) = match &body.specific {
                SpecificFields::Basic { r#type, subtype } => (istring(r#type), istring(subtype)),
                SpecificFields::Message { .. } => ("message".into(), "rfc822".into()),
                SpecificFields::Text { subtype, .. } => ("text".into(), istring(subtype)),
            };
            let mut part = MimePart::new(section.clone(), format!("{ty}/{sub}").to_ascii_lowercase());
            basic(&mut part, &body.basic);
            match &body.specific {
                SpecificFields::Text { number_of_lines, .. } => part.lines = Some(*number_of_lines),
                SpecificFields::Message { body_structure, number_of_lines, .. } => {
                    part.lines = Some(*number_of_lines);
                    let multi = matches!(**body_structure, BodyStructure::Multi { .. });
                    part.children.push(convert(body_structure, mime::embedded_section(&section, multi)));
                }
                SpecificFields::Basic { .. } => {}
            }
            let mut disp_params = Vec::new();
            if let Some(d) = extension_data.as_ref().and_then(|e| e.tail.as_ref()).and_then(|t| t.disposition.as_ref()) {
                part.disposition = Some(istring(&d.0).to_ascii_lowercase());
                disp_params = params(&d.1);
            }
            part.resolve_filename(&disp_params);
            part
        }
    }
}

fn basic(part: &mut MimePart, b: &BasicFields<'_>) {
    part.params = params(&b.parameter_list);
    part.encoding = istring(&b.content_transfer_encoding).to_ascii_lowercase();
    part.size = b.size;
    part.content_id = nstring(&b.id);
}

pub fn nz(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).expect("non-zero")
}
