//! A scripted fake IMAP server for tests.
//!
//! The server accepts one or more TCP connections and answers each client command with the
//! first [`Rule`] whose [`Matcher`] fits the command text (the part after the tag). Replies can
//! contain `{tag}`, which is replaced with the client's tag, so the same script works for
//! clients that generate tags differently.
//!
//! Every complete command (including client literals) is recorded in a transcript, so tests can
//! assert on what actually went over the wire, not only on what a library parsed.
//!
//! The crate has no dependency on any IMAP client library, so it can move into the main
//! workspace as test support for `cm-imap`.

pub mod profiles;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// How a rule recognises a command. Matching ignores ASCII case and runs on the command text
/// after the tag, with client literals inlined.
#[derive(Clone, Debug)]
pub enum Matcher {
    /// The command starts with this text.
    Prefix(String),
    /// The command contains every one of these fragments.
    Contains(Vec<String>),
    /// The command is exactly this text.
    Exact(String),
    /// The inner matcher fits and the command does not contain this word.
    Without(Box<Matcher>, String),
}

impl Matcher {
    fn matches(&self, command: &str) -> bool {
        let cmd = command.to_ascii_uppercase();
        match self {
            Matcher::Prefix(p) => cmd.starts_with(&p.to_ascii_uppercase()),
            Matcher::Contains(parts) => parts.iter().all(|p| cmd.contains(&p.to_ascii_uppercase())),
            Matcher::Exact(e) => cmd == e.to_ascii_uppercase(),
            Matcher::Without(inner, word) => inner.matches(command) && !cmd.contains(&word.to_ascii_uppercase()),
        }
    }
}

/// One step of a scripted reply.
#[derive(Clone, Debug)]
pub enum Action {
    /// Send this text followed by CRLF. `{tag}` is replaced with the client's tag. The text may
    /// itself contain CRLFs (for server literals).
    Line(String),
    /// Send this text followed by CRLF, but in chunks of `chunk` bytes with a short pause and a
    /// flush between chunks, to exercise client reassembly of split TCP reads.
    Chunked(String, usize),
    /// Pause.
    Sleep(Duration),
    /// Send `+ <text>` and read one continuation line from the client (recorded in the
    /// transcript with the prefix `<cont> `).
    Continue(String),
    /// Read client lines until one equals this text (case-insensitive), e.g. `DONE` for IDLE.
    /// Each line is recorded.
    WaitFor(String),
    /// Close the connection.
    Close,
}

/// A command matcher and its scripted reply.
#[derive(Clone, Debug)]
pub struct Rule {
    pub matcher: Matcher,
    pub actions: Vec<Action>,
    /// How many times this rule may fire; `None` means unlimited.
    pub times: Option<usize>,
}

impl Rule {
    pub fn new(matcher: Matcher, actions: Vec<Action>) -> Self {
        Self { matcher, actions, times: None }
    }

    /// Convenience: reply with these lines (each followed by CRLF).
    pub fn lines(matcher: Matcher, lines: &[&str]) -> Self {
        Self::new(matcher, lines.iter().map(|l| Action::Line((*l).to_string())).collect())
    }

    pub fn once(mut self) -> Self {
        self.times = Some(1);
        self
    }
}

pub fn prefix(p: &str) -> Matcher {
    Matcher::Prefix(p.to_string())
}

pub fn contains(parts: &[&str]) -> Matcher {
    Matcher::Contains(parts.iter().map(|s| s.to_string()).collect())
}

pub fn exact(e: &str) -> Matcher {
    Matcher::Exact(e.to_string())
}

pub fn without(inner: Matcher, word: &str) -> Matcher {
    Matcher::Without(Box::new(inner), word.to_string())
}

/// A server personality: greeting plus rules, tried in order.
#[derive(Clone, Debug)]
pub struct Scenario {
    pub greeting: String,
    pub rules: Vec<Rule>,
}

impl Scenario {
    pub fn new(greeting: &str) -> Self {
        Self { greeting: greeting.to_string(), rules: Vec::new() }
    }

    /// Append a rule (lower priority than existing rules).
    pub fn rule(mut self, rule: Rule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Insert a rule ahead of all existing rules, so a test can override a profile's default.
    pub fn first(mut self, rule: Rule) -> Self {
        self.rules.insert(0, rule);
        self
    }

    /// Add the catch-all rules every server needs (NOOP, LOGOUT).
    pub fn with_defaults(self) -> Self {
        self.rule(Rule::lines(exact("NOOP"), &["{tag} OK NOOP completed"])).rule(Rule::new(
            exact("LOGOUT"),
            vec![
                Action::Line("* BYE Logging out".into()),
                Action::Line("{tag} OK Logout completed".into()),
                Action::Close,
            ],
        ))
    }
}

/// A running fake server. Dropping it stops accepting new connections.
pub struct FakeServer {
    port: u16,
    transcript: Arc<Mutex<Vec<String>>>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

impl FakeServer {
    /// Bind to an ephemeral port on 127.0.0.1 and serve the scenario to every connection.
    /// Rule usage counts are shared across connections.
    pub async fn start(scenario: Scenario) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fake server");
        let port = listener.local_addr().unwrap().port();
        let transcript = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(Mutex::new(scenario));
        let t = transcript.clone();
        let accept_task = tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let state = state.clone();
                let t = t.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve(sock, state, t.clone()).await {
                        t.lock().unwrap().push(format!("<server error> {e}"));
                    }
                });
            }
        });
        Self { port, transcript, accept_task }
    }

    pub fn host(&self) -> &'static str {
        "127.0.0.1"
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Everything the client sent, one entry per command or continuation line, with tags.
    pub fn transcript(&self) -> Vec<String> {
        self.transcript.lock().unwrap().clone()
    }

    /// Commands without their tags (continuation lines keep their `<cont>` prefix).
    pub fn commands(&self) -> Vec<String> {
        self.transcript()
            .into_iter()
            .map(|l| {
                if l.starts_with('<') {
                    l
                } else {
                    l.split_once(' ').map(|(_, rest)| rest.to_string()).unwrap_or(l)
                }
            })
            .collect()
    }

    /// The first recorded command (without tag) that contains `needle`, case-insensitively.
    pub fn find_command(&self, needle: &str) -> Option<String> {
        let n = needle.to_ascii_uppercase();
        self.commands().into_iter().find(|c| c.to_ascii_uppercase().contains(&n))
    }
}

type Reader = BufReader<tokio::net::tcp::OwnedReadHalf>;
type Writer = tokio::net::tcp::OwnedWriteHalf;

async fn serve(
    sock: TcpStream,
    state: Arc<Mutex<Scenario>>,
    transcript: Arc<Mutex<Vec<String>>>,
) -> std::io::Result<()> {
    let (r, mut w) = sock.into_split();
    let mut r = BufReader::new(r);
    let greeting = state.lock().unwrap().greeting.clone();
    write_line(&mut w, &greeting).await?;

    loop {
        let Some(raw) = read_command(&mut r, &mut w).await? else { return Ok(()) };
        transcript.lock().unwrap().push(raw.clone());
        let (tag, command) = raw.split_once(' ').unwrap_or((raw.as_str(), ""));
        let tag = tag.to_string();
        let actions = {
            let mut sc = state.lock().unwrap();
            let pos = sc.rules.iter().position(|r| r.times != Some(0) && r.matcher.matches(command));
            match pos {
                Some(i) => {
                    let rule = &mut sc.rules[i];
                    if let Some(t) = rule.times.as_mut() {
                        *t -= 1;
                    }
                    rule.actions.clone()
                }
                None => vec![Action::Line("{tag} BAD [CLIENTBUG] fake server has no rule for this command".into())],
            }
        };
        for action in actions {
            match action {
                Action::Line(text) => write_line(&mut w, &text.replace("{tag}", &tag)).await?,
                Action::Chunked(text, chunk) => {
                    let mut bytes = text.replace("{tag}", &tag).into_bytes();
                    bytes.extend_from_slice(b"\r\n");
                    for piece in bytes.chunks(chunk.max(1)) {
                        w.write_all(piece).await?;
                        w.flush().await?;
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
                Action::Sleep(d) => tokio::time::sleep(d).await,
                Action::Continue(text) => {
                    write_line(&mut w, &format!("+ {text}")).await?;
                    let line = read_line(&mut r).await?.unwrap_or_default();
                    transcript.lock().unwrap().push(format!("<cont> {line}"));
                }
                Action::WaitFor(expected) => loop {
                    let Some(line) = read_line(&mut r).await? else { return Ok(()) };
                    transcript.lock().unwrap().push(line.clone());
                    if line.eq_ignore_ascii_case(&expected) {
                        break;
                    }
                },
                Action::Close => {
                    w.shutdown().await.ok();
                    return Ok(());
                }
            }
        }
    }
}

async fn write_line(w: &mut Writer, text: &str) -> std::io::Result<()> {
    w.write_all(text.as_bytes()).await?;
    w.write_all(b"\r\n").await?;
    w.flush().await
}

/// Read one line without its line ending. `None` at EOF.
async fn read_line(r: &mut Reader) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    let n = r.read_until(b'\n', &mut buf).await?;
    if n == 0 {
        return Ok(None);
    }
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// Read a complete command: a line plus any literals (`{n}`, `{n+}`, `~{n}`) and the line
/// continuations that follow them. Synchronising literals get a `+` continuation request.
async fn read_command(r: &mut Reader, w: &mut Writer) -> std::io::Result<Option<String>> {
    let Some(mut line) = read_line(r).await? else { return Ok(None) };
    let mut out = String::new();
    loop {
        match trailing_literal(&line) {
            Some((len, sync)) => {
                out.push_str(&line);
                out.push_str("\r\n");
                if sync {
                    write_line(w, "+ Ready for literal data").await?;
                }
                let mut data = vec![0u8; len];
                r.read_exact(&mut data).await?;
                out.push_str(&String::from_utf8_lossy(&data));
                line = read_line(r).await?.unwrap_or_default();
            }
            None => {
                out.push_str(&line);
                return Ok(Some(out));
            }
        }
    }
}

/// Parse a literal announcement at the end of a line: returns (length, synchronising).
fn trailing_literal(line: &str) -> Option<(usize, bool)> {
    let body = line.strip_suffix('}')?;
    let open = body.rfind('{')?;
    let inner = &body[open + 1..];
    let (digits, sync) = match inner.strip_suffix('+') {
        Some(d) => (d, false),
        None => (inner, true),
    };
    digits.parse().ok().map(|n| (n, sync))
}

/// Format a server-side literal: `{len}\r\n<data>`.
pub fn literal(data: &str) -> String {
    format!("{{{}}}\r\n{}", data.len(), data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_detection() {
        assert_eq!(trailing_literal("A1 APPEND Sent {12}"), Some((12, true)));
        assert_eq!(trailing_literal("A1 APPEND Sent {12+}"), Some((12, false)));
        assert_eq!(trailing_literal("A1 APPEND Sent ~{12}"), Some((12, true)));
        assert_eq!(trailing_literal("A1 NOOP"), None);
    }

    #[test]
    fn matching_ignores_case() {
        assert!(prefix("uid fetch").matches("UID FETCH 1:* (FLAGS)"));
        assert!(contains(&["fetch", "bodystructure"]).matches("UID FETCH 1:* (UID BODYSTRUCTURE)"));
        assert!(!exact("NOOP").matches("NOOP X"));
    }
}
