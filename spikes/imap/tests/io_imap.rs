//! Candidate C (probe): io-imap 0.11.2, imap-client's successor, driven by our tokio pump.
//!
//! Only the rows that discriminate between candidates are exercised here; the rest are
//! assessed from source in FINDINGS.md (io-imap parses with the same imap-codec as B).

mod common;

use std::time::Duration;

use common::*;
use fake_imap::{Action, FakeServer, Rule, prefix, profiles};
use io_imap::client::ImapClientAsync;
use io_imap::codec::imap_types::{
    core::Vec1,
    fetch::{MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName, Part, Section},
    mailbox::Mailbox,
    response::Data,
    sequence::SequenceSet,
};
use io_imap::rfc3501::fetch::ImapMessageFetchOptions;
use io_imap::rfc3501::select::ImapMailboxSelectOptions;
use io_imap::sasl::auth_xoauth2::ImapAuthXoauth2Options;
use imap_spike::cand_imap_next as b;
use imap_spike::cand_io_imap::{self as c, TokioImap};
use tokio::net::TcpStream;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

async fn login(srv: &FakeServer) -> Result<TokioImap<TcpStream>, BoxErr> {
    let mut cl = c::connect_plain(srv.host(), srv.port()).await?;
    cl.login("alice", "secret", Default::default()).await?;
    Ok(cl)
}

fn uid_opts() -> ImapMessageFetchOptions {
    ImapMessageFetchOptions { uid: true, ..Default::default() }
}

fn names(v: Vec<MessageDataItemName<'static>>) -> MacroOrMessageDataItemNames<'static> {
    MacroOrMessageDataItemNames::MessageDataItemNames(v)
}

fn seq(s: &str) -> SequenceSet {
    SequenceSet::try_from(s).unwrap()
}

#[test]
fn r1_tls_config_builds_with_platform_verifier() {
    let cfg = imap_spike::tls::client_config().expect("platform verifier config");
    assert_eq!(cfg.alpn_protocols, vec![b"imap".to_vec()]);
    let _f = c::connect_tls; // our own rustls stream goes into io-imap
}

#[tokio::test]
#[ignore = "live network: connects to imap.gmail.com:993 and reads the greeting only"]
async fn r1_tls_live_gmail_greeting() -> TestResult {
    let mut cl = c::connect_tls("imap.gmail.com", 993).await?;
    assert!(cl.capability().await?.len() > 1);
    Ok(())
}

#[tokio::test]
async fn r2_xoauth2_sasl_ir() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::gmail()).await;
        let mut cl = c::connect_plain(srv.host(), srv.port()).await?;
        let opts = ImapAuthXoauth2Options { initial_request: true, ..Default::default() };
        let caps = cl.auth_xoauth2(USER, TOKEN, opts).await?;
        assert!(caps.len() > 5, "post-auth capabilities picked up");
        let cmd = srv.find_command("AUTHENTICATE").unwrap();
        let ir = cmd.strip_prefix("AUTHENTICATE XOAUTH2 ").expect("one-line SASL-IR command");
        assert_eq!(b64_decode(ir), format!("user={USER}\x01auth=Bearer {TOKEN}\x01\x01"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn r2_xoauth2_error_challenge() -> TestResult {
    timed(async {
        let sc = profiles::gmail().first(
            Rule::new(
                prefix("AUTHENTICATE XOAUTH2 "),
                vec![
                    Action::Continue(profiles::XOAUTH2_ERROR_CHALLENGE.into()),
                    Action::Line("{tag} NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)".into()),
                ],
            )
            .once(),
        );
        let srv = FakeServer::start(sc).await;
        let mut cl = c::connect_plain(srv.host(), srv.port()).await?;
        let opts = ImapAuthXoauth2Options { initial_request: true, ..Default::default() };
        let err = cl.auth_xoauth2(USER, "expired", opts).await.unwrap_err();
        eprintln!("io-imap XOAUTH2 error: {err}");
        assert!(srv.transcript().contains(&"<cont> ".to_string()), "{:?}", srv.transcript());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn r4_uid_fetch_headers_bodystructure() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut cl = login(&srv).await?;
        let sel = cl.select(Mailbox::Inbox, ImapMailboxSelectOptions::default()).await?;
        assert_eq!(sel.data.highest_mod_seq, Some(4521));
        use MessageDataItemName::*;
        let out = cl
            .fetch(seq("1:*"), names(vec![Uid, Flags, Envelope, BodyStructure, Rfc822Size, InternalDate]), uid_opts())
            .await?;
        assert_eq!(out.data.len(), 3);
        let tree = |items: &Vec1<MessageDataItem<'static>>| {
            items.as_ref().iter().find_map(|i| match i {
                MessageDataItem::BodyStructure(bs) => Some(b::to_mime_tree(bs)),
                _ => None,
            })
        };
        // Keyed by sequence number, not UID.
        assert_tree_101(&tree(&out.data[&b::nz(1)]).unwrap());
        assert_tree_102(&tree(&out.data[&b::nz(2)]).unwrap());
        assert_tree_103(&tree(&out.data[&b::nz(3)]).unwrap());
        // FINDING: the mid-FETCH EXISTS is neither in data nor in skipped.
        assert!(out.skipped.is_empty() && out.partial.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn r5_fetch_single_part() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut cl = login(&srv).await?;
        cl.select(Mailbox::Inbox, ImapMailboxSelectOptions::default()).await?;
        let part = Part(Vec1::try_from(vec![b::nz(1), b::nz(2)]).unwrap());
        let item = MessageDataItemName::BodyExt { section: Some(Section::Part(part)), partial: None, peek: true };
        let out = cl.fetch(seq("101"), names(vec![item]), uid_opts()).await?;
        let data = out.data.values().next().unwrap().as_ref().iter().find_map(|i| match i {
            MessageDataItem::BodyExt { data, .. } => b::nstring_bytes(data),
            _ => None,
        });
        assert_eq!(data.as_deref(), Some(profiles::PART_101_1_2.as_bytes()));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn r6_idle_receives_updates() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut cl = login(&srv).await?;
        cl.select(Mailbox::Inbox, ImapMailboxSelectOptions::default()).await?;
        let (data, stopped) = cl.idle_until(3, std::future::pending()).await?;
        assert!(!stopped);
        assert!(matches!(data[0], Data::Exists(4)));
        assert!(matches!(data[1], Data::Expunge(n) if n.get() == 1));
        assert!(matches!(&data[2], Data::Fetch { seq, .. } if seq.get() == 2));
        assert!(srv.transcript().iter().any(|l| l == "DONE"));
        cl.noop().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn r6_idle_timeout_and_cancel() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot().first(profiles::idle_silent())).await;
        let mut cl = login(&srv).await?;
        cl.select(Mailbox::Inbox, ImapMailboxSelectOptions::default()).await?;
        let (data, stopped) = cl.idle_until(1, tokio::time::sleep(Duration::from_millis(200))).await?;
        assert!(stopped && data.is_empty());
        cl.noop().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn r9_gmail_extensions() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::gmail()).await;
        let mut cl = login(&srv).await?;
        cl.select(Mailbox::Inbox, ImapMailboxSelectOptions::default()).await?;
        // Typed commands cannot express X-GM-* (same imap-types as B); `raw` sends any bytes
        // and returns the server's response verbatim, for the caller to parse.
        let resp = cl.raw(b"G1 UID FETCH 1:* (UID X-GM-MSGID X-GM-THRID X-GM-LABELS)\r\n").await?;
        assert!(resp.contains("X-GM-THRID 1780000000000000101"), "{resp}");
        assert!(resp.contains("G1 OK"));
        let resp = cl.raw(b"G2 UID SEARCH X-GM-RAW \"has:attachment in:inbox\"\r\n").await?;
        assert!(resp.contains("* SEARCH 101 103"), "{resp}");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn risk_unexpected_fetch_item() -> TestResult {
    timed(async {
        // The FETCH line for 102 carries X-GM-LABELS. io-imap keeps the items that decode and
        // reports the rest as raw bytes, so the message is not lost.
        let srv = FakeServer::start(profiles::gmail()).await;
        let mut cl = login(&srv).await?;
        cl.select(Mailbox::Inbox, ImapMailboxSelectOptions::default()).await?;
        let out = cl.fetch(seq("1:*"), names(vec![MessageDataItemName::Flags]), uid_opts()).await?;
        assert_eq!(out.partial.len(), 1, "{:?}", out.partial);
        let p = &out.partial[0];
        assert_eq!(p.uid.map(|u| u.get()), Some(102));
        assert_eq!(p.failed[0].name, "X-GM-LABELS");
        assert_eq!(out.data.len(), 3, "UID and FLAGS of 102 still decoded");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn risk_unknown_fetch_item() -> TestResult {
    timed(async {
        // SAVEDATE is unknown to imap-codec; io-imap keeps UID and FLAGS of 102 and reports
        // SAVEDATE as a failed item with its raw bytes.
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut cl = login(&srv).await?;
        cl.select(Mailbox::Inbox, ImapMailboxSelectOptions::default()).await?;
        let out = cl.fetch(seq("1:*"), names(vec![MessageDataItemName::Flags]), uid_opts()).await?;
        assert_eq!(out.data.len(), 3);
        assert_eq!(out.partial.len(), 1);
        assert_eq!(out.partial[0].failed[0].name, "SAVEDATE");
        Ok(())
    })
    .await
}
