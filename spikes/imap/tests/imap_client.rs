//! Candidate B: imap-client 0.3.1 / imap-next 0.3.4 / imap-codec 2.0.0-alpha.10.
//!
//! Test names match `tests/async_imap.rs` one to one. Where imap-client's convenience method
//! loses information, the test shows that and then the workaround: a `CollectTask` resolved
//! through `Client::resolve`, or (for IDLE) a loop written directly against imap-next.

mod common;

use std::num::NonZeroU64;
use std::time::Duration;

use common::*;
use fake_imap::{Action, FakeServer, Rule, exact, prefix, profiles};
use imap_client::client::tokio::{Client, ClientError};
use imap_client::imap_next::imap_types::{
    command::{CommandBody, FetchModifier, SelectParameter},
    core::Vec1,
    extensions::{enable::CapabilityEnable, uidplus::{UidElement, UidSet}},
    fetch::{MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName, Part, Section},
    flag::{Flag, FlagFetch, StoreResponse, StoreType},
    mailbox::Mailbox,
    response::{Code, Data, StatusKind},
    sequence::SequenceSet,
};
use imap_client::tasks::tasks::TaskError;
use imap_spike::cand_imap_next::{self as b, CollectTask, NextConn, nz};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

async fn login(srv: &FakeServer) -> Result<Client, BoxErr> {
    let mut c = Client::insecure(srv.host(), srv.port()).await?;
    c.login("alice", "secret").await?;
    Ok(c)
}

fn names(v: Vec<MessageDataItemName<'static>>) -> MacroOrMessageDataItemNames<'static> {
    MacroOrMessageDataItemNames::MessageDataItemNames(v)
}

fn seq(s: &str) -> SequenceSet {
    SequenceSet::try_from(s).unwrap()
}

fn find<'a, T>(items: &'a Vec1<MessageDataItem<'static>>, f: impl Fn(&'a MessageDataItem<'static>) -> Option<T>) -> Option<T> {
    items.as_ref().iter().find_map(f)
}

fn uidset(s: &UidSet) -> Vec<u32> {
    s.0.as_ref()
        .iter()
        .flat_map(|e| match e {
            UidElement::Single(u) => vec![u.get()],
            UidElement::Range(a, b) => (a.get()..=b.get()).collect(),
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// 1. TLS
// ---------------------------------------------------------------------------------------------

#[test]
fn r1_tls_config_builds_with_platform_verifier() {
    let cfg = imap_spike::tls::client_config().expect("platform verifier config");
    assert_eq!(cfg.alpn_protocols, vec![b"imap".to_vec()]);
    // imap-client's own TLS path (config and socket built inside the library) and the
    // imap-next path that accepts our config both type-check.
    let _a = b::connect_tls;
    let _b = b::connect_tls_next;
}

#[tokio::test]
#[ignore = "live network: connects to imap.gmail.com:993 and reads the greeting only"]
async fn r1_tls_live_gmail_greeting() -> TestResult {
    let c = Client::rustls("imap.gmail.com", 993, false, None).await?;
    assert!(c.state.capabilities_iter().count() > 1);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// 2. Authentication
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r2_xoauth2_sasl_ir() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::gmail()).await;
        // Gmail's greeting has no capabilities, so the client sends CAPABILITY first.
        let mut c = Client::insecure(srv.host(), srv.port()).await?;
        assert!(c.state.ext_sasl_ir_supported());
        c.authenticate_xoauth2(USER, TOKEN).await?;
        let cmd = srv.find_command("AUTHENTICATE").unwrap();
        let ir = cmd.strip_prefix("AUTHENTICATE XOAUTH2 ").expect("one-line SASL-IR command");
        assert_eq!(b64_decode(ir), format!("user={USER}\x01auth=Bearer {TOKEN}\x01\x01"));
        assert!(!srv.transcript().iter().any(|l| l.starts_with("<cont>")));
        // Post-auth capabilities (sent as untagged data by Gmail) were picked up.
        assert!(c.state.ext_move_supported() && c.state.ext_uidplus_supported());
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
        let mut c = Client::insecure(srv.host(), srv.port()).await?;
        let err = c.authenticate_xoauth2(USER, "expired").await.unwrap_err();
        assert!(matches!(err, ClientError::ResolveTask(TaskError::UnexpectedNoResponse(_))), "{err:?}");
        assert!(srv.transcript().contains(&"<cont> ".to_string()), "{:?}", srv.transcript());
        // FINDING: the JSON in the challenge is only logged (tracing::error!), not returned.
        Ok(())
    })
    .await
}

#[tokio::test]
async fn r2_xoauth2_without_ir() -> TestResult {
    timed(async {
        // A server without SASL-IR: the client must wait for "+".
        let caps = profiles::GMAIL_PREAUTH_CAPS.replace(" SASL-IR", "");
        let sc = profiles::gmail().first(Rule::lines(
            exact("CAPABILITY"),
            &[&format!("* CAPABILITY {caps}"), "{tag} OK Success"],
        ));
        let srv = FakeServer::start(sc).await;
        let mut c = Client::insecure(srv.host(), srv.port()).await?;
        c.authenticate_xoauth2(USER, TOKEN).await?;
        assert!(srv.find_command("AUTHENTICATE XOAUTH2").unwrap() == "AUTHENTICATE XOAUTH2");
        let t = srv.transcript();
        let cont = t.iter().find_map(|l| l.strip_prefix("<cont> ")).expect("payload after +");
        assert_eq!(b64_decode(cont), format!("user={USER}\x01auth=Bearer {TOKEN}\x01\x01"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn r2_login_and_plain() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut c = Client::insecure(srv.host(), srv.port()).await?;
        c.login("alice", r#"pa ss"w\d"#).await?;
        assert_eq!(srv.find_command("LOGIN").unwrap(), r#"LOGIN alice "pa ss\"w\\d""#);

        let mut c = Client::insecure(srv.host(), srv.port()).await?;
        c.authenticate_plain("alice", "secret").await?;
        let cmd = srv.find_command("AUTHENTICATE PLAIN").unwrap();
        assert_eq!(b64_decode(cmd.strip_prefix("AUTHENTICATE PLAIN ").unwrap()), "\0alice\0secret");
        Ok(())
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// 3. LIST, SELECT, EXAMINE
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r3_list_special_use() -> TestResult {
    timed(async {
        for (profile, sent, trash) in [
            (profiles::gmail(), "[Gmail]/Sent Mail", "[Gmail]/Trash"),
            (profiles::dovecot(), "Sent", "Trash"),
        ] {
            let srv = FakeServer::start(profile).await;
            let mut c = login(&srv).await?;
            let list = c.list("", "*").await?;
            let role = |attrs: &Vec<_>| {
                let s: Vec<String> = attrs.iter().map(|a: &imap_client::imap_next::imap_types::flag::FlagNameAttribute| a.to_string()).collect();
                special_use(s.iter().map(String::as_str))
            };
            let by_role = |r: &str| list.iter().find(|(_, _, a)| role(a) == Some(r)).map(|(m, _, _)| b::mailbox_name(m));
            assert_eq!(by_role("sent").as_deref(), Some(sent));
            assert_eq!(by_role("trash").as_deref(), Some(trash));
            assert!(by_role("junk").is_some() && by_role("drafts").is_some());
            assert_eq!(list[0].1.map(|q| q.inner()), Some('/'));
            if sent.starts_with("[Gmail]") {
                assert_eq!(by_role("important").as_deref(), Some("[Gmail]/Important"));
            } else {
                assert_eq!(by_role("archive").as_deref(), Some("Archive/2025"));
            }
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn r3_select_examine() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut c = login(&srv).await?;
        let m = c.select("INBOX").await?;
        assert_eq!(
            (m.exists, m.uid_validity, m.uid_next, m.highest_modseq),
            (Some(3), Some(nz(1_700_000_000)), Some(nz(104)), NonZeroU64::new(4521))
        );
        let m = c.examine("INBOX").await?;
        assert_eq!((m.uid_validity, m.highest_modseq), (Some(nz(1_700_000_000)), NonZeroU64::new(4521)));
        // Gmail sends "* OK [HIGHESTMODSEQ n]" with no text after the code.
        let srv = FakeServer::start(profiles::gmail()).await;
        let mut c = login(&srv).await?;
        let m = c.select("INBOX").await?;
        assert_eq!((m.uid_validity, m.uid_next, m.highest_modseq), (Some(nz(1_700_000_000)), Some(nz(104)), NonZeroU64::new(987_654)));
        Ok(())
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// 4. Header sync with BODYSTRUCTURE
// ---------------------------------------------------------------------------------------------

fn header_items() -> MacroOrMessageDataItemNames<'static> {
    use MessageDataItemName::*;
    names(vec![Uid, Flags, Envelope, BodyStructure, Rfc822Size, InternalDate])
}

#[tokio::test]
async fn r4_uid_fetch_headers_bodystructure() -> TestResult {
    timed(async {
        for (profile, injects_exists) in [(profiles::dovecot(), true), (profiles::gmail(), false)] {
            let srv = FakeServer::start(profile).await;
            let mut c = login(&srv).await?;
            c.select("INBOX").await?;
            let map = c.uid_fetch(seq("1:*"), header_items()).await?;
            assert_eq!(map.len(), 3);
            let i101 = &map[&nz(101)];
            assert_eq!(find(i101, |i| match i { MessageDataItem::Rfc822Size(s) => Some(*s), _ => None }), Some(110_342));
            assert!(find(i101, |i| match i { MessageDataItem::Flags(f) => Some(f.contains(&FlagFetch::Flag(Flag::Seen))), _ => None }).unwrap());
            let subj = find(i101, |i| match i { MessageDataItem::Envelope(e) => b::nstring(&e.subject), _ => None });
            assert_eq!(subj.as_deref(), Some("Quarterly report"));
            assert!(find(i101, |i| matches!(i, MessageDataItem::InternalDate(_)).then_some(())).is_some());
            let tree = |items: &Vec1<MessageDataItem<'static>>| {
                find(items, |i| match i { MessageDataItem::BodyStructure(bs) => Some(b::to_mime_tree(bs)), _ => None }).unwrap()
            };
            assert_tree_101(&tree(i101));
            assert_tree_102(&tree(&map[&nz(102)]));
            let i103 = &map[&nz(103)];
            let subj = find(i103, |i| match i { MessageDataItem::Envelope(e) => b::nstring(&e.subject), _ => None });
            assert_eq!(subj.as_deref(), Some(profiles::SUBJECT_103));
            assert_tree_103(&tree(i103));
            // imap-client appends UID to the item list even when it is already there.
            let cmd = srv.find_command("UID FETCH 1:*").unwrap();
            eprintln!("wire: {cmd}");
            assert!(cmd.starts_with("UID FETCH 1:* (UID FLAGS ENVELOPE BODYSTRUCTURE RFC822.SIZE INTERNALDATE"), "{cmd}");

            // FINDING: the mid-FETCH EXISTS is not observable through uid_fetch (only
            // tracing::debug!). A CollectTask sees it.
            let got = c
                .resolve(CollectTask::new(CommandBody::Fetch {
                    sequence_set: seq("1:*"),
                    macro_or_item_names: header_items(),
                    uid: true,
                    modifiers: vec![],
                }))
                .await?;
            assert!(got.ok());
            assert_eq!(got.data.iter().filter(|d| matches!(d, Data::Fetch { .. })).count(), 3);
            assert_eq!(got.data.iter().any(|d| matches!(d, Data::Exists(4))), injects_exists);
        }
        Ok(())
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// 5. Fetch a single MIME part
// ---------------------------------------------------------------------------------------------

fn peek(path: &[u32]) -> MessageDataItemName<'static> {
    let part = Part(Vec1::try_from(path.iter().map(|n| nz(*n)).collect::<Vec<_>>()).unwrap());
    MessageDataItemName::BodyExt { section: Some(Section::Part(part)), partial: None, peek: true }
}

#[tokio::test]
async fn r5_fetch_single_part() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut c = login(&srv).await?;
        c.select("INBOX").await?;
        for (section, path, expected) in [
            ("1.2", vec![1u32, 2], profiles::PART_101_1_2),
            ("2", vec![2], profiles::PART_101_2),
        ] {
            let map = c.uid_fetch(seq("101"), names(vec![peek(&path)])).await?;
            let data = find(&map[&nz(101)], |i| match i {
                MessageDataItem::BodyExt { data, .. } => b::nstring_bytes(data),
                _ => None,
            });
            assert_eq!(data.as_deref(), Some(expected.as_bytes()));
            assert!(srv.find_command(&format!("UID FETCH 101 (BODY.PEEK[{section}]")).is_some());
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn risk_tagged_no_on_fetch() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut c = login(&srv).await?;
        c.select("INBOX").await?;
        let err = c.uid_fetch(seq("101"), names(vec![peek(&[9])])).await.unwrap_err();
        assert!(matches!(err, ClientError::ResolveTask(TaskError::UnexpectedNoResponse(_))), "{err:?}");
        Ok(())
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// 6. IDLE
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r6_idle_receives_updates() -> TestResult {
    timed(async {
        // imap-client: idle() returns when something arrives, but the data is discarded.
        let srv = FakeServer::start(profiles::dovecot().rule(profiles::idle_with_updates())).await;
        let mut c = login(&srv).await?;
        c.select("INBOX").await?;
        let tag = c.enqueue_idle();
        c.idle(tag).await?; // Ok(()) and nothing else: EXISTS/EXPUNGE/FETCH are gone.
        assert!(srv.transcript().iter().any(|l| l == "DONE"));
        c.noop().await?;

        // imap-next directly: every response received while idling is returned.
        let mut n = NextConn::connect(srv.host(), srv.port()).await?;
        let (_, st) = n.run(CommandBody::login("alice", "secret")?).await?;
        assert_eq!(st.kind, StatusKind::Ok);
        n.run(CommandBody::select("INBOX")?).await?;
        let out = n.idle(3, Duration::from_secs(5)).await?;
        assert!(out.accepted && !out.stopped);
        assert!(matches!(out.data[0], Data::Exists(4)));
        assert!(matches!(out.data[1], Data::Expunge(n) if n.get() == 1));
        match &out.data[2] {
            Data::Fetch { seq, items } => {
                assert_eq!(seq.get(), 2);
                assert!(items.as_ref().contains(&MessageDataItem::Uid(nz(103))));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(out.completed.unwrap().kind, StatusKind::Ok);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn r6_idle_timeout_and_cancel() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot().first(profiles::idle_silent())).await;

        // imap-client: the idle timeout is a client setting; on expiry it sends DONE.
        let mut c = login(&srv).await?;
        c.select("INBOX").await?;
        c.state.set_idle_timeout(Duration::from_millis(200));
        let tag = c.enqueue_idle();
        c.idle(tag).await?;
        // Cancellation: drop the idle future, then finish with idle_done.
        let tag = c.enqueue_idle();
        tokio::select! {
            r = c.idle(tag.clone()) => panic!("idle ended early: {r:?}"),
            () = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        c.idle_done(tag).await?;
        c.noop().await?;

        // imap-next: timeout and external cancel both end in DONE + tagged OK.
        let mut n = NextConn::connect(srv.host(), srv.port()).await?;
        n.run(CommandBody::login("alice", "secret")?).await?;
        let out = n.idle(1, Duration::from_millis(200)).await?;
        assert!(out.stopped && out.data.is_empty());
        assert_eq!(out.completed.unwrap().kind, StatusKind::Ok);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = tx.send(());
        });
        let out = n.idle_until(1, async { let _ = rx.await; }).await?;
        assert!(out.stopped);
        assert_eq!(out.completed.unwrap().kind, StatusKind::Ok);
        assert_eq!(srv.transcript().iter().filter(|l| *l == "DONE").count(), 4);
        Ok(())
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// 7. CONDSTORE / QRESYNC
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r7_condstore_qresync() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut c = login(&srv).await?;
        // No QRESYNC variant in CapabilityEnable; it goes through Other.
        let enabled = c.enable([CapabilityEnable::try_from("QRESYNC")?]).await?;
        assert_eq!(enabled.map(|v| v.len()), Some(1));

        // SELECT ... (QRESYNC ...) is typed in imap-types but imap-client's select() cannot
        // send it, and SelectTask would drop VANISHED; CollectTask keeps everything.
        let sel = c
            .resolve(CollectTask::new(CommandBody::Select {
                mailbox: Mailbox::Inbox,
                parameters: vec![SelectParameter::QResync {
                    uid_validity: nz(1_700_000_000),
                    mod_sequence_value: NonZeroU64::new(4500).unwrap(),
                    known_uids: Some(seq("98:103")),
                    seq_match_data: None,
                }],
            }))
            .await?;
        assert!(sel.ok());
        assert!(sel.untagged.iter().any(|s| matches!(s.code, Some(Code::HighestModSeq(m)) if m.get() == 4521)));
        assert!(sel.data.iter().any(|d| matches!(d, Data::Vanished { earlier: true, known_uids } if *known_uids == seq("98:100"))));
        assert!(srv.find_command("SELECT INBOX (QRESYNC (1700000000 4500 98:103))").is_some());

        // UID FETCH with CHANGEDSINCE + VANISHED: modifiers are typed; MODSEQ is parsed;
        // VANISHED is dropped by the convenience method...
        let mods = vec![FetchModifier::ChangedSince(NonZeroU64::new(4500).unwrap()), FetchModifier::Vanished];
        let map = c.uid_fetch_with_modifiers(seq("1:*"), names(vec![MessageDataItemName::Flags]), mods.clone()).await?;
        let mut modseqs: Vec<_> = map
            .iter()
            .map(|(uid, items)| (uid.get(), find(items, |i| match i { MessageDataItem::ModSeq(m) => Some(m.get()), _ => None })))
            .collect();
        modseqs.sort();
        assert_eq!(modseqs, vec![(102, Some(4519)), (103, Some(4521))]);
        // ...and kept by CollectTask.
        let got = c
            .resolve(CollectTask::new(CommandBody::Fetch {
                sequence_set: seq("1:*"),
                macro_or_item_names: names(vec![MessageDataItemName::Flags]),
                uid: true,
                modifiers: mods,
            }))
            .await?;
        assert!(got.data.iter().any(|d| matches!(d, Data::Vanished { earlier: true, .. })));
        assert!(srv.find_command("(CHANGEDSINCE 4500 VANISHED)").is_some());
        Ok(())
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// 8. UIDPLUS, MOVE, STORE, APPEND
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r8_uidplus_move_store_append() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut c = login(&srv).await?;
        c.select("INBOX").await?;

        // APPEND with APPENDUID: typed. Dovecot advertises BINARY, so a literal8 (~{n}) is used.
        let got = c.appenduid("Sent", [Flag::Seen], APPEND_MSG).await?;
        assert_eq!(got, Some((nz(205), nz(1_700_000_001))));
        assert!(srv.find_command("Hello there.").unwrap().starts_with(r"APPEND Sent (\Seen) ~{"));

        // UID MOVE: uid_move() returns (); COPYUID (untagged OK) and EXPUNGE are dropped.
        c.uid_move(seq("102"), "Trash").await?;
        let mv = c
            .resolve(CollectTask::new(CommandBody::Move { sequence_set: seq("102"), mailbox: "Trash".try_into()?, uid: true }))
            .await?;
        let copyuid = mv.untagged.iter().find_map(|s| match &s.code {
            Some(Code::CopyUid { uid_validity, source, destination }) => Some((uid_validity.get(), uidset(source), uidset(destination))),
            _ => None,
        });
        assert_eq!(copyuid, Some((1_700_000_002, vec![102], vec![301])));
        assert!(mv.data.iter().any(|d| matches!(d, Data::Expunge(n) if n.get() == 2)));

        // UID COPY: COPYUID in the tagged OK; uid_copy() returns (), CollectTask keeps it.
        c.uid_copy(seq("101"), "Archive").await?;
        let cp = c
            .resolve(CollectTask::new(CommandBody::Copy { sequence_set: seq("101"), mailbox: "Archive".try_into()?, uid: true }))
            .await?;
        assert!(matches!(&cp.tagged.code, Some(Code::CopyUid { destination, .. }) if uidset(destination) == vec![501]));

        // UID STORE: FETCH results typed (with MODSEQ); the concurrent EXPUNGE is dropped...
        let st = c.uid_store(seq("102"), StoreType::Add, [Flag::Seen]).await?;
        assert_eq!(st.len(), 1);
        let items = st.values().next().unwrap();
        assert_eq!(find(items, |i| match i { MessageDataItem::ModSeq(m) => Some(m.get()), _ => None }), Some(4530));
        // ...and kept by CollectTask.
        let st = c
            .resolve(CollectTask::new(CommandBody::Store {
                sequence_set: seq("102"),
                kind: StoreType::Add,
                response: StoreResponse::Answer,
                flags: vec![Flag::Seen],
                uid: true,
                modifiers: vec![],
            }))
            .await?;
        assert!(st.data.iter().any(|d| matches!(d, Data::Expunge(n) if n.get() == 3)));

        // UID EXPUNGE: no convenience method (only EXPUNGE); the command body exists.
        let ex = c.resolve(CollectTask::new(CommandBody::ExpungeUid { sequence_set: seq("103") })).await?;
        assert!(ex.ok());
        assert_eq!(ex.data, vec![Data::Expunge(nz(3))]);
        Ok(())
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// 9. Gmail extensions
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r9_gmail_extensions() -> TestResult {
    timed(async {
        // Requesting: MessageDataItemName and SearchKey have no X-GM-* or raw/other variant,
        // and CommandBody has no raw variant, so `UID FETCH ... (X-GM-MSGID ...)` and
        // `UID SEARCH X-GM-RAW ...` cannot be expressed at all (checked against
        // imap-types 2.0.0-alpha.8 source).
        //
        // Parsing: imap-codec rejects a FETCH response that carries X-GM-* items.
        use imap_codec::{ResponseCodec, decode::Decoder};
        let line = b"* 1 FETCH (X-GM-THRID 1780000000000000101 X-GM-MSGID 1780000000000000101 X-GM-LABELS (\\Inbox) UID 101)\r\n";
        assert!(ResponseCodec::default().decode(line).is_err());
        let plain = b"* 1 FETCH (UID 101 FLAGS (\\Seen))\r\n";
        assert!(ResponseCodec::default().decode(plain).is_ok());
        // Capabilities with X-GM-EXT-1 parse fine (as Other).
        let caps = format!("* CAPABILITY {}\r\n", profiles::GMAIL_CAPS);
        assert!(ResponseCodec::default().decode(caps.as_bytes()).is_ok());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn risk_unexpected_fetch_item() -> TestResult {
    timed(async {
        // One FETCH line carries an item the parser does not know (X-GM-LABELS here). The
        // scheduler's "skip bad fetches" hack discards the whole line: message 102 silently
        // disappears from the result, with no error.
        let srv = FakeServer::start(profiles::gmail()).await;
        let mut c = login(&srv).await?;
        c.select("INBOX").await?;
        let map = c.uid_fetch(seq("1:*"), names(vec![MessageDataItemName::Flags])).await?;
        let mut uids: Vec<u32> = map.keys().map(|u| u.get()).collect();
        uids.sort();
        assert_eq!(uids, vec![101, 103], "102 was dropped silently");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn risk_unknown_fetch_item() -> TestResult {
    timed(async {
        // One FETCH line carries SAVEDATE, which imap-codec does not know: the whole line for
        // message 102 is dropped silently.
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut c = login(&srv).await?;
        c.select("INBOX").await?;
        let map = c.uid_fetch(seq("1:*"), names(vec![MessageDataItemName::Flags])).await?;
        let mut uids: Vec<u32> = map.keys().map(|u| u.get()).collect();
        uids.sort();
        assert_eq!(uids, vec![101, 103], "102 was dropped silently");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn risk_unsolicited_burst() -> TestResult {
    timed(async {
        let srv = FakeServer::start(
            profiles::dovecot().first(profiles::noop_burst(150)).first(profiles::noop_burst(150)),
        )
        .await;
        let mut c = login(&srv).await?;
        // noop(): all 150 unsolicited FETCHes are discarded (debug-logged only).
        c.noop().await?;
        // CollectTask: nothing is lost, nothing is bounded.
        let got = c.resolve(CollectTask::new(CommandBody::Noop)).await?;
        assert_eq!(got.data.len(), 150);
        Ok(())
    })
    .await
}
