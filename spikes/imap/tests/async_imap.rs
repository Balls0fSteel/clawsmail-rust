//! Candidate A: async-imap 0.12 (tokio) against the fake server.
//!
//! Test names match `tests/imap_client.rs` one to one: `rN_*` covers requirement N of the spike,
//! `risk_*` probes a behaviour that matters for a mail client.

mod common;

use std::collections::HashSet;
use std::time::Duration;

use async_imap::extensions::idle::IdleResponse;
use async_imap::imap_proto::{
    AttributeValue, MailboxDatum, NameAttribute, Response, ResponseCode, SectionPath,
};
use async_imap::types::{Fetch, Flag, UnsolicitedResponse};
use common::*;
use fake_imap::{Action, FakeServer, Rule, prefix, profiles};
use futures::TryStreamExt;
use imap_spike::cand_async_imap::{self as a, EmptyResponder, XOAuth2};

type Session = async_imap::Session<tokio::net::TcpStream>;

async fn login(srv: &FakeServer) -> Result<Session, Box<dyn std::error::Error + Send + Sync>> {
    let (client, _) = a::connect_plain(srv.host(), srv.port()).await?;
    client.login("alice", "secret").await.map_err(|(e, _)| e.into())
}

fn drain(session: &Session) -> Vec<UnsolicitedResponse> {
    let mut v = Vec::new();
    while let Ok(u) = session.unsolicited_responses.try_recv() {
        v.push(u);
    }
    v
}

fn attr_str(a: &NameAttribute<'_>) -> String {
    match a {
        NameAttribute::NoInferiors => "\\Noinferiors".into(),
        NameAttribute::NoSelect => "\\Noselect".into(),
        NameAttribute::Marked => "\\Marked".into(),
        NameAttribute::Unmarked => "\\Unmarked".into(),
        NameAttribute::All => "\\All".into(),
        NameAttribute::Archive => "\\Archive".into(),
        NameAttribute::Drafts => "\\Drafts".into(),
        NameAttribute::Flagged => "\\Flagged".into(),
        NameAttribute::Junk => "\\Junk".into(),
        NameAttribute::Sent => "\\Sent".into(),
        NameAttribute::Trash => "\\Trash".into(),
        NameAttribute::Extension(e) => e.to_string(),
        other => format!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// 1. TLS
// ---------------------------------------------------------------------------------------------

#[test]
fn r1_tls_config_builds_with_platform_verifier() {
    // Builds the real rustls config at runtime (no network): catches crypto-provider panics.
    let cfg = imap_spike::tls::client_config().expect("platform verifier config");
    assert_eq!(cfg.alpn_protocols, vec![b"imap".to_vec()]);
    // The TLS connect path is `a::connect_tls`; it type-checks as Client<TlsStream<TcpStream>>.
    let _f = a::connect_tls;
}

#[tokio::test]
#[ignore = "live network: connects to imap.gmail.com:993 and reads the greeting only"]
async fn r1_tls_live_gmail_greeting() -> TestResult {
    let mut client = a::connect_tls("imap.gmail.com", 993).await?;
    client.run_command_and_check_ok("CAPABILITY", None).await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// 2. Authentication
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r2_xoauth2_sasl_ir() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::gmail()).await;
        let (client, _) = a::connect_plain(srv.host(), srv.port()).await?;
        let mut r = EmptyResponder::default();
        let mut s = a::authenticate_xoauth2_ir(client, USER, TOKEN, &mut r).await.map_err(|(e, _)| e)?;
        let cmd = srv.find_command("AUTHENTICATE").unwrap();
        let ir = cmd.strip_prefix("AUTHENTICATE XOAUTH2 ").expect("one-line SASL-IR command");
        assert_eq!(b64_decode(ir), format!("user={USER}\x01auth=Bearer {TOKEN}\x01\x01"));
        assert!(!srv.transcript().iter().any(|l| l.starts_with("<cont>")), "no round trip");
        s.logout().await?;
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
        let (client, _) = a::connect_plain(srv.host(), srv.port()).await?;
        let mut r = EmptyResponder::default();
        let err = match a::authenticate_xoauth2_ir(client, USER, "expired", &mut r).await {
            Ok(_) => panic!("must fail"),
            Err((e, _client_back)) => e,
        };
        assert!(matches!(err, async_imap::error::Error::No(_)), "{err:?}");
        // The JSON error from the challenge is available for the UI / token refresh logic.
        assert!(r.last_challenge.unwrap().contains(r#""status":"400""#));
        // The client acknowledged the challenge with an empty line.
        assert!(srv.transcript().contains(&"<cont> ".to_string()), "{:?}", srv.transcript());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn r2_xoauth2_without_ir() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::gmail()).await;
        let (client, _) = a::connect_plain(srv.host(), srv.port()).await?;
        let mut auth = XOAuth2::new(USER, TOKEN);
        let _s = client.authenticate("XOAUTH2", &mut auth).await.map_err(|(e, _)| e)?;
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
        let (client, _) = a::connect_plain(srv.host(), srv.port()).await?;
        let _s = client.login("alice", r#"pa ss"w\d"#).await.map_err(|(e, _)| e)?;
        assert_eq!(srv.find_command("LOGIN").unwrap(), r#"LOGIN "alice" "pa ss\"w\\d""#);

        let (client, _) = a::connect_plain(srv.host(), srv.port()).await?;
        let _s = a::authenticate_plain_ir(client, "alice", "secret").await.map_err(|(e, _)| e)?;
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
            let mut s = login(&srv).await?;
            let names: Vec<_> = s.list(Some(""), Some("*")).await?.try_collect().await?;
            let role = |n: &async_imap::types::Name| {
                let attrs: Vec<String> = n.attributes().iter().map(attr_str).collect();
                special_use(attrs.iter().map(String::as_str))
            };
            let by_role = |r: &str| names.iter().find(|n| role(n) == Some(r)).map(|n| n.name().to_string());
            assert_eq!(by_role("sent").as_deref(), Some(sent));
            assert_eq!(by_role("trash").as_deref(), Some(trash));
            assert!(by_role("junk").is_some() && by_role("drafts").is_some());
            assert_eq!(names[0].delimiter(), Some("/"));
            if sent.starts_with("[Gmail]") {
                assert_eq!(by_role("important").as_deref(), Some("[Gmail]/Important"));
                let gm = names.iter().find(|n| n.name() == "[Gmail]").unwrap();
                assert!(gm.attributes().contains(&NameAttribute::NoSelect));
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
        let mut s = login(&srv).await?;
        let m = s.select("INBOX").await?;
        assert_eq!((m.exists, m.uid_validity, m.uid_next, m.highest_modseq), (3, Some(1_700_000_000), Some(104), Some(4521)));
        let m = s.examine("INBOX").await?;
        assert_eq!((m.uid_validity, m.highest_modseq), (Some(1_700_000_000), Some(4521)));
        // Gmail sends "* OK [HIGHESTMODSEQ n]" with no text after the code.
        let srv = FakeServer::start(profiles::gmail()).await;
        let mut s = login(&srv).await?;
        let m = s.select("INBOX").await?;
        assert_eq!((m.uid_validity, m.uid_next, m.highest_modseq), (Some(1_700_000_000), Some(104), Some(987_654)));
        Ok(())
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// 4. Header sync with BODYSTRUCTURE
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r4_uid_fetch_headers_bodystructure() -> TestResult {
    timed(async {
        for (profile, injects_exists) in [(profiles::dovecot(), true), (profiles::gmail(), false)] {
            let srv = FakeServer::start(profile).await;
            let mut s = login(&srv).await?;
            s.select("INBOX").await?;
            drain(&s);
            let fetches: Vec<Fetch> = s
                .uid_fetch("1:*", "(UID FLAGS ENVELOPE BODYSTRUCTURE RFC822.SIZE INTERNALDATE)")
                .await?
                .try_collect()
                .await?;
            assert_eq!(fetches.len(), 3);
            let f101 = fetches.iter().find(|f| f.uid == Some(101)).unwrap();
            assert_eq!(f101.size, Some(110_342));
            assert_eq!(f101.flags().collect::<Vec<_>>(), vec![Flag::Seen]);
            assert_eq!(f101.envelope().unwrap().subject.as_deref(), Some(&b"Quarterly report"[..]));
            assert!(f101.internal_date().is_some());
            assert_tree_101(&a::to_mime_tree(f101.bodystructure().unwrap()));
            let f102 = fetches.iter().find(|f| f.uid == Some(102)).unwrap();
            assert!(f102.flags().any(|f| f == Flag::Custom("$Forwarded".into())));
            assert_tree_102(&a::to_mime_tree(f102.bodystructure().unwrap()));
            let f103 = fetches.iter().find(|f| f.uid == Some(103)).unwrap();
            // Subject arrived as a literal split over several TCP writes.
            let subj = f103.envelope().unwrap().subject.as_deref().unwrap();
            assert_eq!(subj, profiles::SUBJECT_103.as_bytes());
            assert_tree_103(&a::to_mime_tree(f103.bodystructure().unwrap()));
            assert!(srv.find_command("UID FETCH 1:* (UID FLAGS ENVELOPE BODYSTRUCTURE RFC822.SIZE INTERNALDATE)").is_some());
            // The EXISTS the Dovecot profile injects mid-FETCH is delivered on the side channel.
            assert_eq!(drain(&s).contains(&UnsolicitedResponse::Exists(4)), injects_exists);
        }
        Ok(())
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// 5. Fetch a single MIME part
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r5_fetch_single_part() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut s = login(&srv).await?;
        s.select("INBOX").await?;
        for (section, path, expected) in [
            ("1.2", vec![1, 2], profiles::PART_101_1_2),
            ("2", vec![2], profiles::PART_101_2),
        ] {
            let f: Vec<Fetch> = s.uid_fetch("101", format!("(BODY.PEEK[{section}])")).await?.try_collect().await?;
            assert_eq!(f.len(), 1);
            let data = f[0].section(&SectionPath::Part(path, None)).expect("part data");
            assert_eq!(data, expected.as_bytes());
            assert!(srv.find_command(&format!("UID FETCH 101 (BODY.PEEK[{section}])")).is_some());
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn risk_tagged_no_on_fetch() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut s = login(&srv).await?;
        s.select("INBOX").await?;
        // FINDING: the typed stream ends at the tagged response without checking its status,
        // so a tagged NO looks exactly like "no messages".
        let f: Vec<Fetch> = s.uid_fetch("101", "(BODY.PEEK[9])").await?.try_collect().await?;
        assert!(f.is_empty(), "NO is swallowed: {f:?}");
        // Workaround: the raw path sees the status.
        let res = a::raw_command(&mut s, "UID FETCH 101 (BODY.PEEK[9])").await?;
        assert!(!res.ok());
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
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut s = login(&srv).await?;
        s.select("INBOX").await?;
        let mut idle = s.idle();
        idle.init().await?;
        let mut seen = Vec::new();
        for _ in 0..3 {
            let (fut, _stop) = idle.wait_with_timeout(Duration::from_secs(5));
            match fut.await? {
                IdleResponse::NewData(d) => seen.push(match d.parsed() {
                    Response::MailboxData(MailboxDatum::Exists(n)) => format!("EXISTS {n}"),
                    Response::Expunge(n) => format!("EXPUNGE {n}"),
                    Response::Fetch(n, attrs) => {
                        let uid = attrs.iter().find_map(|a| match a {
                            AttributeValue::Uid(u) => Some(*u),
                            _ => None,
                        });
                        format!("FETCH {n} uid={uid:?}")
                    }
                    other => format!("{other:?}"),
                }),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(seen, ["EXISTS 4", "EXPUNGE 1", "FETCH 2 uid=Some(103)"]);
        let mut s = idle.done().await?;
        assert!(srv.transcript().iter().any(|l| l == "DONE"));
        s.noop().await?; // the session is usable again
        Ok(())
    })
    .await
}

#[tokio::test]
async fn r6_idle_timeout_and_cancel() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot().first(profiles::idle_silent())).await;
        let mut s = login(&srv).await?;
        s.select("INBOX").await?;

        // Timeout.
        let mut idle = s.idle();
        idle.init().await?;
        let (fut, _stop) = idle.wait_with_timeout(Duration::from_millis(200));
        assert_eq!(fut.await?, IdleResponse::Timeout);
        let s = idle.done().await?;

        // Cancellation from elsewhere: dropping the StopSource interrupts the wait.
        let mut idle = s.idle();
        idle.init().await?;
        let (fut, stop) = idle.wait();
        let (res, ()) = tokio::join!(fut, async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(stop);
        });
        assert_eq!(res?, IdleResponse::ManualInterrupt);
        let mut s = idle.done().await?;
        s.noop().await?;
        assert_eq!(srv.transcript().iter().filter(|l| *l == "DONE").count(), 2);
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
        let mut s = login(&srv).await?;
        // No typed ENABLE; any command string works.
        let en = a::raw_command(&mut s, "ENABLE QRESYNC").await?;
        assert!(en.ok());

        // SELECT ... (QRESYNC ...) has no typed helper (only select_condstore); raw path.
        let sel = a::raw_command(&mut s, "SELECT INBOX (QRESYNC (1700000000 4500 98:103))").await?;
        assert!(sel.ok());
        assert!(sel.untagged_codes().contains(&ResponseCode::HighestModSeq(4521)));
        let vanished: Vec<_> = sel
            .untagged()
            .filter_map(|r| match r {
                Response::Vanished { earlier, uids } => Some((earlier, uids)),
                _ => None,
            })
            .collect();
        assert_eq!(vanished, vec![(true, vec![98..=100])]);
        assert!(sel.untagged().any(|r| matches!(r, Response::Fetch(2, ref a) if a.contains(&AttributeValue::ModSeq(4519)))));

        // Typed UID FETCH with modifiers in the query string; MODSEQ is parsed into Fetch,
        // VANISHED arrives on the unsolicited channel.
        drain(&s);
        let f: Vec<Fetch> = s.uid_fetch("1:*", "(FLAGS) (CHANGEDSINCE 4500 VANISHED)").await?.try_collect().await?;
        let modseqs: Vec<_> = f.iter().map(|f| (f.uid, f.modseq)).collect();
        assert_eq!(modseqs, vec![(Some(102), Some(4519)), (Some(103), Some(4521))]);
        let side = drain(&s);
        let v = side.iter().find_map(|u| match u {
            UnsolicitedResponse::Other(rd) => match rd.parsed() {
                Response::Vanished { earlier, uids } => Some((*earlier, uids.clone())),
                _ => None,
            },
            _ => None,
        });
        assert_eq!(v, Some((true, vec![98..=100])));
        assert!(srv.find_command("UID FETCH 1:* (FLAGS) (CHANGEDSINCE 4500 VANISHED)").is_some());

        // select_condstore exists as a typed helper.
        let m = s.select_condstore("INBOX").await?;
        assert_eq!(m.highest_modseq, Some(4521));
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
        let mut s = login(&srv).await?;
        s.select("INBOX").await?;
        drain(&s);

        // APPEND: the typed helper returns () and drops APPENDUID.
        s.append("Sent", Some(r"(\Seen)"), None, APPEND_MSG).await?;
        // Workaround: our own APPEND over the same session.
        let got = a::append_uid(&mut s, "Sent", r"\Seen", APPEND_MSG).await?;
        assert_eq!(got, Some((1_700_000_001, 205)));
        assert!(srv.find_command("Hello there.").unwrap().starts_with(r#"APPEND "Sent" (\Seen) {"#));

        // UID MOVE: typed helper returns (); COPYUID (untagged OK) and EXPUNGE go to the
        // unsolicited channel.
        s.uid_mv("102", "Trash").await?;
        let side = drain(&s);
        assert!(side.contains(&UnsolicitedResponse::Expunge(2)));
        assert!(side.iter().any(|u| matches!(u, UnsolicitedResponse::Other(rd)
            if matches!(rd.parsed(), Response::Data { outcome, .. } if matches!(outcome.code, Some(ResponseCode::CopyUid(1_700_000_002, _, _)))))));
        // Raw path gives it directly.
        let mv = a::raw_command(&mut s, "UID MOVE 102 Trash").await?;
        assert_eq!(a::copyuid(&mv), Some((1_700_000_002, vec![102], vec![301])));

        // UID COPY: COPYUID is in the tagged OK, which the typed helper discards; raw path.
        s.uid_copy("101", "Archive").await?;
        let cp = a::raw_command(&mut s, "UID COPY 101 Archive").await?;
        assert_eq!(a::copyuid(&cp), Some((1_700_000_003, vec![101], vec![501])));

        // UID STORE: FETCH results with MODSEQ; the concurrent EXPUNGE goes to the side channel.
        drain(&s);
        let f: Vec<Fetch> = s.uid_store("102", r"+FLAGS (\Seen)").await?.try_collect().await?;
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].uid, f[0].modseq), (Some(102), Some(4530)));
        assert!(f[0].flags().any(|x| x == Flag::Flagged));
        assert_eq!(drain(&s), vec![UnsolicitedResponse::Expunge(3)]);

        // UID EXPUNGE.
        let gone: Vec<u32> = s.uid_expunge("103").await?.try_collect().await?;
        assert_eq!(gone, vec![3]);
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
        let srv = FakeServer::start(profiles::gmail()).await;
        let mut s = login(&srv).await?;
        s.select("INBOX").await?;
        let f: Vec<Fetch> = s.uid_fetch("1:*", "(UID X-GM-MSGID X-GM-THRID X-GM-LABELS)").await?.try_collect().await?;
        let f101 = f.iter().find(|f| f.uid == Some(101)).unwrap();
        assert_eq!(f101.gmail_msg_id(), Some(&1_780_000_000_000_000_101));
        let labels: Vec<&str> = f101.gmail_labels().unwrap().iter().map(|c| c.as_ref()).collect();
        assert_eq!(labels, [r"\Inbox", r"\Important", "Work Stuff"]);
        // X-GM-THRID: parsed by imap-proto but no accessor on Fetch; read it on the raw path.
        let raw = a::raw_command(&mut s, "UID FETCH 1:* (UID X-GM-MSGID X-GM-THRID X-GM-LABELS)").await?;
        assert_eq!(a::gmail_thread_ids(&raw), vec![(101, 1_780_000_000_000_000_101), (102, 1_780_000_000_000_000_101)]);

        // X-GM-RAW search: the search string is passed through.
        let hits = s.uid_search(r#"X-GM-RAW "has:attachment in:inbox""#).await?;
        assert_eq!(hits, HashSet::from([101, 103]));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn risk_unexpected_fetch_item() -> TestResult {
    timed(async {
        // One FETCH line carries an item the client did not request (X-GM-LABELS here; known
        // to imap-proto, so this checks only that an unrequested item does no harm).
        let srv = FakeServer::start(profiles::gmail()).await;
        let mut s = login(&srv).await?;
        s.select("INBOX").await?;
        let f: Vec<Fetch> = s.uid_fetch("1:*", "(UID FLAGS)").await?.try_collect().await?;
        let uids: Vec<_> = f.iter().map(|f| f.uid).collect();
        assert_eq!(uids, vec![Some(101), Some(102), Some(103)], "no message lost");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn risk_unknown_fetch_item() -> TestResult {
    timed(async {
        // One FETCH line carries SAVEDATE, which imap-proto 0.17.0 does not know. It is
        // tolerated (parsed as AttributeValue::Unknown, value discarded); nothing is lost.
        let srv = FakeServer::start(profiles::dovecot()).await;
        let mut s = login(&srv).await?;
        s.select("INBOX").await?;
        let f: Vec<Fetch> = s.uid_fetch("1:*", "(UID FLAGS)").await?.try_collect().await?;
        let uids: Vec<_> = f.iter().map(|f| f.uid).collect();
        assert_eq!(uids, vec![Some(101), Some(102), Some(103)]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn risk_unsolicited_burst() -> TestResult {
    timed(async {
        let srv = FakeServer::start(profiles::dovecot().first(profiles::noop_burst(150))).await;
        let mut s = login(&srv).await?;
        s.noop().await?;
        // FINDING: the unsolicited channel is bounded(100) and uses try_send(..).ok(), so
        // responses beyond 100 that the application has not drained are silently dropped.
        assert_eq!(drain(&s).len(), 100);
        Ok(())
    })
    .await
}
