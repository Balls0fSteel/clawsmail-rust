//! Realistic server personalities: a Gmail-like and a Dovecot-like scenario.
//!
//! The responses are modelled on transcripts of the real servers (capability strings, LIST
//! attributes, response-code placement, Gmail's missing text after `[HIGHESTMODSEQ n]`), but
//! all addresses, IDs and contents are made up.
//!
//! Mailbox model shared by both profiles: INBOX holds UIDs 101, 102, 103 at sequence numbers
//! 1, 2, 3. UIDNEXT is 104.
//!
//! * 101: multipart/mixed { multipart/alternative { text/plain, text/html }, application/pdf
//!   attachment, inline image/png with a Content-ID }. Part numbers 1.1, 1.2, 2, 3.
//! * 102: multipart/mixed { text/plain, message/rfc822 { multipart/alternative { text/plain,
//!   text/html } } }. Part numbers 1, 2, 2.1, 2.2.
//! * 103: a single text/plain part (part 1); its subject arrives as a literal.

use std::time::Duration;

use crate::{Action, Rule, Scenario, contains, exact, literal, prefix, without};

// ---------------------------------------------------------------------------------------------
// Shared message data
// ---------------------------------------------------------------------------------------------

pub const UIDVALIDITY: u32 = 1_700_000_000;

pub const BS_101: &str = r#"((("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "QUOTED-PRINTABLE" 1234 30 NIL NIL NIL NIL)("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "BASE64" 5678 74 NIL NIL NIL NIL) "ALTERNATIVE" ("BOUNDARY" "alt-b") NIL NIL NIL)("APPLICATION" "PDF" ("NAME" "report.pdf") NIL NIL "BASE64" 102400 NIL ("ATTACHMENT" ("FILENAME" "report.pdf")) NIL NIL)("IMAGE" "PNG" ("NAME" "logo.png") "<img1@example.com>" NIL "BASE64" 2048 NIL ("INLINE" ("FILENAME" "logo.png")) NIL NIL) "MIXED" ("BOUNDARY" "mix-b") NIL NIL NIL)"#;

pub const BS_102: &str = r#"(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 120 4 NIL NIL NIL NIL)("MESSAGE" "RFC822" ("NAME" "forwarded.eml") NIL NIL "7BIT" 3000 ("Mon, 9 Nov 2026 10:00:00 +0100" "Original subject" (("Bob" NIL "bob" "example.org")) (("Bob" NIL "bob" "example.org")) (("Bob" NIL "bob" "example.org")) (("Alice" NIL "alice" "example.com")) NIL NIL NIL "<inner@example.org>") (("TEXT" "PLAIN" ("CHARSET" "us-ascii") NIL NIL "7BIT" 100 3 NIL NIL NIL NIL)("TEXT" "HTML" ("CHARSET" "us-ascii") NIL NIL "7BIT" 200 5 NIL NIL NIL NIL) "ALTERNATIVE" ("BOUNDARY" "inner-b") NIL NIL NIL) 60 NIL ("ATTACHMENT" ("FILENAME" "forwarded.eml")) NIL NIL) "MIXED" ("BOUNDARY" "outer-b") NIL NIL NIL)"#;

pub const BS_103: &str = r#"("TEXT" "PLAIN" ("CHARSET" "iso-8859-2" "FORMAT" "flowed") NIL NIL "8BIT" 512 12 NIL NIL NIL NIL)"#;

const ENV_101: &str = r#"("Tue, 17 Nov 2026 09:15:00 +0100" "Quarterly report" (("Alice Example" NIL "alice" "example.com")) (("Alice Example" NIL "alice" "example.com")) (("Alice Example" NIL "alice" "example.com")) (("Me" NIL "me" "example.net")) NIL NIL NIL "<msg101@example.com>")"#;
const ENV_102: &str = r#"("Tue, 17 Nov 2026 10:00:00 +0100" "Fwd: Original subject" (("Carol" NIL "carol" "example.com")) (("Carol" NIL "carol" "example.com")) (("Carol" NIL "carol" "example.com")) (("Me" NIL "me" "example.net")) (("Dave" NIL "dave" "example.com")) NIL "<msg101@example.com>" "<msg102@example.com>")"#;

/// Subject of 103, sent as a literal because it contains double quotes.
pub const SUBJECT_103: &str = r#"=?utf-8?Q?=C3=81rv=C3=ADzt=C5=B1r=C5=91?= "quoted" words"#;

fn env_103() -> String {
    format!(
        r#"("Tue, 17 Nov 2026 11:30:00 +0100" {} (("Erzsi" NIL "erzsi" "example.hu")) (("Erzsi" NIL "erzsi" "example.hu")) (("Erzsi" NIL "erzsi" "example.hu")) (("Me" NIL "me" "example.net")) NIL NIL NIL "<msg103@example.hu>")"#,
        literal(SUBJECT_103)
    )
}

/// Body of part 1.2 of UID 101 (text/html, base64), as sent on the wire.
pub const PART_101_1_2: &str = "PGh0bWw+PGJvZHk+PHA+SGVsbG8gPGI+d29ybGQ8L2I+PC9wPjwvYm9keT48L2h0bWw+";
/// Body of part 2 of UID 101 (application/pdf, base64), two lines with an inner CRLF.
pub const PART_101_2: &str = "JVBERi0xLjQKJWZha2UgcGRmIGZvciB0ZXN0cwo=\r\nAAECAwQFBgcICQ==";

pub const XOAUTH2_ERROR_CHALLENGE: &str =
    "eyJzdGF0dXMiOiI0MDAiLCJzY2hlbWVzIjoiQmVhcmVyIiwic2NvcGUiOiJodHRwczovL21haWwuZ29vZ2xlLmNvbS8ifQ==";

fn header_fetch_lines_dovecot() -> Vec<Action> {
    vec![
        Action::Line(format!(
            r#"* 1 FETCH (UID 101 FLAGS (\Seen) INTERNALDATE "17-Nov-2026 09:15:02 +0100" RFC822.SIZE 110342 ENVELOPE {ENV_101} BODYSTRUCTURE {BS_101})"#
        )),
        Action::Line(format!(
            r#"* 2 FETCH (UID 102 FLAGS (\Seen \Flagged $Forwarded) INTERNALDATE "17-Nov-2026 10:00:05 +0100" RFC822.SIZE 4210 ENVELOPE {ENV_102} BODYSTRUCTURE {BS_102})"#
        )),
        // A new message arrives while the command runs; allowed during UID FETCH.
        Action::Line("* 4 EXISTS".into()),
        // Split into small TCP writes so the literal straddles reads.
        Action::Chunked(
            format!(
                r#"* 3 FETCH (UID 103 FLAGS () INTERNALDATE "17-Nov-2026 11:30:09 +0100" RFC822.SIZE 1650 ENVELOPE {} BODYSTRUCTURE {BS_103})"#,
                env_103()
            ),
            7,
        ),
        Action::Line("{tag} OK Fetch completed (0.002 + 0.000 secs).".into()),
    ]
}

fn header_fetch_lines_gmail() -> Vec<Action> {
    vec![
        Action::Line(format!(
            r#"* 1 FETCH (UID 101 RFC822.SIZE 110342 INTERNALDATE "17-Nov-2026 08:15:02 +0000" FLAGS (\Seen) ENVELOPE {ENV_101} BODYSTRUCTURE {BS_101})"#
        )),
        Action::Line(format!(
            r#"* 2 FETCH (UID 102 RFC822.SIZE 4210 INTERNALDATE "17-Nov-2026 09:00:05 +0000" FLAGS (\Seen \Flagged $Forwarded) ENVELOPE {ENV_102} BODYSTRUCTURE {BS_102})"#
        )),
        Action::Chunked(
            format!(
                r#"* 3 FETCH (UID 103 RFC822.SIZE 1650 INTERNALDATE "17-Nov-2026 10:30:09 +0000" FLAGS () ENVELOPE {} BODYSTRUCTURE {BS_103})"#,
                env_103()
            ),
            7,
        ),
        Action::Line("{tag} OK Success".into()),
    ]
}

fn part_fetch_rules() -> Vec<Rule> {
    vec![
        Rule::new(
            contains(&["UID FETCH 101", "BODY.PEEK[1.2]"]),
            vec![
                Action::Chunked(format!("* 1 FETCH (UID 101 BODY[1.2] {})", literal(PART_101_1_2)), 5),
                Action::Line("{tag} OK Fetch completed.".into()),
            ],
        ),
        Rule::new(
            contains(&["UID FETCH 101", "BODY.PEEK[2]"]),
            vec![
                Action::Line(format!("* 1 FETCH (UID 101 BODY[2] {})", literal(PART_101_2))),
                Action::Line("{tag} OK Fetch completed.".into()),
            ],
        ),
    ]
}

fn uidplus_rules() -> Vec<Rule> {
    vec![
        Rule::lines(contains(&["APPEND"]), &["{tag} OK [APPENDUID 1700000001 205] Append completed."]),
        // RFC 6851: COPYUID arrives in an untagged OK before the EXPUNGEs.
        Rule::lines(
            contains(&["UID MOVE"]),
            &["* OK [COPYUID 1700000002 102 301] Moved UIDs.", "* 2 EXPUNGE", "{tag} OK Move completed."],
        ),
        Rule::lines(contains(&["UID COPY"]), &["{tag} OK [COPYUID 1700000003 101 501] Copy completed."]),
        Rule::lines(contains(&["UID EXPUNGE"]), &["* 3 EXPUNGE", "{tag} OK Expunge completed."]),
        // Another client expunges 103 while our STORE runs; the server reports it.
        Rule::lines(
            contains(&["UID STORE", "+FLAGS"]),
            &[r"* 2 FETCH (UID 102 FLAGS (\Seen \Flagged $Forwarded) MODSEQ (4530))", "* 3 EXPUNGE", "{tag} OK Store completed."],
        ),
    ]
}

/// IDLE that pushes EXISTS, EXPUNGE and FETCH, then waits for DONE.
pub fn idle_with_updates() -> Rule {
    Rule::new(
        exact("IDLE"),
        vec![
            Action::Line("+ idling".into()),
            Action::Sleep(Duration::from_millis(100)),
            Action::Line("* 4 EXISTS".into()),
            Action::Line("* 1 EXPUNGE".into()),
            Action::Line(r"* 2 FETCH (FLAGS (\Seen) UID 103)".into()),
            Action::WaitFor("DONE".into()),
            Action::Line("{tag} OK Idle completed (0.001 + 0.100 secs).".into()),
        ],
    )
    .once()
}

/// IDLE where nothing happens; the client must time out or cancel and send DONE.
pub fn idle_silent() -> Rule {
    // (no updates are pushed)
    Rule::new(
        exact("IDLE"),
        vec![
            Action::Line("+ idling".into()),
            Action::WaitFor("DONE".into()),
            Action::Line("{tag} OK Idle completed (0.001 + 0.300 secs).".into()),
        ],
    )
}

// ---------------------------------------------------------------------------------------------
// Dovecot
// ---------------------------------------------------------------------------------------------

pub const DOVECOT_CAPS: &str = "IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY PREVIEW STATUS=SIZE SAVEDATE LITERAL+ NOTIFY SPECIAL-USE";

const DOVECOT_SELECT_HEAD: &[&str] = &[
    r"* FLAGS (\Answered \Flagged \Deleted \Seen \Draft $Forwarded)",
    r"* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft $Forwarded \*)] Flags permitted.",
    "* 3 EXISTS",
    "* 0 RECENT",
    "* OK [UNSEEN 3] First unseen.",
    "* OK [UIDVALIDITY 1700000000] UIDs valid",
    "* OK [UIDNEXT 104] Predicted next UID",
    "* OK [HIGHESTMODSEQ 4521] Highest",
];

fn dovecot_select(tail: &[&str], done: &str) -> Vec<Action> {
    DOVECOT_SELECT_HEAD
        .iter()
        .chain(tail.iter())
        .map(|l| Action::Line((*l).to_string()))
        .chain(std::iter::once(Action::Line(done.to_string())))
        .collect()
}

pub fn dovecot() -> Scenario {
    let greeting = "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] Dovecot ready.";
    let mut sc = Scenario::new(greeting)
        .rule(Rule::lines(
            exact("CAPABILITY"),
            &[&format!("* CAPABILITY {DOVECOT_CAPS}"), "{tag} OK Capability completed."],
        ))
        .rule(Rule::lines(
            prefix("LOGIN"),
            &[&format!("{{tag}} OK [CAPABILITY {DOVECOT_CAPS}] Logged in")],
        ))
        .rule(Rule::lines(
            prefix("AUTHENTICATE PLAIN "),
            &[&format!("{{tag}} OK [CAPABILITY {DOVECOT_CAPS}] Logged in")],
        ))
        .rule(Rule::new(
            exact("AUTHENTICATE PLAIN"),
            vec![
                Action::Continue(String::new()),
                Action::Line(format!("{{tag}} OK [CAPABILITY {DOVECOT_CAPS}] Logged in")),
            ],
        ))
        .rule(Rule::lines(contains(&["ENABLE", "QRESYNC"]), &["* ENABLED QRESYNC", "{tag} OK Enabled."]))
        .rule(Rule::lines(contains(&["ENABLE", "CONDSTORE"]), &["* ENABLED CONDSTORE", "{tag} OK Enabled."]))
        .rule(Rule::lines(
            prefix("LIST"),
            &[
                r#"* LIST (\HasNoChildren) "/" INBOX"#,
                r#"* LIST (\HasNoChildren \Drafts) "/" Drafts"#,
                r#"* LIST (\HasNoChildren \Sent) "/" Sent"#,
                r#"* LIST (\HasNoChildren \Junk) "/" Junk"#,
                r#"* LIST (\HasNoChildren \Trash) "/" Trash"#,
                r#"* LIST (\HasChildren) "/" Archive"#,
                r#"* LIST (\HasNoChildren \Archive) "/" "Archive/2025""#,
                "{tag} OK List completed (0.001 + 0.000 secs).",
            ],
        ))
        // SELECT with QRESYNC: VANISHED (EARLIER) and changed FETCHes before the tagged OK.
        .rule(Rule::new(
            contains(&["SELECT", "QRESYNC"]),
            dovecot_select(
                &["* VANISHED (EARLIER) 98:100", r"* 2 FETCH (UID 102 FLAGS (\Seen \Flagged) MODSEQ (4519))"],
                "{tag} OK [READ-WRITE] Select completed (0.001 + 0.000 secs).",
            ),
        ))
        .rule(Rule::new(prefix("SELECT"), dovecot_select(&[], "{tag} OK [READ-WRITE] Select completed (0.001 + 0.000 secs).")))
        .rule(Rule::new(prefix("EXAMINE"), dovecot_select(&[], "{tag} OK [READ-ONLY] Examine completed (0.001 + 0.000 secs).")))
        .rule(Rule::lines(
            contains(&["UID FETCH", "CHANGEDSINCE"]),
            &[
                "* VANISHED (EARLIER) 98:100",
                r"* 2 FETCH (UID 102 FLAGS (\Seen \Flagged) MODSEQ (4519))",
                "* 3 FETCH (UID 103 FLAGS () MODSEQ (4521))",
                "{tag} OK Fetch completed (0.001 + 0.000 secs).",
            ],
        ));
    // A flags sync where one FETCH line carries SAVEDATE (RFC 8514), an item none of the
    // parsers under test knows. Simulated: a server only sends it when asked.
    sc = sc.rule(Rule::lines(
        without(without(contains(&["UID FETCH", "1:*", "FLAGS"]), "BODYSTRUCTURE"), "CHANGEDSINCE"),
        &[
            r"* 1 FETCH (UID 101 FLAGS (\Seen))",
            r#"* 2 FETCH (UID 102 FLAGS () SAVEDATE "17-Nov-2026 10:00:05 +0100")"#,
            r"* 3 FETCH (UID 103 FLAGS ())",
            "{tag} OK Fetch completed (0.001 + 0.000 secs).",
        ],
    ));
    for r in part_fetch_rules() {
        sc = sc.rule(r);
    }
    sc = sc.rule(Rule::new(contains(&["UID FETCH", "BODYSTRUCTURE"]), header_fetch_lines_dovecot()));
    // A command that fails: used to check that a tagged NO surfaces as an error.
    sc = sc.rule(Rule::lines(
        contains(&["UID FETCH 101", "BODY.PEEK[9]"]),
        &["{tag} NO [SERVERBUG] Internal error occurred. Refer to server log for more information."],
    ));
    for r in uidplus_rules() {
        sc = sc.rule(r);
    }
    sc.rule(idle_with_updates()).with_defaults()
}

// ---------------------------------------------------------------------------------------------
// Gmail
// ---------------------------------------------------------------------------------------------

pub const GMAIL_PREAUTH_CAPS: &str = "IMAP4rev1 UNSELECT IDLE NAMESPACE QUOTA ID XLIST CHILDREN X-GM-EXT-1 XYZZY SASL-IR AUTH=XOAUTH2 AUTH=PLAIN AUTH=PLAIN-CLIENTTOKEN AUTH=OAUTHBEARER";
pub const GMAIL_CAPS: &str = "IMAP4rev1 UNSELECT IDLE NAMESPACE QUOTA ID XLIST CHILDREN X-GM-EXT-1 UIDPLUS COMPRESS=DEFLATE ENABLE MOVE CONDSTORE ESEARCH UTF8=ACCEPT LIST-EXTENDED LIST-STATUS LITERAL- SPECIAL-USE APPENDLIMIT=35651584";

const GMAIL_SELECT: &[&str] = &[
    r"* FLAGS (\Answered \Flagged \Draft \Deleted \Seen $NotPhishing $Phishing)",
    r"* OK [PERMANENTFLAGS (\Answered \Flagged \Draft \Deleted \Seen $NotPhishing $Phishing \*)] Flags permitted.",
    "* OK [UIDVALIDITY 1700000000] UIDs valid.",
    "* 3 EXISTS",
    "* 0 RECENT",
    "* OK [UIDNEXT 104] Predicted next UID.",
    // Gmail really omits the text after this response code.
    "* OK [HIGHESTMODSEQ 987654]",
];

fn gmail_select(done: &str) -> Vec<Action> {
    GMAIL_SELECT
        .iter()
        .map(|l| Action::Line((*l).to_string()))
        .chain(std::iter::once(Action::Line(done.to_string())))
        .collect()
}

pub fn gmail() -> Scenario {
    let greeting = "* OK Gimap ready for requests from 192.0.2.10 a1b2c3d4e5f6mb12345678abc";
    let auth_ok = [format!("* CAPABILITY {GMAIL_CAPS}"), "{tag} OK user@gmail.com authenticated (Success)".to_string()];
    let mut sc = Scenario::new(greeting)
        .rule(Rule::lines(
            exact("CAPABILITY"),
            &[&format!("* CAPABILITY {GMAIL_PREAUTH_CAPS}"), "{tag} OK Thats all she wrote! a1b2c3d4e5f6"],
        ))
        .rule(Rule::lines(prefix("AUTHENTICATE XOAUTH2 "), &[&auth_ok[0], &auth_ok[1]]))
        .rule(Rule::new(
            exact("AUTHENTICATE XOAUTH2"),
            vec![Action::Continue(String::new()), Action::Line(auth_ok[0].clone()), Action::Line(auth_ok[1].clone())],
        ))
        .rule(Rule::lines(prefix("AUTHENTICATE PLAIN "), &[&auth_ok[0], &auth_ok[1]]))
        .rule(Rule::lines(prefix("LOGIN"), &[&auth_ok[0], &auth_ok[1]]))
        .rule(Rule::lines(contains(&["ENABLE", "CONDSTORE"]), &["* ENABLED CONDSTORE", "{tag} OK Success"]))
        .rule(Rule::lines(
            prefix("LIST"),
            &[
                r#"* LIST (\HasNoChildren) "/" "INBOX""#,
                r#"* LIST (\HasChildren \Noselect) "/" "[Gmail]""#,
                r#"* LIST (\All \HasNoChildren) "/" "[Gmail]/All Mail""#,
                r#"* LIST (\Drafts \HasNoChildren) "/" "[Gmail]/Drafts""#,
                r#"* LIST (\HasNoChildren \Important) "/" "[Gmail]/Important""#,
                r#"* LIST (\HasNoChildren \Sent) "/" "[Gmail]/Sent Mail""#,
                r#"* LIST (\HasNoChildren \Junk) "/" "[Gmail]/Spam""#,
                r#"* LIST (\Flagged \HasNoChildren) "/" "[Gmail]/Starred""#,
                r#"* LIST (\HasNoChildren \Trash) "/" "[Gmail]/Trash""#,
                "{tag} OK Success",
            ],
        ))
        .rule(Rule::new(prefix("SELECT"), gmail_select("{tag} OK [READ-WRITE] INBOX selected. (Success)")))
        .rule(Rule::new(prefix("EXAMINE"), gmail_select("{tag} OK [READ-ONLY] INBOX selected. (Success)")))
        .rule(Rule::lines(
            contains(&["UID FETCH", "X-GM-MSGID"]),
            &[
                r#"* 1 FETCH (X-GM-THRID 1780000000000000101 X-GM-MSGID 1780000000000000101 X-GM-LABELS (\Inbox \Important "Work Stuff") UID 101)"#,
                r#"* 2 FETCH (X-GM-THRID 1780000000000000101 X-GM-MSGID 1780000000000000102 X-GM-LABELS (\Sent) UID 102)"#,
                "{tag} OK Success",
            ],
        ))
        .rule(Rule::lines(
            contains(&["UID SEARCH", "X-GM-RAW"]),
            &["* SEARCH 101 103", "{tag} OK SEARCH completed (Success)"],
        ))
        // A flags sync where one FETCH line carries an extension item the client did not ask
        // for. Used to show how each parser copes with an unknown FETCH item.
        .rule(Rule::lines(
            without(contains(&["UID FETCH", "1:*", "FLAGS"]), "BODYSTRUCTURE"),
            &[
                r"* 1 FETCH (UID 101 FLAGS (\Seen))",
                r"* 2 FETCH (X-GM-LABELS (\Inbox) UID 102 FLAGS ())",
                r"* 3 FETCH (UID 103 FLAGS ())",
                "{tag} OK Success",
            ],
        ));
    for r in part_fetch_rules() {
        sc = sc.rule(r);
    }
    sc = sc.rule(Rule::new(contains(&["UID FETCH", "BODYSTRUCTURE"]), header_fetch_lines_gmail()));
    for r in uidplus_rules() {
        sc = sc.rule(r);
    }
    sc.rule(idle_with_updates()).with_defaults()
}

/// A NOOP whose reply carries `n` unsolicited FETCH responses, to probe how a client buffers
/// unilateral data.
pub fn noop_burst(n: u32) -> Rule {
    let mut actions: Vec<Action> = (1..=n)
        .map(|i| Action::Line(format!(r"* {i} FETCH (FLAGS (\Seen))")))
        .collect();
    actions.push(Action::Line("{tag} OK NOOP completed.".into()));
    Rule::new(exact("NOOP"), actions).once()
}
