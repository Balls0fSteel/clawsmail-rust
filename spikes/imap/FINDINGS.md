# Spike A: choosing the IMAP library

2026-11-17_213205_1794947525

## Recommendation

**Use `async-imap` 0.12 (tokio runtime; parser `imap-proto` 0.17) for `cm-imap`**, wrapped in a thin layer of our own:
- a raw-command helper for the responses the typed methods drop;
- our own SASL-IR handling;
- our own reading of APPENDUID and COPYUID;
- a converter from BODYSTRUCTURE to a MIME tree.

All of these are in `src/cand_async_imap.rs` and pass the tests.

Why:
- **Requirements:** all nine work. Some need a workaround, but each one is small, local and covered by tests.
- **Gmail:** async-imap is the only candidate that handles Gmail natively. It requests and parses X-GM-MSGID,
  X-GM-THRID and X-GM-LABELS, and passes X-GM-RAW through.
- **Unknown FETCH items** (such as SAVEDATE) are tolerated: they become `AttributeValue::Unknown`, and the message is
  not lost.
- **Maintenance:** mature and widely used (about 2.35 M downloads), in the chatmail organisation, with commits this
  month.
- **The raw path makes gaps cheap:** any command can be sent, and its responses re-parsed with imap-proto.

**Candidate B (the duesee/pimalaya stack) is out:**
- `imap-client` was archived on 2026-05-17 and moved to `io-imap`.
- It cannot request or parse Gmail X-GM items.
- It silently drops a whole FETCH line that carries an item it does not know.

**Its successor `io-imap`** (probed as candidate C) is technically strong. But its repository was created in May 2026
and it has gone through 0.7 → 0.11 in six weeks. It is the runner-up: re-evaluate it at the end of M1.

## How this was tested

- **Fake server** (`fake-imap/`): a tokio TCP server that answers commands from scripted rules, matching on the
  command text after the tag. It records what the client sent, so tests can check the exact bytes on the wire.
- **Profiles:** Gmail-like and Dovecot-like, with real capability strings and special-use LIST attributes. They
  cover:
  - a nested multipart BODYSTRUCTURE with a message/rfc822 part;
  - literals split across TCP writes;
  - EXISTS arriving in the middle of a FETCH;
  - EXPUNGE arriving during STORE;
  - IDLE pushes and VANISHED (EARLIER);
  - the XOAUTH2 error challenge;
  - an unknown FETCH item.
- **Tests:** `tests/{async_imap,imap_client,io_imap}.rs` use the same test names: `rN_*` covers requirement N, and
  `risk_*` probes a risky behaviour. All three convert BODYSTRUCTURE to the same neutral `MimePart` tree
  (`src/mime.rs`) and are checked by the same assertions.
- **TLS:** `src/tls.rs` uses rustls with the `ring` provider (selected explicitly) and `rustls-platform-verifier`
  0.7, which reads the Windows certificate store; ALPN is `imap`. The ignored `r1_tls_live_gmail_greeting` tests ran
  once per candidate and passed. They connected to `imap.gmail.com:993` without credentials and read only the
  greeting and CAPABILITY.

```
(Get-Process -Id $PID).PriorityClass = 'Idle'; cargo test --workspace
  fake-imap unit tests        2 passed
  tests/async_imap.rs        18 passed, 1 ignored (live TLS)
  tests/imap_client.rs       18 passed, 1 ignored (live TLS)
  tests/io_imap.rs           10 passed, 1 ignored (live TLS)
```

## Requirement tables

**S** = supported by the API; **W** = works through a workaround in our code, shown in tests; **M** = missing;
*src* = judged from the source only.

### A: async-imap 0.12.0 + imap-proto 0.17.0

| # | Requirement | Status | Notes |
|---|---|---|---|
| 1 | TLS | S | `Client::new` takes any `AsyncRead + AsyncWrite`, so we supply the TLS stream and control the config, socket, proxies and timeouts. |
| 2 | XOAUTH2 with SASL-IR | W | No SASL-IR API, but `authenticate()` writes the mechanism verbatim, so `"XOAUTH2 <b64>"` produces a correct one-line command (checked on the wire). The error challenge is answered with an empty line; the NO becomes `Error::No`, and the decoded JSON is kept. Plain XOAUTH2 through the `Authenticator` trait is S. |
| 2 | LOGIN / PLAIN | S / W | PLAIN with SASL-IR uses the same mechanism-string trick. |
| 3 | LIST special-use; SELECT / EXAMINE | S | Typed `NameAttribute::{Sent, Trash, Junk, Drafts, All, Archive, Flagged}`. `Mailbox` carries `uid_validity`, `uid_next` and `highest_modseq`. |
| 4 | Header FETCH + BODYSTRUCTURE | S | Our converter (about 60 lines) gives part numbers, filename, encoding and size. Do not use imap-proto's `BodyStructParser`: it numbers sibling parts wrongly. |
| 5 | `BODY.PEEK[section]` | S | Returns the exact bytes. |
| 6 | IDLE | S | `idle().init()` then `wait_with_timeout()` returns EXISTS/EXPUNGE/FETCH. A timeout returns `Timeout`, dropping the `StopSource` returns `ManualInterrupt`, and `done()` gives the session back. |
| 7 | CONDSTORE / QRESYNC | W | ENABLE QRESYNC and `SELECT (QRESYNC …)` go through the raw path. `CHANGEDSINCE` works typed, but VANISHED lands on the lossy unsolicited channel, so resync commands must use the raw path. |
| 8 | APPEND + APPENDUID | W | `append()` returns `()`; our `append_uid()` returns `(uidvalidity, uid)`. |
| 8 | UID MOVE / COPY + COPYUID | W | MOVE's COPYUID reaches the unsolicited channel. COPY's is lost, so COPY uses the raw path. |
| 8 | UID STORE, UID EXPUNGE | S | Typed; MODSEQ parsed. |
| 9 | X-GM-MSGID / LABELS / RAW | S | `gmail_msg_id()`, `gmail_labels()`; `uid_search("X-GM-RAW …")`. |
| 9 | X-GM-THRID | W | Parsed but has no accessor; read through the raw path. |

Risks in A:
- **A tagged NO or BAD on typed `uid_fetch`/`fetch`/`uid_store` is swallowed** and looks like an empty result. Use the
  raw path where failure matters, such as body-part fetches.
- **The unsolicited channel is `bounded(100)` and fed with `try_send(..).ok()`.** Beyond 100 undrained responses,
  data is lost silently, VANISHED included. `cm-imap` must drain the channel after every command.
- **The workarounds rely on implementation details.** SASL-IR relies on the mechanism string not being validated
  (fallback: non-IR XOAUTH2). The raw path relies on `ResponseData::borrow_owner()`.
- **Whole responses are buffered** (up to 512 MiB). Use `BODY.PEEK[n]<offset.len>` for big parts.
- **A breaking release is coming:** main keeps the status in `Error::No` and `Error::Bad`, and fixes the APPEND
  continuation ordering and an IDLE panic. Pin the version and expect a small migration.

### B: imap-client 0.3.1 + imap-next 0.3.4 + imap-codec 2.0.0-alpha.10

| # | Requirement | Status | Notes |
|---|---|---|---|
| 1 | TLS | S (rigid) | The library builds its own config and socket; there is no connect timeout. |
| 2 | XOAUTH2 SASL-IR, LOGIN, PLAIN | S | The error-challenge JSON is only logged, not returned. |
| 3 | LIST, SELECT | S | |
| 4 | FETCH + BODYSTRUCTURE | S | Results come back as a HashMap (order lost). UID is sent twice. An EXISTS during FETCH is dropped. |
| 5 | `BODY.PEEK[section]` | S | |
| 6 | IDLE | W | `idle()` discards the data; it needs a loop written against imap-next. |
| 7 | CONDSTORE / QRESYNC | W | No QRESYNC on `enable()` or `select()`; VANISHED is dropped unless a `CollectTask` is used. |
| 8 | UIDPLUS, MOVE, STORE, APPEND | S/W | COPYUID and an EXPUNGE during STORE are dropped unless a `CollectTask` is used. |
| 9 | Gmail X-GM-* | **M** | Cannot be expressed, and a FETCH line containing X-GM items is rejected. Only a fork would fix this. |

Risks in B: a whole FETCH line is dropped silently on any unknown item; unsolicited data is dropped; there is no raw
escape hatch; the library calls `println!`.

### C (probe): io-imap 0.11.2

| # | Requirement | Status | Notes |
|---|---|---|---|
| 1 | TLS | S | I/O-free coroutines; our tokio pump takes any stream. |
| 2 | XOAUTH2 SASL-IR | S | The error JSON is returned. |
| 3 | LIST, SELECT | S | SELECT tested; LIST from source only. |
| 4 | FETCH + BODYSTRUCTURE | S | Results keyed by sequence number; an EXISTS during FETCH is dropped. |
| 5 | `BODY.PEEK[section]` | S | Streamed FETCH and APPEND exist (*src*). |
| 6 | IDLE | S/W | Data arrives in batches; cancel through our pump. |
| 7 | CONDSTORE / QRESYNC | S *src* | Includes a UID-diff fallback. |
| 8 | UIDPLUS, MOVE, STORE, APPEND | S *src* | |
| 9 | Gmail X-GM-* | W | Untyped. `raw()` returns a String. An unknown item goes to a raw partial, and the rest of the line is kept. |

## Maintenance (2026-11-17)

| Crate | Latest release | Activity | Downloads |
|---|---|---|---|
| async-imap | 0.12.0, 2026-09-30 | Last commit 2026-11-12; a breaking change is on main | 2.35 M |
| imap-proto | 0.17.0, 2026-09-28 | Last commit 2026-11-10 | 4.9 M |
| imap-client | 0.3.1, 2026-05-17 | **Archived**; moved to io-imap | 84 k |
| imap-next | 0.3.4, 2026-02-18 | Quiet since April | 95 k |
| imap-codec / imap-types | 2.0.0-alpha.10, 2026-11-02 | Active, **still alpha**; QRESYNC unfinished | 295 k |
| io-imap | 0.11.2, 2026-11-15 | Created 2026-05-17; 0.7 → 0.11 in six weeks | under 2 k per version |

## Licences

`cargo tree` lists 121 crates, all compatible with GPL-3.0-or-later.
- The candidates are MIT OR Apache-2.0; imap-client is MIT.
- Other licences in the tree: Apache-2.0, ISC, BSD-3-Clause, Unicode-3.0 and Unlicense OR MIT.
- `self_cell` is dual-licensed Apache-2.0 OR GPL-2.0-only; we use it under Apache-2.0.
- No `aws-lc-rs`, so no CMake or NASM is needed.

## Gmail without QRESYNC (fallback for requirement 7)

Gmail advertises CONDSTORE but not QRESYNC. Per folder:
1. `SELECT … (CONDSTORE)`. If UIDVALIDITY changed, drop the cache.
2. `UID SEARCH ALL` (or `UID FETCH 1:* (UID)`), and diff the result against the cache to find expunged messages.
3. `UID FETCH 1:* (FLAGS) (CHANGEDSINCE <stored modseq>)`. Without CONDSTORE, refetch the FLAGS of the cached range
   instead.
4. Fetch headers for `<old UIDNEXT>:*`.
5. Store the new HIGHESTMODSEQ.

X-GM-MSGID is a stable key, so a label change can be recognised as a move rather than a delete plus an add.

## Other notes for cm-imap

- No candidate has per-command timeouts. Wrap each command in `tokio::time::timeout`, and drop the connection when
  one fires.
- Give IDLE its own connection: each library allows only one command in flight.
- Keep `ring` as the only rustls provider, selected explicitly.
- The fake server does not cover STARTTLS, COMPRESS=DEFLATE, Outlook quirks, TLS, or very large literals.

## Layout

```
spikes/imap/
  Cargo.toml              standalone workspace; fake-imap is a member
  fake-imap/              scripted fake server, Gmail and Dovecot profiles
  src/mime.rs             neutral MIME tree
  src/tls.rs              rustls + platform verifier
  src/cand_async_imap.rs  A: SASL-IR, raw path, APPENDUID/COPYUID, THRID, BODYSTRUCTURE
  src/cand_imap_next.rs   B: CollectTask, imap-next IDLE loop
  src/cand_io_imap.rs     C: tokio pump, IDLE pump
  tests/                  one test file per candidate plus shared assertions
```
