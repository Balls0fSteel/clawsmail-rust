//! Manual test CLI for real Google and Microsoft accounts.
//!
//! This is the only code path that opens the system browser. The automated
//! tests never run it.

use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use oauth_spike::{ClientConfig, LoginOptions, Provider, ProviderKind, TokenSet};

const USAGE: &str = "\
oauth-spike: try the Clawsmail OAuth flow against a real provider

USAGE:
  oauth-spike login   --provider google|microsoft [options] [--save]
  oauth-spike refresh --provider google|microsoft --account EMAIL [options]
  oauth-spike forget  --account EMAIL

OPTIONS:
  --client-id ID        overrides the build-time CM_GOOGLE_CLIENT_ID / CM_MS_CLIENT_ID
  --client-secret S     overrides CM_GOOGLE_CLIENT_SECRET (Google Desktop clients)
  --tenant T            Microsoft tenant: common (default), consumers, organizations or an ID
  --login-hint EMAIL    pre-fills the account on the provider's sign-in page
  --timeout SECS        how long to wait for the browser (default 300)
  --save                store the refresh token (Credential Manager, DPAPI file fallback)
  --print-xoauth2       print the base64 XOAUTH2 string (it contains the access token)

Stored tokens use the Credential Manager service name `clawsmail-rust-spike`.";

const SERVICE: &str = "clawsmail-rust-spike";

#[derive(Default)]
struct Args {
    command: String,
    provider: Option<ProviderKind>,
    client_id: Option<String>,
    client_secret: Option<String>,
    tenant: Option<String>,
    login_hint: Option<String>,
    account: Option<String>,
    timeout: u64,
    save: bool,
    print_xoauth2: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let mut a = Args {
        command: match it.next().ok_or("missing command")?.as_str() {
            "-h" | "--help" | "help" => return Err(String::new()),
            c => c.to_owned(),
        },
        timeout: 300,
        ..Args::default()
    };
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--provider" => a.provider = Some(value()?.parse()?),
            "--client-id" => a.client_id = Some(value()?),
            "--client-secret" => a.client_secret = Some(value()?),
            "--tenant" => a.tenant = Some(value()?),
            "--login-hint" => a.login_hint = Some(value()?),
            "--account" => a.account = Some(value()?),
            "--timeout" => a.timeout = value()?.parse().map_err(|e| format!("--timeout: {e}"))?,
            "--save" => a.save = true,
            "--print-xoauth2" => a.print_xoauth2 = true,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(a)
}

fn provider_for(a: &Args) -> Result<(Provider, ClientConfig), Box<dyn std::error::Error>> {
    let kind = a.provider.ok_or("--provider is required")?;
    let provider = match (kind, &a.tenant) {
        (ProviderKind::Microsoft, Some(t)) => Provider::microsoft(t),
        _ => Provider::preset(kind),
    };
    let client = ClientConfig::resolve(kind, a.client_id.as_deref(), a.client_secret.as_deref())?;
    Ok((provider, client))
}

fn report(tokens: &TokenSet, account: &str, print_xoauth2: bool) {
    let left = tokens
        .expires_at
        .duration_since(SystemTime::now())
        .unwrap_or_default()
        .as_secs();
    println!("account:        {account}");
    println!(
        "access token:   {} bytes, expires in {left} s",
        tokens.access_token.len()
    );
    match &tokens.refresh_token {
        Some(t) => println!("refresh token:  {} bytes", t.len()),
        None => println!("refresh token:  none returned"),
    }
    println!(
        "granted scope:  {}",
        tokens.scope.as_deref().unwrap_or("(not reported)")
    );
    let x = tokens.xoauth2(account);
    if print_xoauth2 {
        println!("XOAUTH2:        {x}");
    } else {
        println!(
            "XOAUTH2:        {} bytes (use --print-xoauth2 to show)",
            x.len()
        );
    }
}

#[cfg(windows)]
fn token_store() -> oauth_spike::Result<oauth_spike::store::TokenStore> {
    oauth_spike::store::TokenStore::new(
        SERVICE,
        oauth_spike::store::TokenStore::default_fallback_dir(),
    )
}

async fn run(a: Args) -> Result<(), Box<dyn std::error::Error>> {
    let http = oauth_spike::http_client();
    match a.command.as_str() {
        "login" => {
            let (provider, client) = provider_for(&a)?;
            let options = LoginOptions {
                login_hint: a.login_hint.clone(),
                timeout: Duration::from_secs(a.timeout),
            };
            let tokens = oauth_spike::login(&http, &provider, &client, &options, |url| {
                eprintln!("Opening the browser. If nothing happens, open this URL:\n{url}\n");
                webbrowser::open(url.as_str())
                    .map_err(|e| oauth_spike::Error::Browser(e.to_string()))
            })
            .await?;
            let account = tokens
                .email
                .clone()
                .or(a.login_hint.clone())
                .ok_or("the provider returned no email; pass --login-hint")?;
            report(&tokens, &account, a.print_xoauth2);
            if a.save {
                #[cfg(windows)]
                {
                    let rt = tokens
                        .refresh_token
                        .as_deref()
                        .ok_or("no refresh token to save")?;
                    let backend = token_store()?.save(&account, rt)?;
                    println!("saved refresh token: {backend:?}");
                }
                #[cfg(not(windows))]
                return Err("--save is only implemented on Windows in this spike".into());
            }
        }
        #[cfg(windows)]
        "refresh" => {
            let (provider, client) = provider_for(&a)?;
            let account = a.account.clone().ok_or("--account is required")?;
            let store = token_store()?;
            let (rt, backend) = store
                .load(&account)?
                .ok_or("no stored token for that account")?;
            println!("loaded refresh token from {backend:?}");
            let old = TokenSet {
                access_token: String::new(),
                refresh_token: Some(rt.clone()),
                expires_at: SystemTime::UNIX_EPOCH,
                scope: None,
                email: Some(account.clone()),
            };
            let tokens = oauth_spike::refresh(&http, &provider, &client, &old).await?;
            report(&tokens, &account, a.print_xoauth2);
            if let Some(new_rt) = tokens.refresh_token.as_deref().filter(|t| *t != rt) {
                println!(
                    "refresh token rotated; saved to {:?}",
                    store.save(&account, new_rt)?
                );
            }
        }
        #[cfg(windows)]
        "forget" => {
            let account = a.account.clone().ok_or("--account is required")?;
            token_store()?.delete(&account)?;
            println!("deleted stored token for {account}");
        }
        other => return Err(format!("unknown command {other}\n\n{USAGE}").into()),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}\n");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
