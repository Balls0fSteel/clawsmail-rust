# OAuth client setup for maintainers

Clawsmail signs in to Gmail and Microsoft mailboxes with OAuth 2.0: the authorization-code flow with PKCE and a
loopback redirect (`http://127.0.0.1:<port>` for Google, `http://localhost:<port>` for Microsoft). Each provider
needs one app registration owned by the maintainer. The resulting IDs are passed in at build time and are **never
committed**. The repository is public, and a committed ID would let anyone impersonate the app.

Facts below were checked on 2026-11-17; console labels change often. Sources and caveats are in
`spikes/oauth/FINDINGS.md`.

## Google (Gmail)

1. **Project.** Open <https://console.cloud.google.com/> and create a project named, for example, `clawsmail`.
2. **Gmail API (optional).** Under *APIs & Services > Library*, enable **Gmail API**. IMAP and SMTP don't call the
   API, but enabling it makes the Gmail scope easy to pick in the console.
3. **Branding.** Open the **Google Auth Platform** (*APIs & Services > OAuth consent screen* redirects there) and go
   to **Branding**. Fill in:
   - app name `Clawsmail`;
   - user support email;
   - developer contact email.

   For production you also need the app home page, a privacy policy URL and the authorized domains. Google
   requires the branding to be published before scope verification can be requested.
4. **Audience.** Choose **External** user type and leave the **publishing status** on **Testing**. Then:
   - Add yourself and other testers under **Test users**.
   - Testing apps work only for listed test users (up to 100).
   - **Refresh tokens expire after 7 days in Testing**, so testers sign in again weekly.
5. **Data Access.** Add these scopes:
   - `https://mail.google.com/`: restricted; full IMAP, POP and SMTP access.
   - `openid`
   - `.../auth/userinfo.email` (`email`)
6. **Client.** Go to **Clients > Create client**, choose **Application type: Desktop app** and name it
   `Clawsmail desktop`. Then:
   - Don't add a redirect URI. Desktop clients accept any loopback port.
   - **Copy the client ID and the client secret right away.** Google hashes client secrets and shows the full
     value only once, at creation; afterwards you see only the last four characters. If it is lost, use *client
     secret rotation* to add a new one.
   - The Desktop "secret" is not confidential (Google calls desktop apps public clients), but keep it out of Git
     like the ID.
7. **Publishing.** **Publish app** moves the app to *In production*. Because `https://mail.google.com/` is a
   restricted scope:
   - **Before verification:** users see the "unverified app" screen, and the app is capped at 100 new users.
   - **Verification:** submit it from the **Verification Center**. Expect to need the privacy policy, a
     justification for the scope and probably a demo video; that list is not confirmed.
   - **Security assessment (CASA):** Google requires one when restricted data is stored on or sent to servers.
     Clawsmail has no server, but Google publishes no explicit desktop exemption, so ask during verification.
   - **Alternative:** users can register their own Desktop client and enter its ID in the account settings
     (per-account override).

## Microsoft (Outlook.com and Microsoft 365)

1. **New registration.** Open <https://entra.microsoft.com/> and go to *Entra ID > App registrations > New
   registration*. The Azure portal's App registrations page works too.
   - **Name:** `Clawsmail`.
   - **Supported account types:** *Accounts in any organizational directory (any Microsoft Entra ID tenant,
     multitenant) and personal Microsoft accounts (for example Skype, Xbox)*.
   - **Redirect URI:** platform **Public client/native (mobile & desktop)**, value `http://localhost`. Microsoft
     ignores the port when matching localhost, so `http://localhost:<any port>` works at runtime.
   - Select **Register**.
2. **Authentication.**
   - Check that the *Mobile and desktop applications* platform lists `http://localhost`.
   - Under *Advanced settings*, set **Allow public client flows** to **Yes**, then save.
   - Do **not** create a client secret or certificate: a public client must not send one.
   - Microsoft now recommends `127.0.0.1` over `localhost`, but the portal cannot add an `http://127.0.0.1` URI.
     If you want it, add it in the **Manifest** under `replyUrlsWithType` and switch the preset to
     `RedirectHost::Loopback127`. The IPv6 loopback `[::1]` is not supported.
3. **API permissions.** Choose *Add a permission > Microsoft Graph > Delegated permissions* and add:
   - `offline_access`
   - `openid`
   - `email`
   - `IMAP.AccessAsUser.All`
   - `SMTP.Send`

   Notes:
   - Never add *Application* permissions such as `IMAP.AccessAsApp`.
   - The app requests the scopes at sign-in as `https://outlook.office.com/IMAP.AccessAsUser.All` and
     `https://outlook.office.com/SMTP.Send`, so listing them here is optional for personal accounts. It still
     helps tenant admins who grant consent for their organization.
   - In tenants that block user consent, an admin must grant consent. The portal can show the admin-consent URL.
4. **Client ID.** On **Overview**, copy the **Application (client) ID**, a GUID.
5. **Publisher verification (recommended).** Under *Branding & properties*, verify the publisher through a
   Microsoft Partner Network account. Unverified multitenant apps may be blocked from user consent by tenant
   policies.
6. **Mailbox requirements to tell users.** These are not app settings:
   - **Outlook.com:** IMAP may need to be enabled under *Settings > Mail > Forwarding and IMAP*. SMTP is
     `smtp-mail.outlook.com:587`.
   - **Microsoft 365:** SMTP AUTH must not be disabled for the tenant or the mailbox (`SmtpClientAuthenticationDisabled`;
     security defaults disable it). SMTP is `smtp.office365.com:587`.
   - **IMAP** is `outlook.office365.com:993` for both.

## Passing the IDs at build time

The code reads three variables with `option_env!` **at compile time**:

| Variable | Value |
|---|---|
| `CM_GOOGLE_CLIENT_ID` | `xxxxxxxx.apps.googleusercontent.com` |
| `CM_GOOGLE_CLIENT_SECRET` | the Desktop client's secret (optional; sent only when set) |
| `CM_MS_CLIENT_ID` | the Application (client) ID GUID |

Local build (PowerShell):

```powershell
$env:CM_GOOGLE_CLIENT_ID = "<id>.apps.googleusercontent.com"
$env:CM_GOOGLE_CLIENT_SECRET = "<secret>"
$env:CM_MS_CLIENT_ID = "<guid>"
cargo build --release
```

- **Rebuilds:** Cargo tracks `option_env!` reads, so changing a variable rebuilds the crate that reads it. This was
  checked in the spike.
- **`.env` files:** they are ignored by Git (`.gitignore` lists `.env` and `.env.*`), but Cargo does not load them
  itself. Load one into the shell first, or use a small script that is not committed.
- **CI:** store the values as encrypted repository secrets (*Settings > Secrets and variables > Actions*) and map
  them to `env:` on the release build step only. Don't set them for pull-request builds from forks; GitHub does
  not expose secrets there anyway.
- **Missing values:** a build without the variables still works. Sign-in then reports that no client ID is
  configured, unless the account has its own override.
- **Per-account override:** every account can override the client ID (and, for Google, the secret). The spike CLI
  has `--client-id` and `--client-secret`, for development or for users who bring their own registration.
- **Strings in the binary:** release binaries contain the IDs and the Google secret as plain strings. Both
  providers treat these as public for desktop apps; the protection is PKCE plus the registered loopback redirect.

## Trying it

```powershell
cd spikes\oauth
cargo run --bin oauth-spike -- login --provider google --save
cargo run --bin oauth-spike -- login --provider microsoft --save
```

This opens the system browser. After sign-in the browser shows "You can close this tab", and the CLI prints the
token lengths and the XOAUTH2 size.
