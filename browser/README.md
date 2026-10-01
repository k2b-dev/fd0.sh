# fd0 browser integration

This directory contains the plain-TypeScript Manifest V3 extension that brings
fd0 autofill to Chrome and Chromium on macOS and Linux.

The extension:

- finds login, signup, password-change, confirmation, and one-time-code fields,
  including open shadow roots and HTTPS frames;
- reveals a password only after the user chooses an origin-matching login;
- never submits a form;
- fills a fresh TOTP code after a recent, explicit login selection;
- generates random, memorable, or PIN passwords with the same controls as
  fd0 Desktop and fills both password confirmation fields;
- offers explicit save and revision-bound update actions;
- accepts a pasted `otpauth://` setup link for a selected login;
- keeps submitted login candidates only in Chrome's in-memory session storage,
  scoped to one tab frame and HTTPS origin, and actively expires them after 60
  seconds;
- never writes passwords, TOTP seeds, or codes to Chrome Local or Sync
  Storage. Explicit save, update, and TOTP actions write to the encrypted fd0
  vault.

## Install it

1. Install the current [fd0 Desktop or CLI](https://fd0.sh/#install). The
   installer registers the local Native Messaging host used by the extension.
2. Add [fd0 from the Chrome Web Store](https://chromewebstore.google.com/detail/fd0/kcbjlgbkgoabcdflpnohkknfbegcigel).
3. Unlock fd0 and focus a username, password, or one-time-code field on an
   HTTPS page.

If fd0 was installed before automatic browser registration was available, run
`fd0 browser enable` once. This writes only the browser's local Native
Messaging manifest; it does not change the vault.

## Build and register a development copy

```sh
cd browser
bun install --frozen-lockfile
bun run typecheck
bun test
bun run build
bunx playwright install chromium
bun run test:smoke

cd ..
go build -o .build/browser/fd0 ./cmd/fd0
go build -o .build/browser/fd0-browser-host ./cmd/fd0-browser-host
.build/browser/fd0 browser enable --host .build/browser/fd0-browser-host
```

Open `chrome://extensions` or `chromium://extensions`, enable **Developer
mode**, choose **Load unpacked**, and select `browser/dist`. The browser must
show extension id
`flkmmllfacmjnhjgdfliahdkhfjmdoec`. A different id cannot use this development
Native Messaging registration.

`fd0 browser enable` registers both exact identities accepted by the native
host: the unpacked development extension above and Chrome Web Store item
`kcbjlgbkgoabcdflpnohkknfbegcigel`. No wildcard extension origin is accepted.

## Build the Chrome Web Store package

The store package is separate from the unpacked development build. It omits
the development extension key and source maps, includes only the required
runtime files and icons, and is checked before it is written:

```sh
cd browser
bun run package:store
```

The verified ZIP is written to
`.build/browser-store/fd0-chrome-<version>.zip`. Listing copy, privacy answers,
reviewer instructions, and store graphics live under [`store/`](./store/).

## Use fd0 in Chrome

Unlock fd0 and focus a credential field on an HTTPS page. The inline fd0 button
opens matching logins. **Save login** keeps title, username, visible password,
generator controls, vault, and the explicit save/update action in one compact
editor. TOTP setup stays collapsed until requested.

Automatic login suggestions leave the keyboard focus in your field. Typing or
pressing Escape dismisses them. Click the fd0 button to use the login picker
with the keyboard or open **Password tools** to generate or save a password.
Closing the picker or editing its target fields cancels a pending fill.
Automatic one-time codes only fill empty fields that you have not edited.

If a site signs you in without loading a new page, fd0 may not offer to save
the login automatically. While the credentials are still in the form, open
**Password tools**, review the values, and choose **Save login**, **Save as new**,
or **Update login** as appropriate.

The toolbar action selects one concrete frame containing a visible credential
field. Existing HTTPS tabs are reconnected after an extension rebuild; a page
reload is not required.
Locked and unavailable states keep a retry action instead of requiring an
extension restart.

Matching returns only opaque references, titles, usernames, vault metadata,
revisions, and whether a TOTP is available. A password or TOTP code is
requested only after an explicit action, and the Go host repeats the
HTTPS-origin check. Updates also require the revision shown to the extension,
so a stale page cannot overwrite a newer change.

## Remove the registration

Remove only the fd0 Native Messaging registration with:

```sh
.build/browser/fd0 browser disable
```

Remove the unpacked or Store extension separately in `chrome://extensions`.
Neither action removes the fd0 vault. Firefox is not supported yet.
