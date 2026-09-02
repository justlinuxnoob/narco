# narco

Private chat for two people. No accounts, no server, no history.

Both people enter the same secret. The app turns that secret into a Tor address,
they meet there, and everything they say is end-to-end encrypted. When the
session ends, the keys are destroyed and the conversation is gone — because it
was never written down anywhere.

```
type a secret  →  it becomes an address  →  you meet there  →  encrypted chat
                                                             →  end  →  gone
```

## There is no server

That's the point, and it's the part worth understanding.

A server's only real job is introducing two people who can't find each other.
Narco doesn't need one, because **the secret is the address**:

```
PWXK7M2QRT9HFZ  →  Argon2id  →  ed25519 key  →  ew3r52hw…qu3hhxyd.onion
```

Both devices compute that offline, from the secret alone, and arrive at the same
place. Tor's existing public directory does the introduction. Nothing is hosted,
nothing is rented, and there is no bill that can ever arrive.

See for yourself, without connecting to anything:

```sh
cargo run -p narco-tor --example derive -- "YOUR-SECRET-HERE"
```

## Get it

Latest builds are on the [releases page](https://github.com/justlinuxnoob/narco/releases/latest).

| Platform | File | How |
| --- | --- | --- |
| Windows | `_installer.exe` | Install and launch from the Start menu |
| Windows, no install | `_portable.zip` | Unzip, run `Narco.exe` |
| Linux | `_linux_portable.tar.gz` | Extract, run `./narco` |
| Android | `_android.apk` | Sideload it |
| iOS | — | TestFlight, not yet public |

The portable builds keep the executable and the `tor` folder together; the app
runs that Tor daemon itself. Windows will warn that the publisher is unknown,
because the build is unsigned.

Arch and derivatives can build a package from [`packaging/PKGBUILD`](packaging/PKGBUILD).

## What it does

- **Two people, ever.** The moment the handshake confirms, the address is
  unpublished. There is no longer a door for a third person to knock on.
- **Any number of secrets.** Use one, or five. Send each a different way — one
  messaged, one spoken aloud — so intercepting one channel yields nothing.
- **Photos and files.** Sent as ordinary encrypted messages, cut into pieces
  because one message holds 32 KiB. A photo appears in the conversation;
  anything else is offered as a download. Received files stay in memory and
  reach your disk only if you save them, and are released when the session
  ends.
- **Nothing on disk.** No database, no history, no logs. Messages live in memory
  and die with the session.
- **Forward secrecy.** Each message's key is destroyed right after use. Someone
  who takes your device tomorrow cannot read what you said today, even with a
  full recording of the traffic.
- **Survives a dropped connection.** Switch apps on a phone and the OS closes
  the socket; Narco publishes and dials the same address again and carries on,
  with the conversation still on screen. A fresh handshake runs each time, so
  it is a new session at the same address rather than a resumed one.
- **Ends when you say so, and only then.** Pressing end or closing the app wipes
  everything. Nothing else closes a chat: there is no silence timer, because two
  people leaving a room open between messages is the normal way to use this, and
  the keys live exactly as long as the session either way.
- **Guessing is bounded.** A host answers five wrong secrets, each more slowly
  than the last, and then stops.

## What it does not do

Stated plainly, because a privacy claim that hides its limits is worthless.

- **It is not instant.** Joining the Tor network takes about **25 seconds**.
  Finding each other after that has ranged from **10 seconds to nearly two
  minutes** across test runs, because an onion address has to be published and
  propagate through Tor's directory before anyone can dial it, and how long
  that takes is not up to us. That is the price of needing no server.
  Reconnecting to an address that is already published is much quicker —
  measured at **2 seconds**.
- **It does not protect a compromised device.** Plaintext is on both screens.
- **A guessable secret is a guessable address.** The onion address is derived
  from the secret, so an attacker can guess secrets, derive addresses, and ask
  the Tor directory which ones exist — offline, in bulk, without touching
  either of you. Argon2id prices each guess in memory, but what decides this is
  the secret: generated is 130 bits and unreachable, invented is nearer 30.
  **Use the generated code.** Narco fills one in and warns if you replace it.
- **The onion descriptor lives in Tor's directory for a few hours.** So
  "nothing exists anywhere" is not literally true at the Tor layer.
- **Reused secrets meet at the same address.** Old messages are unrecoverable
  either way, but someone who learns your secret could show up in a *new* empty
  room pretending to be your friend. Generate a fresh one each time.

## Security design

[`PROTOCOL.md`](PROTOCOL.md) is the normative spec — key derivation, the SPAKE2
handshake, the ratchet, padding, and an exhaustive list of what leaks.

The short version: secrets are stretched with Argon2id, then a **SPAKE2**
password-authenticated key exchange establishes a session key. SPAKE2 matters
because it makes offline dictionary attacks impossible — an attacker gets one
online guess per attempt and learns nothing from a recorded transcript. Messages
use ChaCha20-Poly1305 with a per-message ratchet and length padding.

**SPAKE2 does not fail on a wrong secret — it silently yields a different key.**
So the protocol confirms the key explicitly before unlocking the UI. A wrong
secret connects to nothing and says nothing.

No cryptographic primitive is implemented here. Every one comes from an
established, reviewed crate.

**Tor is the C `tor` daemon** on Windows, Linux and Android — the same binary
Tor Browser ships, currently 0.4.9.11, run as a child process.

**iOS uses Arti**, the Rust Tor implementation, because iOS forbids executing a
second binary — which is also why no Tor Browser exists for iOS. Linking the C
tor there instead is the intended end state and is not done yet.

Known weaknesses are listed in [`SECURITY.md`](SECURITY.md) rather than left
for a reader to find, including the ones not yet fixed.

## Layout

| | |
| --- | --- |
| `crates/narco-proto` | All cryptography. Transport-agnostic, no Tor dependency. |
| `crates/narco-tor` | Secret → onion address, and meeting without a server. |
| `app/` | Tauri app for all four platforms. Holds no keys; the UI is 4 kB of JavaScript. |

There is no fourth entry. Narco once carried an optional self-hosted relay; it
was removed in 0.5.5, because nothing could select it and shipping an unusable
server in a project whose first claim is "no server" was worse than useless.

## Build

Needs [Rust](https://rustup.rs) and [Node](https://nodejs.org), plus the
[Tauri prerequisites](https://tauri.app/start/prerequisites/) for your platform.

```sh
cd app
npm install
npm run tauri build     # or: npm run tauri dev
```

Run the tests, including a live end-to-end check over the real Tor network:

```sh
cargo test --manifest-path crates/narco-proto/Cargo.toml
cargo test --manifest-path crates/narco-tor/Cargo.toml
cargo run -p narco-tor --example live_handshake   # takes a few minutes
```

## Status

Early, and working: Tor connects and two people can talk on Windows, Linux,
Android and iOS.

It has **not** been audited. An internal review in 0.5.6 found seven real
defects — including a forward-secrecy claim that was false because a crate
feature was off — and four more are documented but unfixed in
[`SECURITY.md`](SECURITY.md). That is what a couple of careful readers found;
it is not what a professional audit would find. Don't stake your safety on it.

## Licence

[AGPL-3.0-or-later](LICENSE). If you run a modified version as a service, you
have to publish your changes — which is the point, for software whose whole
claim is that you can check what it does.
