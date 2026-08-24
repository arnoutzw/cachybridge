# CachyBridge v4

CachyBridge shares one Bluetooth mouse and keyboard between two CachyOS/KDE Wayland desktops on the same LAN. Its seamless mode uses the desktop portals: crossing the host's configured outer edge captures input and sends it over an authenticated encrypted connection; the client injects it with RemoteDesktop, and its return edge releases the host capture.

Version 4 adds an initial-pairing and topology setup wizard, including the client’s relative display location and optional persistent portal consent.

See `outputs/cachybridge-demo-guide.md` for build, permission, and two-machine run instructions.

## Quick verification

```bash
cargo test --offline
```

An end-to-end run without physical input devices uses `client --dry-run` and `host --demo-events`.

## Native v4 setup wizard

The Qt 6 Widgets wizard offers a host-led **Easy one-time pairing** flow:

1. Open CachyBridge's tray utility on the controlled client iMac. It announces
   that client as ready, but does not create a pairing code yet.
2. On the input-owner host iMac, refresh **Ready client iMacs** and select a
   discovered client. The client tray immediately opens a large, readable
   five-character code dialog.
3. Enter that code on the host and choose **Pair selected client**. Both
   machines save the new peer automatically; the code expires after five
   minutes and works for one successful join only.

Either role can choose **Unpair this iMac** in setup. It stops local sharing
and removes the local trust key and portal permissions. Run the same action on
the other iMac to revoke its saved copy too.

```bash
cargo build --release --offline
cmake -S ui -B build/ui -DCMAKE_BUILD_TYPE=Release
cmake --build build/ui --parallel
target/release/cachybridge setup --gui build/ui/cachybridge-setup
```

For an installed build, place `cachybridge` and `cachybridge-setup` in the same
binary directory and run `cachybridge setup`. Use `--config PATH` to work with
a non-default v4 configuration file.

The tray menu includes **Start and reconnect at login**. After a pairing has
started a sharing session once, CachyBridge records the chosen role, paired
peer, and display geometry locally; enabling that option writes a user
autostart entry and restores the appropriate host or client session on the
next desktop login. Pairing keys and portal restore tokens remain in the
private v4 configuration rather than the desktop entry.

One-time codes are five easy-to-type Base32 characters. They are authenticated
with SPAKE2 before the normal Noise handshake, preventing an observer from
checking captured pairing traffic against the short code offline. The temporary
encrypted connection transfers a fresh 256-bit long-term key; the displayed
code is never saved. While the client tray is open, it announces only its
friendly name and pairing port over local mDNS (with a same-subnet UDP
fallback), never the code or any secret. Selecting it sends a local UDP request
that causes the client itself to show a new code and open its short-lived TCP
pairing listener. The manual PSK path delegates validation and saving to
`cachybridge peer-add`; its tokens are passed through owner-only temporary
files, never process arguments. The
persistent-permissions setting is stored per peer in the private v4 config;
the first configured seamless start requests consent and subsequent starts use
the portal’s one-time restore tokens. Setup itself never opens a desktop portal
or requests consent.

The same workflow is available to installers and automation without a GUI:

```bash
# Controlled client iMac: show the generated code, then wait for its host.
cachybridge pair-code
cachybridge pair-client --code "$PAIR_CODE"

# Input-owner host iMac: enter that code and the client address shown by setup.
cachybridge pair-host --connect 192.168.2.24:45232 \
  --code "$PAIR_CODE" --local-name "Host iMac" --placement left
```

`$PAIR_CODE` denotes the code printed by `cachybridge pair-code`.

The configuration directory is mode 0700 and its `config.v4` file is mode
0600. `seamless-host-config` and `seamless-client-config` load peer endpoints,
the PSK, placement, and restore tokens from that file, keeping secrets out of
process arguments and logs. The live seamless runtime supports a peer on the
**left or right**; vertical placement remains planned work.

The real local kernel adapters can be verified without visible input using:

```bash
sudo target/release/cachybridge kernel-self-test
```

## Safety

- Start physical testing with `host --no-grab`.
- Exclusive mode grabs the selected devices until the host exits.
- Press **Ctrl+Alt+Shift+Esc** to stop exclusive forwarding and return input locally.
- Kernel evdev grabs and the virtual uinput device are also released when the relevant process exits.

## Current limitations

- Linux/CachyOS only.
- The current RemoteDesktop injector is relative-pointer based, so exact
  first-entry cursor placement is not yet guaranteed without the planned
  ScreenCast absolute-coordinate mapping.
- One host and one client.
- The config-driven seamless runtime supports left/right peers. Vertical
  placement is not available yet.
- Clipboard text and PNG, JPEG, or WebP images are shared bidirectionally over
  a second Noise-PSK connection while a seamless session is running. It
  requires the `wl-clipboard` package (`wl-copy` and `wl-paste`) on both
  desktops and limits a single text/image item to 8 MiB.
- Copying one or more regular local files is supported up to 64 MiB in total.
  Received files are placed in the private CachyBridge data cache and exposed
  to the desktop as a normal file clipboard selection. Directories, remote
  URLs, duplicate file names, and larger batches are intentionally rejected.
