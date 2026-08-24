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

The Qt 6 Widgets wizard configures the local/peer names, host and client IP
endpoints, pairing PSK, persistent portal-permission preference, and the
client's position to the left, right, above, or below the host.

```bash
cargo build --release --offline
cmake -S ui -B build/ui -DCMAKE_BUILD_TYPE=Release
cmake --build build/ui --parallel
target/release/cachybridge setup --gui build/ui/cachybridge-setup
```

For an installed build, place `cachybridge` and `cachybridge-setup` in the same
binary directory and run `cachybridge setup`. Use `--config PATH` to work with
a non-default v4 configuration file.

The wizard delegates validation and saving to `cachybridge peer-add`. Pairing
tokens are passed through owner-only temporary files, never process arguments.
Its **Generate token** button delegates to the Rust OS-random generator. The
persistent-permissions setting is stored per peer in the private v4 config;
the first configured seamless start requests consent and subsequent starts use
the portal’s one-time restore tokens. Setup itself never opens a desktop portal
or requests consent.

The configuration directory is mode 0700 and its `config.v4` file is mode
0600. `seamless-host-config` and `seamless-client-config` load peer endpoints,
the PSK, placement, and restore tokens from that file, keeping secrets out of
process arguments and logs. At present the live seamless runtime supports a
peer on the **left**; the GUI retains all four placements for the planned
generalized topology runtime.

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
- The current config-driven seamless runtime supports a left-side peer; right,
  above, and below are stored by setup but rejected clearly at runtime.
- No clipboard, file transfer, or automatic discovery.
