# Changelog

## 4.2.0 — 2026-08-26

- Added Dolphin `Actions → CachyBridge → Send to paired iMac` for explicit
  AirDrop-style file offers without touching the clipboard.
- Automatic file clipboard syncing is disabled; text and image clipboard
  sharing remains unchanged.

## 4.1.1 — 2026-08-26

- File clipboard copies are now offers: the receiving iMac must explicitly
  accept or decline a KDE popup before CachyBridge sends file bytes.

## 4.1.0 — 2026-08-26

- Reworked file clipboard transfer into an encrypted, disk-streaming flow.
- Received files are staged safely, then published in `Downloads/CachyBridge`
  and exposed as a native KDE file clipboard selection.
- Added file-transfer progress, throughput, direction, and final destination to
  the Clipboard tab.
- Raised the aggregate file-transfer safeguard to 64 GiB without using file
  size as RAM.

## 4.0.1 — 2026-08-26

- Raised regular-file clipboard transfers to 512 MiB, including video files.
- Oversize clipboard selections now remain local without restarting clipboard sync.
- Improved KVM reconnect behavior after a dropped host/client transport.

## 1.0.0 — 2026-08-25

- First complete CachyBridge release for two CachyOS/KDE Wayland iMacs.
- Seamless Bluetooth mouse and keyboard handoff across left/right display edges.
- Authenticated five-character pairing, LAN discovery, persistent portal permissions,
  login restore, and a tray utility.
- Draggable relative-display placement with client resolution fetched automatically.
- Encrypted text, image, and regular-file clipboard transfer.
- Per-iMac user-settable CachyBridge names, defaulting to the hostname.
