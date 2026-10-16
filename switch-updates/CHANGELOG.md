# Changelog

## 1.1.1

- Joins a group hosted by a Switch 2. Its reply with the game's name and icon is larger than a Switch's, and
  1.1.0 refused it.

## 1.1.0

- First release. Backs up a Switch game's update or its system update from a console, and sends a saved update
  to another console, through Match Version With Local Users.
- Library: updates kept as NSPs and system updates as ZIPs, each with a note showing the game's icon. A library
  in the older layout is converted on the first run.
- Check saved updates hashes every saved update and verifies Nintendo's signatures. Import an update adds an NSP,
  a system update's NCAs, or an archive of them, once it passes the same checks.
