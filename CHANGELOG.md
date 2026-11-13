# Changelog

## 1.0.0-rc.1

First release candidate. The layout is frozen; the items in the README's
"Known limitations" are tracked for 1.0 final.

- 192-byte peek header replacing the earlier 64-byte prefix: magic, version,
  tree id, journal generation, content id, type id, sequence, sizes, counts,
  families, event window, header CRC.
- Content id over the data projection and every non-META section; provenance is
  excluded, so equal data from different paths hashes equally.
- Journal with 48-byte segment headers, crc32c framed records, dense sequences,
  a writer lock, a generation per incarnation, checkpoint verification, and
  `state.json` for restart-safe sequence numbering.
- `snap` CLI: build, verify, search, info.
- Golden object test that fails on any archived-layout drift.
