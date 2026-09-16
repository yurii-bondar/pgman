## 1.0.0 (2026-09-15)

### ⚠ BREAKING CHANGES

* auth_hba_file parsing is stricter and, in two cases,
different. A quoted value is now a literal name, so `"all"` means a
database called all rather than the wildcard; a sixth field (Postgres's
per-method options, none of which pgman implements) is refused rather
than ignored; and an empty DATABASE or USER list is refused rather than
accepted as a rule that can never match.

### Features

* prod-ready packaging, self-contained admin UI, and 93% test coverage ([adf6233](https://github.com/yurii-bondar/pgman/commit/adf623382151fb8d7331ff1be7d0d2db27fc0278))

### Bug fixes

* bump github.com/go-jose/go-jose/v4 in the go-patch group ([68456ed](https://github.com/yurii-bondar/pgman/commit/68456ed71e2875417180c461dec759b8ce3ed549))
* bump golang from 1.27.0-alpine to 1.27.1-alpine ([bcf69ba](https://github.com/yurii-bondar/pgman/commit/bcf69ba1539eff48ff41371795b6d519186b308e))
* bump golang.org/x/crypto from 0.20.0 to 0.57.0 ([25eb6b0](https://github.com/yurii-bondar/pgman/commit/25eb6b002181c22c9c2c854be7a31162cdc10481))
* **ci:** pin the changelog preset to the major that matches semantic-release 25 ([6a6e674](https://github.com/yurii-bondar/pgman/commit/6a6e6749effd32cafdc37ba842051fb5c218111c))
* stop the config reloader without closing its signal channel ([4f4d3ab](https://github.com/yurii-bondar/pgman/commit/4f4d3abd05bc684cec83b77c4b9eb387459b0c1c))
