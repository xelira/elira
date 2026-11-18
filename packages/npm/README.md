# elira

Launcher for the native `elira` binary. The npm package does not contain the
server itself; it finds an installed binary and runs it.

Lookup order:

1. `ELIRA_BIN` — path to an executable
2. `@elira/<platform>-<arch>` — a platform package, when one is published
3. `elira` on `PATH`

When nothing is found, the launcher prints the install options and exits 1.

```
ELIRA_BIN=/usr/local/bin/elira npx elira run --config elira.toml
```

Source and releases: <https://github.com/xelira/elira>
