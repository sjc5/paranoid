# Release Instructions

First, bump to the appropriate version you want to publish in the root Cargo.toml.

Then run the full gate.

```sh
make gate
```

Then run the dependency policy checks:

```sh
cargo audit
cargo deny check licenses bans sources advisories
```

Then run the publish commands:

```sh
cargo publish --dry-run
cargo publish
```
