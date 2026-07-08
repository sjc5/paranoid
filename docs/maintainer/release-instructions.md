# Release Instructions

## 1: Gate

```sh
make gate
```

## 2: Bump

Bump the version in the root Cargo.toml.

## 3: Pre-Publish

```sh
cargo audit
cargo deny check licenses bans sources advisories
cargo publish --dry-run
```

## 4: Publish

```sh
cargo publish
```
