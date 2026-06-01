# Release Instructions

Bump the version as appropriate in the root Cargo.toml. Then run the following:

```sh
make gate

cargo package --list
cargo publish --dry-run
cargo publish
```
