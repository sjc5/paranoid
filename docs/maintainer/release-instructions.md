# Release Instructions

## First time only:

Sign in at `crates.io` with GitHub and verify your email. Create an API token at
`crates.io/me`. Then run:

```sh
cargo login
```

## Every time:

Bump the workspace and README package numbers as appropriate.

```sh
make gate

cargo package --list
cargo publish --dry-run
cargo publish
```
