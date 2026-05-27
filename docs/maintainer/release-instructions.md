# Release Instructions

## First time only:

Sign in at `crates.io` with GitHub and verify your email. Create an API token at
`crates.io/me`. Then run:

```sh
cargo login
```

## Every time:

```sh
cargo package --list
cargo publish --dry-run
cargo publish
```
