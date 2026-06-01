# Release Instructions

First, bump to the appropriate version you want to publish in the root Cargo.toml.

Then run the following:

```sh
make gate && cargo publish --dry-run && cargo publish
```
