# Local Env Vault Playground

This playground is a tiny application-owned wrapper for `paranoid::local_env_vault`.

```sh
make configure
make validate-api
make validate-worker
make run-api
make run-worker
```

The wrapper stores its local vault in `.paranoid_local_env_vault/` under this playground
package root.
