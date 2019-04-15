# vault_proxy

A simple reverse proxy that provides authentication using [HashiCorp Vault](https://www.vaultproject.io) to validate access by [Userpass](https://www.vaultproject.io/docs/auth/userpass.html) or [LDAP](https://www.vaultproject.io/docs/auth/ldap.html) methods. Proxy doesn't read and store any data taken from Vault by user's token unless list of policies.

## Architecture

```
Nginx :443 (ssl termination)    -> vault-auth-proxy 127.0.0.1:8080
vault-auth-proxy 127.0.0.1:8080 ~> HashiCorp Vault :443
vault-auth-proxy 127.0.0.1:8080 -> Secured HTTP service 127.0.0.1:9090
```

## Configuration

Here is example of protection [Alertmanager](https://prometheus.io/docs/alerting/alertmanager/) from deleting or creating silences by everyone. In same time all authorized users can view silences cause `GET` requests allowed for all.

```yaml
---
meta:
  title: Portal
vaultConfig:
  addr: https://vault.local
  authMethod: ldap
  # TTL as `token` will be based on token lifetime,
  # it might be specified in time.Duration format.
  # ref: https://golang.org/pkg/time/#ParseDuration
  ttl: token
cookieEncryptionKey: Xoo6eiquai3oow2uBaejai8itah8eeMa
cookieName: sso
headerName: SSO
publicURL: http://alertmanager.local
upstreamURL: http://127.0.0.1:9093
accessList:
  - path: /api/v[1-2]/silence
    methods:
      - POST
      - DELETE
    policies:
      - admins
      - developers
  - path: /
    policies:
      - default
```
