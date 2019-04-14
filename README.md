# vault-auth-proxy

## Configuration

```yaml
---
meta:
  title: Portal
vaultConfig:
  addr: https://vault.local
  authMethod: ldap
  ttl: token # 720h
cookieEncryptionKey: Xoo6eiquai3oow2uBaejai8itah8eeMa
cookieName: w2e9
headerName: SSO
publicURL: http://127.0.0.1:8080
upstreamURL: https://ya.ru
accessList:
  - path: /ee/README.html
    policy: admins-full
  - path: /omnibus
    policy: omnibus-admins
  - path: /runner
    policy: runner-admins
```
