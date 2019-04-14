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
cookieName: sso
headerName: SSO
publicURL: http://127.0.0.1:8080
upstreamURL: http://127.0.0.1:9093
accessList:
  - path: /api/v[1-2]/silences
    methods:
      - POST
      - DELETE
    policies:
      - admins-full
  - path: /
    policies:
      - default
```
