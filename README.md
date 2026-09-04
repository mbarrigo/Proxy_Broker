# Proxy_Broker

Proxy local con relay que gestiona tokens, OTP y credenciales de autenticación sin exposición externa: un broker de credenciales que permite a aplicaciones ejercer capacidades autenticadas (firmar con SSH, llamar a la API de GitHub, generar un TOTP) **sin recibir nunca la credencial que las origina** — el patrón de `ssh-agent` generalizado a OAuth, API keys y TOTP.

**Objetivo operativo: MVP funcional antes del 10 de febrero de 2027.**

## Estado actual

Esqueleto inicial del workspace de Rust: compila y ejecuta de extremo a extremo con tres adapters registrados (SSH, TOTP, GitHub), pero ninguno tiene lógica real todavía — el IPC, la identidad de proceso, el almacén de secretos y los adapters son placeholders con TODOs explícitos. El objetivo de esta fase es tener la separación de módulos y el contrato `ProviderAdapter` fijados para que los dos podamos avanzar en paralelo.

Documentos de referencia:
- **[Credential Broker Blueprint](https://claude.ai/code/artifact/1d25527d-3316-4fdd-b235-04178eee173f)** — arquitectura completa, roadmap, reparto de trabajo, glosario.
- **[docs/threat-model.md](docs/threat-model.md)** — assets, adversarios, qué protegemos y qué no.
- **[SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md)** — reglas que no se pueden romper, con su estado real en el código.

## Compilar y ejecutar

```sh
cargo build --workspace
cargo run --bin daemon
```

## Estructura del repo

```
crates/
├── broker-ipc/             # socket Unix / Named Pipe + framing del protocolo
├── broker-identity/        # SO_PEERCRED / getpeereid / GetNamedPipeClientProcessId
├── broker-storage/         # abstracción sobre Keychain / DPAPI / Secret Service
├── broker-policy/          # motor de políticas: allow / deny / ask-user
├── broker-core/            # trait ProviderAdapter + lifecycle + dispatch
├── broker-audit/           # log append-only de decisiones (nunca del secreto)
└── broker-http-relay/      # cliente HTTP, validación TLS, inyección de header
providers/
├── ssh/                    # firma vía protocolo real de ssh-agent (paquete: provider-ssh)
├── totp/                   # RFC 6238 (paquete: provider-totp)
└── github/                 # OAuth 2.0 + PKCE + mapeo semántico de scopes (paquete: provider-github)
daemon/                     # binario final — junta todo
apps/
└── ui/                     # pendiente — aprobaciones, historial, revocación
docs/
└── threat-model.md         # assets, adversarios, riesgos y mitigación mínima viable
```

## Reparto de trabajo

- **Núcleo / seguridad**: `broker-ipc`, `broker-identity`, `broker-storage`, `broker-policy`, `broker-core`, `providers/ssh`, `broker-audit`
- **Proveedores / producto**: `providers/totp`, `providers/github`, `broker-http-relay`, `apps/ui`

El contrato `ProviderAdapter` (en `crates/broker-core/src/lib.rs`) es el límite de sincronización entre ambos — cualquier cambio en su firma se acuerda entre los dos antes de tocarla.
