# Proxy_Broker

Proxy local con relay que gestiona tokens, OTP y credenciales de autenticación sin exposición externa: un broker de credenciales que permite a aplicaciones ejercer capacidades autenticadas (firmar con SSH, llamar a la API de GitHub, generar un TOTP) **sin recibir nunca la credencial que las origina** — el patrón de `ssh-agent` generalizado a OAuth, API keys y TOTP.

**Objetivo operativo: MVP funcional antes del 10 de febrero de 2027.**

## Estado actual

El ciclo **identidad → política → auditoría** funciona de extremo a extremo, verificado a mano con `demo-client`:

- IPC real (`broker-ipc`, socket local multiplataforma vía `interprocess`), no un placeholder.
- Identidad de proceso real: PID vía credenciales del peer del socket, ruta del ejecutable resuelta desde el PID (Windows implementado y probado; Linux implementado sin verificar; macOS pendiente).
- Política real: `demo-client` tiene `demo.read` en `allow` y `demo.admin` en `deny` — y un binario idéntico copiado a otra ruta (`evil-demo.exe`) es denegado igual que si fuera una app no autorizada, porque la decisión depende de la identidad resuelta, no de lo que el cliente declare.
- Auditoría real: cada decisión (permitida o denegada) queda registrada — cierra INV-004.

Lo que sigue siendo placeholder: los tres providers reales (SSH, TOTP, GitHub — siguen devolviendo "no implementado todavía"), el almacén de secretos (solo hay una versión en memoria para desarrollo) y la UI de aprobación.

Cómo comprobarlo vosotros mismos:
```sh
cargo build --workspace
./target/debug/daemon &          # o cargo run --bin daemon
./target/debug/demo-client hello
./target/debug/demo-client demo read    # -> Ok
./target/debug/demo-client demo admin   # -> Denied
cargo test --workspace           # unit tests de broker-policy
```

Documentos de referencia:
- **[Credential Broker Blueprint](https://claude.ai/code/artifact/1d25527d-3316-4fdd-b235-04178eee173f)** — arquitectura completa, roadmap, reparto de trabajo, glosario.
- **[docs/threat-model.md](docs/threat-model.md)** — assets, adversarios, qué protegemos y qué no.
- **[SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md)** — reglas que no se pueden romper, con su estado real en el código.

## Estructura del repo

```
crates/
├── broker-ipc/             # socket Unix / Named Pipe + framing del protocolo (implementado)
├── broker-identity/        # PID + ruta del ejecutable a partir del PID (implementado, Windows probado)
├── broker-storage/         # abstracción sobre Keychain / DPAPI / Secret Service (placeholder en memoria)
├── broker-policy/          # motor de políticas: allow / deny / ask-user (implementado + tests)
├── broker-core/            # trait ProviderAdapter + lifecycle + dispatch + auditoría (implementado)
├── broker-audit/           # log de decisiones, nunca del secreto (implementado, stdout por ahora)
└── broker-http-relay/      # cliente HTTP, validación TLS, inyección de header (placeholder)
providers/
├── ssh/                    # firma vía protocolo real de ssh-agent (placeholder, paquete: provider-ssh)
├── totp/                   # RFC 6238 (placeholder, paquete: provider-totp)
└── github/                 # OAuth 2.0 + PKCE + mapeo semántico de scopes (placeholder, paquete: provider-github)
daemon/                     # binario final — junta todo, política de la demo
examples/
└── demo-client/            # cliente de prueba manual (hello / demo read / demo admin)
apps/
└── ui/                     # pendiente — aprobaciones, historial, revocación
docs/
└── threat-model.md         # assets, adversarios, riesgos y mitigación mínima viable
```

## Reparto de trabajo

- **Núcleo / seguridad**: `broker-ipc`, `broker-identity`, `broker-storage`, `broker-policy`, `broker-core`, `providers/ssh`, `broker-audit`
- **Proveedores / producto**: `providers/totp`, `providers/github`, `broker-http-relay`, `apps/ui`

El contrato `ProviderAdapter` (en `crates/broker-core/src/lib.rs`) es el límite de sincronización entre ambos — cualquier cambio en su firma se acuerda entre los dos antes de tocarla.
