# Proxy_Broker

Proxy local con relay que gestiona tokens, OTP y credenciales de autenticación sin exposición externa: un broker de credenciales que permite a aplicaciones ejercer capacidades autenticadas (firmar con SSH, llamar a la API de GitHub, generar un TOTP) **sin recibir nunca la credencial que las origina** — el patrón de `ssh-agent` generalizado a OAuth, API keys y TOTP.

## Estado actual

Esqueleto inicial del workspace de Rust (Mes 1 del roadmap): compila y ejecuta de extremo a extremo con tres adapters registrados (SSH, TOTP, GitHub), pero ninguno tiene lógica real todavía — el IPC, la identidad de proceso, el almacén de secretos y los adapters son placeholders con TODOs explícitos. El objetivo de esta fase es tener la separación de módulos y el contrato `ProviderAdapter` fijados para que los dos podamos avanzar en paralelo.

Documento de referencia completo (arquitectura, roadmap de 6 meses, reparto de trabajo, glosario): **[Credential Broker Blueprint](https://claude.ai/code/artifact/1d25527d-3316-4fdd-b235-04178eee173f)**.

## Compilar y ejecutar

```sh
cargo build --workspace
cargo run --bin daemon
```

## Estructura del repo

```
crates/
├── ipc/                   # socket Unix / Named Pipe + framing del protocolo
├── peer-identity/         # SO_PEERCRED / getpeereid / GetNamedPipeClientProcessId
├── secret-store/          # abstracción sobre Keychain / DPAPI / Secret Service
├── policy/                # motor de políticas: allow / deny / ask-user
├── credential-manager/    # trait ProviderAdapter + lifecycle + dispatch
├── adapter-ssh/           # firma vía protocolo real de ssh-agent
├── adapter-totp/          # RFC 6238
├── adapter-github/        # OAuth 2.0 + PKCE + mapeo semántico de scopes
├── http-relay/            # cliente HTTP, validación TLS, inyección de header
├── audit/                 # log append-only de decisiones (nunca del secreto)
└── daemon/                # binario final — junta todo
apps/
└── ui/                    # pendiente — aprobaciones, historial, revocación
docs/
└── threat-model.md        # riesgos identificados y mitigación mínima viable
```

## Reparto de trabajo

- **Núcleo / seguridad**: `ipc`, `peer-identity`, `secret-store`, `policy`, `credential-manager`, `adapter-ssh`, `audit`
- **Proveedores / producto**: `adapter-totp`, `adapter-github`, `http-relay`, `apps/ui`

El contrato `ProviderAdapter` (en `crates/credential-manager/src/lib.rs`) es el límite de sincronización entre ambos — cualquier cambio en su firma se acuerda entre los dos antes de tocarla.
