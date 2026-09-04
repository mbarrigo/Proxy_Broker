# Security invariants

Reglas que nunca se pueden romper. Cada una debería tener, más adelante,
un test que la verifique — cuando eso pase, enlazar el test aquí en vez
de dejarlo como aspiracional.

Ver [docs/threat-model.md](docs/threat-model.md) para los riesgos de los
que se derivan.

## INV-001

Una credencial marcada como non-exportable (clave privada SSH, seed
TOTP) nunca puede aparecer en una respuesta IPC.

`ProviderAdapter::execute` (`crates/broker-core`) devuelve el
**resultado** de la operación, nunca el secreto usado para producirlo —
la firma del trait no da forma de devolver el secreto por accidente,
pero un adapter mal escrito podría meterlo en el `serde_json::Value` de
respuesta. Pendiente: test que falle si algún adapter serializa un
patrón reconocible de secreto (regex de tokens conocidos, longitud de
clave, etc.) en su output.

## INV-002

Los secretos nunca aparecen en el audit log.

`broker_audit::AuditEntry` (`crates/broker-audit`) solo tiene campos para
caller/provider/action/decisión — no existe campo para el valor de la
credencial ni para el payload completo de la operación.

## INV-003

Toda operación pasa por el motor de políticas antes de ejecutarse — no
existe ninguna ruta que invoque `ProviderAdapter::execute` sin haber
consultado antes `PolicyEngine::evaluate`.

`CredentialManager::dispatch` (`crates/broker-core`) es el único
punto de entrada previsto hacia los adapters; no debería añadirse nunca
un segundo camino que los llame directamente.

## INV-004

Todo intento de uso de una credencial genera una entrada de auditoría,
incluidos los denegados — no solo los permitidos.

Estado actual: **no implementado todavía** — `dispatch()` no llama a
`AuditSink::record` en ninguna rama. Bloqueante para cerrar la Fase 1
del roadmap.

## INV-005

Un provider solo accede a los secretos de su propio namespace en el
`SecretStore`; no puede leer los de otro provider.

Estado actual: **no aplica todavía** — `SecretStore` (`crates/broker-storage`)
no tiene noción de namespace por provider; `InMemoryStore` es una única
tabla plana. Diseñar el prefijo/namespace antes de conectar un backend
real, no después.
