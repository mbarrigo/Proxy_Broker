# Threat model

Documento vivo — actualizar conforme el diseño evolucione. Ver también
el [Credential Broker Blueprint] para arquitectura completa y glosario,
y [SECURITY_INVARIANTS.md](../SECURITY_INVARIANTS.md) para las reglas
concretas que de aquí se derivan y que se convierten en tests.

## Assets

- Refresh tokens OAuth
- API keys
- Claves privadas SSH
- Seeds TOTP

## Adversarios

1. Aplicación local no autorizada (usa al broker como intermediario sin robar nada — confused deputy)
2. Malware ejecutándose como el mismo usuario
3. Atacante de red
4. Servidor remoto malicioso (proveedor comprometido o suplantado)

## Protegemos contra

- Lectura accidental de credenciales por la app cliente
- Exposición en variables de entorno, ficheros de configuración o logs
- Aplicaciones locales no autorizadas usando el broker como proxy de sus privilegios
- Robo directo del almacén de secretos en reposo

## No garantizamos protección contra

- root/SYSTEM con control completo de la máquina
- Kernel comprometido
- Hardware comprometido
- Inyección de código en un proceso ya autorizado (ver "Confused deputy residual" abajo — mitigado, no eliminado)

## Riesgos a defender explícitamente

| Riesgo | Descripción | Mitigación mínima viable |
|---|---|---|
| Confused deputy residual | Proceso legítimo, intención ajena (malware invoca el binario real con argv propio) | Consentimiento por operación+recurso concreto, no solo por app — la identidad de proceso es precondición, no autorización |
| Consent fatigue | "Allow for 10 min" abusado por malware dentro de la ventana | Atar la ventana al recurso exacto aprobado, no a la app entera |
| Broker impersonation | Malware crea el socket antes que el daemon real | Creación atómica del socket + verificación de propietario antes de que el cliente confíe en él |
| Exposición en memoria | Swap/pagefile y core dumps filtran secretos ya en claro | `mlock`/`VirtualLock`, deshabilitar core dumps, restringir ptrace hacia el daemon |
| Bypass semántico | Mutations GraphQL no mapean a verbo+URL REST | Para el subconjunto de GitHub soportado, parsear el payload de la mutation, no solo método+ruta |
| Abuso dentro de política | Acceso ya aprobado usado a volumen (exfiltración) | Fuera del MVP — trabajo futuro: rate-limiting y kill switch de revocación total |

[Credential Broker Blueprint]: https://claude.ai/code/artifact/1d25527d-3316-4fdd-b235-04178eee173f
