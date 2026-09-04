# Threat model

Documento vivo — actualizar conforme el diseño evolucione. Ver también
el [Credential Broker Blueprint] para arquitectura completa y glosario.

## Riesgos a defender explícitamente

| Riesgo | Descripción | Mitigación mínima viable |
|---|---|---|
| Confused deputy residual | Proceso legítimo, intención ajena (malware invoca el binario real con argv propio) | Consentimiento por operación+recurso concreto, no solo por app — la identidad de proceso es precondición, no autorización |
| Consent fatigue | "Allow for 10 min" abusado por malware dentro de la ventana | Atar la ventana al recurso exacto aprobado, no a la app entera |
| Broker impersonation | Malware crea el socket antes que el daemon real | Creación atómica del socket + verificación de propietario antes de que el cliente confíe en él |
| Exposición en memoria | Swap/pagefile y core dumps filtran secretos ya en claro | `mlock`/`VirtualLock`, deshabilitar core dumps, restringir ptrace hacia el daemon |
| Bypass semántico | Mutations GraphQL no mapean a verbo+URL REST | Para el subconjunto de GitHub soportado, parsear el payload de la mutation, no solo método+ruta |
| Abuso dentro de política | Acceso ya aprobado usado a volumen (exfiltración) | Fuera del MVP — trabajo futuro: rate-limiting y kill switch de revocación total |

[Credential Broker Blueprint]: <URL del artifact publicado>
