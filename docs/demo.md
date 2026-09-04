# Demo end-to-end: identidad → política → auditoría

Este documento recoge la primera prueba de humo real del proyecto: el
ciclo completo *identidad de proceso → política → auditoría* funcionando,
sin depender todavía de ningún provider real (SSH/TOTP/GitHub siguen
siendo placeholders — ver [SECURITY_INVARIANTS.md](../SECURITY_INVARIANTS.md)).

## Cómo reproducirlo

```sh
cargo build --workspace
./target/debug/daemon &                 # o cargo run --bin daemon
./target/debug/demo-client hello
./target/debug/demo-client demo read
./target/debug/demo-client demo admin
cargo test --workspace                  # 5 tests unitarios de broker-policy
```

## Resultados

| Petición | Resultado | Por qué |
|---|---|---|
| `demo-client hello` | `Ok -> "world"` | ping de conectividad, resuelto antes de tocar política (ver `handle_request`) |
| `demo-client demo read` | `Ok -> {"data":"contenido de prueba"}` | `demo-client.exe` tiene `demo.read` en `allow` |
| `demo-client demo admin` | `Denied` | `demo-client.exe` tiene `demo.admin` en `deny` |
| `demo-client github repos.list` | `Denied` | no hay regla para esa capability → cae en `AskUser`, que hoy se trata como deny (pendiente la UI de consentimiento) |
| `evil-demo.exe demo read` (mismo binario, copiado a otra ruta) | `Denied` | la identidad resuelta es otra ruta de ejecutable — la política no reconoce a `evil-demo.exe`, sin importar que el binario sea idéntico |

El último caso es el que demuestra la tesis del proyecto: la autorización
depende de *quién eres realmente* (identidad de proceso resuelta por el
broker), no de lo que dices ser al conectarte.

## Qué pasa internamente, paso a paso

Trazado sobre el caso `evil-demo.exe demo read`:

1. **El cliente conecta y manda la petición.** `demo-client` llama a
   `broker_ipc::connect()` y `send_message(&stream, &request)`
   (`crates/broker-ipc/src/lib.rs:68`), mandando
   `{"provider":"demo","op":"read"}` como una línea de JSON. El
   protocolo no tiene ningún campo de identidad — el cliente nunca dice
   quién es.

2. **El daemon acepta la conexión.** `listener.accept()`
   (`daemon/src/main.rs:76`) bloquea hasta que llega esa conexión y
   devuelve un `Stream`.

3. **El daemon pregunta al sistema operativo quién es, no al cliente.**
   `broker_ipc::peer_creds(&stream)` (`crates/broker-ipc/src/lib.rs:37`)
   llama a `interprocess::PeerCreds`, que por debajo usa
   `GetNamedPipeClientProcessId` en Windows (o `SO_PEERCRED` en Linux)
   — una llamada al **kernel**, sobre el socket ya conectado. El PID no
   es un dato que el proceso conectado elija o pueda falsear: el kernel
   ya sabe qué proceso hizo la llamada `connect()`, porque es él quien
   la atendió.

4. **De PID a ruta del ejecutable.** `CallerIdentity::new(pid, uid)`
   (`crates/broker-identity/src/lib.rs:24`) llama a
   `resolve_exe_path(pid)` (línea 44 en Windows: `OpenProcess` +
   `QueryFullProcessImageNameW`) — una **segunda** consulta al kernel,
   esta vez para traducir "PID 4821" en
   "`C:\...\AppData\Local\Temp\evil\evil-demo.exe`". Esta ruta es lo que
   la política puede razonar; el PID por sí solo no tiene significado
   duradero (ver más abajo).

5. **Se construye la clave de política.** `identity.policy_key()`
   (línea 34) devuelve esa ruta completa como string.

6. **Dispatch: primero el adapter, luego la política.**
   `manager.dispatch("demo", operation, &identity)`
   (`crates/broker-core/src/lib.rs:85`) encuentra el `DemoAdapter`
   registrado, calcula `capability = "demo.read"`, y llama a
   `policy.evaluate(&caller_key, &capability)`.

7. **La política no reconoce esa ruta.** `PolicyEngine::evaluate`
   (`crates/broker-policy/src/lib.rs:39`) busca la ruta de
   `evil-demo.exe` en su tabla de reglas. Solo hay una regla cargada,
   para la ruta exacta de `demo-client.exe` (la que el daemon registra
   al arrancar, ver `expected_demo_client_path()` en
   `daemon/src/main.rs`) → no hay coincidencia → `Decision::Deny`.

8. **Se audita antes de actuar sobre la decisión.**
   `self.audit.record(...)` (línea 102) se ejecuta con `decision=DENY`
   incondicionalmente — esto es lo que cierra INV-004: la denegación
   queda registrada igual que habría quedado un permiso.

9. **Nunca se llega a ejecutar el adapter.** Al ser `Deny`, `dispatch()`
   devuelve `Err(DispatchError::Denied)` sin llamar a
   `adapter.execute()` en ningún momento.

10. **La respuesta vuelve al cliente.** `handle_request`
    (`daemon/src/main.rs:119`) traduce el error a
    `Response { status: Denied, result: null }`, y `demo-client` la
    imprime.

## PID y "identidad": qué relación tienen exactamente

Un PID es un número que el kernel asigna al crear un proceso y libera
cuando termina — no es un dato que el proceso conozca de antemano ni
pueda elegir. Por eso `GetNamedPipeClientProcessId`/`SO_PEERCRED` no se
pueden falsear desde el proceso conectado: la respuesta sale de la
propia tabla de procesos del kernel, no de nada que viaje por el canal
que controla el cliente (a diferencia de, por ejemplo, un header HTTP
`X-Process-Id`, que el cliente pondría libremente).

Pero el PID en sí **no es la identidad** que le interesa a la política
— es un puntero efímero, válido solo "ahora mismo, para este proceso
concreto". Por eso el diseño usa el PID en dos pasos separados:

1. El kernel da un PID que no se puede falsear (paso 3 arriba).
2. Con ese PID se hace una **segunda** consulta al kernel — "¿qué
   ejecutable tiene cargado el proceso que ahora mismo tiene este PID?"
   (paso 4) — para llegar a algo duradero y legible (la ruta), que es
   lo que se puede escribir en una regla de política.

### Riesgo conocido: la ventana entre esos dos pasos

Los pasos 3 y 4 no son atómicos — pasa tiempo real de CPU entre uno y
otro. Si el proceso original muriera justo en ese hueco y el kernel
reasignara ese mismo PID a otro proceso antes del paso 4,
`OpenProcess(pid)` abriría el proceso equivocado y le atribuiría su
ruta al caller original.

En la práctica esto casi nunca es explotable: el descriptor de la
conexión vive dentro del proceso que conectó, así que para que la
conexión siga abierta, ese proceso tiene que seguir vivo (salvo que el
handle se haya filtrado a otro proceso a propósito — la propia
documentación de `interprocess::PeerCreds` señala exactamente este
caso). Sigue siendo una asunción, no una garantía matemática, así que
queda anotado como riesgo conocido en
[docs/threat-model.md](threat-model.md) en vez de darlo por resuelto.
