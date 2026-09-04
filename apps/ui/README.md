# UI de aprobación / gestión

Pendiente de empezar. Vive como proceso separado del daemon (habla con él
por el mismo socket/pipe, con un rol especial para responder a
peticiones de consentimiento, ver historial y revocar accesos), para que
un fallo de la UI nunca tumbe el broker.

Candidato natural: Wails (backend Go) sería la opción si el core fuera
Go; con el core en Rust, el equivalente es Tauri.
