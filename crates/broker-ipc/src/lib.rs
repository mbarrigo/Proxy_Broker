//! Transporte IPC: socket local multiplataforma — Unix domain socket en
//! Linux/macOS, Named Pipe en Windows — vía el crate `interprocess`.
//!
//! Framing del mensaje: una línea de JSON por mensaje. Es un placeholder
//! deliberadamente simple (fácil de depurar a mano con `nc`/scripts);
//! sustituir por length-prefixed CBOR cuando el protocolo se estabilice
//! (ver blueprint, sección de protocolo IPC).
//!
//! TODO (ver docs/threat-model.md, riesgo de broker impersonation): esto
//! todavía no hace creación atómica del socket ni verifica quién es el
//! dueño de un socket ya existente antes de bindear.

use std::io::{self, BufRead, Write};

pub use interprocess::local_socket::{traits::Listener as ListenerExt, Listener, PeerCreds, Stream};
use interprocess::local_socket::{
    traits::{Stream as StreamExt, StreamCommon},
    GenericNamespaced, ListenerOptions, Name, ToNsName,
};

/// Nombre del socket — namespaced, se traduce a Named Pipe en Windows y a
/// un Unix domain socket (abstracto en Linux, en /tmp en el resto) en Unix.
pub const SOCKET_NAME: &str = "cred-broker.sock";

pub fn socket_name() -> io::Result<Name<'static>> {
    SOCKET_NAME.to_ns_name::<GenericNamespaced>()
}

pub fn bind() -> io::Result<Listener> {
    ListenerOptions::new().name(socket_name()?).create_sync()
}

pub fn connect() -> io::Result<Stream> {
    Stream::connect(socket_name()?)
}

pub fn peer_creds(stream: &Stream) -> io::Result<PeerCreds> {
    stream.peer_creds()
}

/// Petición del cliente al broker.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Request {
    /// Vacío para operaciones de meta-nivel (p.ej. "hello").
    #[serde(default)]
    pub provider: String,
    pub op: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// Respuesta del broker al cliente.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Response {
    pub status: ResponseStatus,
    #[serde(default)]
    pub result: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Ok,
    Denied,
    Error,
}

pub fn send_message<T: serde::Serialize>(mut writer: impl Write, msg: &T) -> io::Result<()> {
    let mut line = serde_json::to_string(msg).map_err(io::Error::other)?;
    line.push('\n');
    writer.write_all(line.as_bytes())
}

pub fn recv_message<T: serde::de::DeserializeOwned>(mut reader: impl BufRead) -> io::Result<T> {
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "conexión cerrada por el peer"));
    }
    serde_json::from_str(line.trim_end()).map_err(io::Error::other)
}
