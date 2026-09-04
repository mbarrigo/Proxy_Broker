//! Resuelve la identidad del proceso conectado al otro lado del IPC.
//!
//! TODO: implementar el wrapper multiplataforma real sobre `SO_PEERCRED`
//! (Linux), `getpeereid` (macOS/BSD) y `GetNamedPipeClientProcessId`
//! (Windows). De momento expone solo el tipo de datos y la firma.

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerIdentity {
    pub pid: u32,
    pub uid: u32,
    pub exe_path: PathBuf,
}

/// Placeholder del handle de conexión hasta que `ipc` defina el real.
pub type RawHandle = i32;

pub fn resolve_caller(_connection_handle: RawHandle) -> Result<CallerIdentity, ResolveError> {
    Err(ResolveError::NotImplemented)
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("resolución de identidad de proceso aún no implementada")]
    NotImplemented,
    #[error("no se pudo resolver la identidad del proceso llamante")]
    Unresolvable,
}
