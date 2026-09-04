//! Resuelve la identidad del proceso conectado al otro lado del IPC.
//!
//! El PID/UID llegan de verdad desde el transporte (`interprocess::PeerCreds`,
//! que usa `SO_PEERCRED` en Linux y `GetNamedPipeClientProcessId` en Windows
//! por debajo). La ruta del ejecutable se resuelve aparte, a partir del PID,
//! porque el crate de transporte no la da.
//!
//! Estado por plataforma:
//! - Windows: implementado (`OpenProcess` + `QueryFullProcessImageNameW`).
//! - Linux: implementado (`/proc/<pid>/exe`), sin verificar en esta máquina.
//! - macOS: TODO — necesita `proc_pidpath` (libproc), sin implementar
//!   todavía porque no se puede verificar aquí.

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerIdentity {
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub exe_path: Option<PathBuf>,
}

impl CallerIdentity {
    pub fn new(pid: Option<u32>, uid: Option<u32>) -> Self {
        let exe_path = pid.and_then(resolve_exe_path);
        Self { pid, uid, exe_path }
    }

    /// Clave que usa el motor de políticas para buscar reglas. Prefiere la
    /// ruta del ejecutable (lo ideal); cae a `pid:<n>` si no se pudo
    /// resolver, y a "unknown" si ni siquiera hay PID — en ambos casos de
    /// fallback, las reglas configuradas no van a coincidir y la política
    /// deniega por defecto (ver `PolicyEngine::evaluate`).
    pub fn policy_key(&self) -> String {
        match (&self.exe_path, self.pid) {
            (Some(path), _) => path.to_string_lossy().into_owned(),
            (None, Some(pid)) => format!("pid:{pid}"),
            (None, None) => "unknown".to_string(),
        }
    }
}

#[cfg(target_os = "windows")]
fn resolve_exe_path(pid: u32) -> Option<PathBuf> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }

        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(handle);

        if ok == 0 {
            return None;
        }
        Some(PathBuf::from(String::from_utf16_lossy(&buf[..size as usize])))
    }
}

#[cfg(target_os = "linux")]
fn resolve_exe_path(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn resolve_exe_path(_pid: u32) -> Option<PathBuf> {
    None
}
