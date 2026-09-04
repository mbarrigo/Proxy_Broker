//! Log de auditoría append-only. Registra cada decisión de política —
//! nunca el secreto en sí.
//!
//! TODO: fichero append-only con rotación en vez de stdout.

use std::io::Write;

pub struct AuditEntry<'a> {
    pub caller_exe: &'a str,
    pub provider: &'a str,
    pub action: &'a str,
    pub decision: &'a str,
}

pub trait AuditSink: Send + Sync {
    fn record(&self, entry: &AuditEntry);
}

#[derive(Default)]
pub struct StdoutSink;

impl AuditSink for StdoutSink {
    fn record(&self, entry: &AuditEntry) {
        let _ = writeln!(
            std::io::stdout(),
            "[audit] caller={} provider={} action={} decision={}",
            entry.caller_exe, entry.provider, entry.action, entry.decision
        );
    }
}
