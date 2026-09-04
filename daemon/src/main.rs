use broker_core::CredentialManager;
use broker_policy::PolicyEngine;

fn main() {
    let policy = PolicyEngine::new();
    let mut manager = CredentialManager::new(policy);

    manager.register(Box::new(provider_ssh::SshAdapter::new()));
    manager.register(Box::new(provider_totp::TotpAdapter::new()));
    manager.register(Box::new(provider_github::GithubAdapter::new()));

    println!("cred-broker-daemon — esqueleto inicial");
    println!("adapters registrados:");
    for cap in manager.capabilities() {
        println!("  - {} ({})", cap.name, cap.description);
    }
    println!();
    println!("TODO: levantar el listener IPC (crates/broker-ipc) y resolver la identidad");
    println!("de proceso (crates/broker-identity) en cada conexión antes de llamar a");
    println!("manager.dispatch(...).");
}
