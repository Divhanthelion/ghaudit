//! A GitHub token the user typed in, kept in the operating system's credential store:
//! Windows Credential Manager, the macOS Keychain or the Secret Service on Linux. Never
//! in a file: where no store is available, a token can't be saved and the page says so.

use keyring_core::{CredentialStore, Entry};
use std::sync::{Arc, OnceLock};

const SERVICE: &str = "io.github.divhanthelion.ghaudit";
const ACCOUNT: &str = "github-token";

/// Whether this system has a credential store the app can use.
pub fn available() -> bool {
    store().is_some()
}

/// The saved token, if any.
pub fn get() -> Result<Option<String>, String> {
    if store().is_none() {
        return Ok(None);
    }
    match entry()?.get_password() {
        Ok(token) => Ok(Some(token)),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!(
            "Couldn't read the token from the system keychain: {e}"
        )),
    }
}

pub fn set(token: &str) -> Result<(), String> {
    entry()?
        .set_password(token)
        .map_err(|e| format!("Couldn't save the token in the system keychain: {e}"))
}

pub fn delete() -> Result<(), String> {
    if store().is_none() {
        return Ok(());
    }
    match entry()?.delete_credential() {
        Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!(
            "Couldn't remove the token from the system keychain: {e}"
        )),
    }
}

fn entry() -> Result<Entry, String> {
    let store = store().ok_or("This system has no keychain to keep a token in.")?;
    store
        .build(SERVICE, ACCOUNT, None)
        .map_err(|e| format!("System keychain: {e}"))
}

/// The platform's credential store, set up once; `None` where it can't be used.
fn store() -> Option<&'static Arc<CredentialStore>> {
    static STORE: OnceLock<Option<Arc<CredentialStore>>> = OnceLock::new();
    STORE
        .get_or_init(|| {
            // Store setup talks to the OS (D-Bus on Linux); never let it take the app down.
            std::panic::catch_unwind(platform_store).ok().flatten()
        })
        .as_ref()
}

#[cfg(target_os = "windows")]
fn platform_store() -> Option<Arc<CredentialStore>> {
    Some(windows_native_keyring_store::Store::new().ok()?)
}

#[cfg(target_os = "macos")]
fn platform_store() -> Option<Arc<CredentialStore>> {
    Some(apple_native_keyring_store::keychain::Store::new().ok()?)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_store() -> Option<Arc<CredentialStore>> {
    let store: Arc<CredentialStore> = zbus_secret_service_keyring_store::Store::new().ok()?;
    // A Secret Service that exists but can't store anything (locked, or blocked by a
    // sandbox) is worse than none: check that it works before trusting it.
    let probe = store.build(SERVICE, "probe", None).ok()?;
    probe.set_password("ok").ok()?;
    let _ = probe.delete_credential();
    Some(store)
}
