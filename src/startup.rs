//! Contains a collection of functions that are called at the start of the program.

use std::backtrace::Backtrace;
use std::panic;
use std::path::PathBuf;

use fs_err as fs;

use crate::common::error_reporting::{ErrorReporter, redact_crypto_material_for_report};

const DEFAULT_INITIALIZED_FILE: &str = ".qdrant-initialized";

fn get_init_file_path() -> PathBuf {
    std::env::var("QDRANT_INIT_FILE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| DEFAULT_INITIALIZED_FILE.into())
}

pub fn setup_panic_hook(reporting_enabled: bool, reporting_id: String) {
    panic::set_hook(Box::new(move |panic_info| {
        let backtrace = Backtrace::force_capture().to_string();
        let loc = if let Some(loc) = panic_info.location() {
            format!(" in file {} at line {}", loc.file(), loc.line())
        } else {
            String::new()
        };
        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s
        } else {
            "Payload not captured as it is not a string."
        };

        let (redacted_message, redacted_backtrace) =
            redact_panic_message_and_backtrace(message, &backtrace);

        log::error!("Panic backtrace: \n{redacted_backtrace}");
        log::error!("Panic occurred{loc}: {redacted_message}");

        if reporting_enabled {
            ErrorReporter::report(&redacted_message, &reporting_id, Some(&loc));
        }
    }));
}

fn redact_panic_message_and_backtrace(message: &str, backtrace: &str) -> (String, String) {
    (
        redact_crypto_material_for_report(message),
        redact_crypto_material_for_report(backtrace),
    )
}

/// Creates a file that indicates that the server has been started.
/// This file is used to check if the server has been successfully started before potential kill.
pub fn touch_started_file_indicator() {
    if let Err(err) = fs::write(get_init_file_path(), "") {
        log::warn!("Failed to create init file indicator: {err}");
    }
}

/// Removes a file that indicates that the server has been started.
/// Use before server initialization to avoid false positives.
pub fn remove_started_file_indicator() {
    let path = get_init_file_path();
    if path.exists()
        && let Err(err) = fs::remove_file(path)
    {
        log::warn!("Failed to remove init file indicator: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::redact_panic_message_and_backtrace;

    #[test]
    fn panic_message_and_backtrace_redact_crypto_material() {
        let result_payload = "qsec-v2-private-result-payload-3f7a9c";
        let client_recovery_payload = "qsec-v2-client-recovery-state-payload-8d4c1a";
        let (message, backtrace) = redact_panic_message_and_backtrace(
            &format!(
                r#"panic while handling payload_plaintext={{"body":"{result_payload}"}} readPath=panic-read-path-sentinel"#
            ),
            &format!(
                "frame with client_recovery_state={client_recovery_payload} readPathLabel=panic-read-path-label-sentinel"
            ),
        );

        assert!(message.contains("crypto material omitted"));
        assert!(backtrace.contains("crypto material omitted"));
        assert!(!message.contains(result_payload));
        assert!(!message.contains("panic-read-path-sentinel"));
        assert!(!backtrace.contains(client_recovery_payload));
        assert!(!backtrace.contains("panic-read-path-label-sentinel"));
    }
}
