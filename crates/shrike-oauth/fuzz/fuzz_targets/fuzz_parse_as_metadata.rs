#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse arbitrary bytes as AS metadata -- must not panic
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(meta) = serde_json::from_str::<shrike_oauth::AuthServerMetadata>(s) {
            // Validation must also not panic
            let _ = shrike_oauth::metadata::validate_auth_server_metadata(&meta);
        }
    }
});
