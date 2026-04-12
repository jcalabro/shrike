#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse arbitrary bytes as token response -- must not panic
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(s) {
            // Token parsing/validation must not panic
            let _ = shrike_oauth::token::parse_token_response(
                json,
                "https://example.com/token",
                "https://example.com/revoke",
            );
        }
    }
});
