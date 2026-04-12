#![no_main]
use libfuzzer_sys::fuzz_target;
use shrike_crypto::P256SigningKey;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Use first 2 bytes to choose method and URL patterns
    let method = match data[0] % 4 {
        0 => "GET",
        1 => "POST",
        2 => "PUT",
        _ => "DELETE",
    };

    let url = match data[1] % 3 {
        0 => "https://example.com/token",
        1 => "https://example.com/path?query=value#fragment",
        _ => "https://example.com",
    };

    let nonce = if data[2] % 2 == 0 {
        Some(std::str::from_utf8(&data[3..]).unwrap_or("nonce"))
    } else {
        None
    };

    let token = if data.len() > 10 && data[3] % 2 == 0 {
        Some("test-access-token")
    } else {
        None
    };

    let key = P256SigningKey::generate();
    // Must not panic
    let _ = shrike_oauth::dpop::create_dpop_proof(&key, method, url, nonce, token);
});
