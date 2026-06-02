pub(crate) fn apply_user_agent(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    rb.header(reqwest::header::USER_AGENT, crate::USER_AGENT)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn apply_user_agent_sets_shrike_user_agent() {
        let request = apply_user_agent(reqwest::Client::new().get("https://example.com"))
            .build()
            .unwrap();
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::USER_AGENT)
                .and_then(|value| value.to_str().ok()),
            Some(crate::USER_AGENT)
        );
    }
}
