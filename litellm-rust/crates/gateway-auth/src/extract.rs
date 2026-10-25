use std::borrow::Cow;

use axum::http::{HeaderName, request::Parts};
use litellm_auth_types::SecretValue;
use url::form_urlencoded;

use crate::{Credential, CredentialExtractor, Error};

#[derive(Clone, Default)]
pub struct PythonHeaders {
    custom_header: Option<HeaderName>,
}

impl PythonHeaders {
    pub fn new(custom_header: Option<HeaderName>) -> Self {
        Self { custom_header }
    }
}

impl CredentialExtractor for PythonHeaders {
    fn extract(&self, parts: &Parts) -> Result<Credential, Error> {
        let custom_value = self
            .custom_header
            .as_ref()
            .map(|name| selected_header_value(parts, name, false))
            .transpose()?
            .flatten();
        let token = match custom_value {
            Some(value) => strict_credential(value)?,
            None => standard_credential(parts)?,
        };
        Ok(Credential::Token(SecretValue::new(token)))
    }
}

fn standard_credential(parts: &Parts) -> Result<String, Error> {
    if let Some(value) = standard_header(parts, "x-litellm-api-key")? {
        return permissive_credential(value);
    }
    if let Some(value) = standard_header(parts, "authorization")? {
        return strict_credential(value);
    }
    if let Some(value) = standard_header(parts, "api-key")? {
        return raw_credential(value);
    }
    if let Some(value) = standard_header(parts, "x-api-key")? {
        return raw_credential(value);
    }
    if let Some(value) = standard_header(parts, "x-goog-api-key")? {
        return raw_credential(value);
    }
    if let Some(value) = standard_header(parts, "ocp-apim-subscription-key")? {
        return raw_credential(value);
    }
    query_credential(parts).ok_or(Error::InvalidToken)
}

fn standard_header<'a>(parts: &'a Parts, name: &'static str) -> Result<Option<&'a str>, Error> {
    selected_header_value(parts, &HeaderName::from_static(name), true)
}

fn selected_header_value<'a>(
    parts: &'a Parts,
    name: &HeaderName,
    empty_is_missing: bool,
) -> Result<Option<&'a str>, Error> {
    let values = parts
        .headers
        .get_all(name)
        .iter()
        .map(|value| value.to_str().map_err(|_| Error::InvalidToken))
        .collect::<Result<Vec<_>, _>>()?;
    if values.is_empty() {
        return Ok(None);
    }
    if empty_is_missing && values.iter().all(|value| value.is_empty()) {
        return Ok(None);
    }
    if values.len() != 1 {
        return Err(Error::InvalidToken);
    }
    Ok(Some(values[0]))
}

fn strict_credential(value: &str) -> Result<String, Error> {
    let token = if value.starts_with("Bearer ") {
        value.replace("Bearer ", "")
    } else if value.starts_with("Basic ") {
        value.replace("Basic ", "")
    } else if value.starts_with("bearer ") {
        value.replace("bearer ", "")
    } else if value.starts_with("AWS4-HMAC-SHA256") {
        aws4_credential(value)
            .map(str::to_owned)
            .ok_or(Error::InvalidToken)?
    } else {
        return Err(Error::InvalidToken);
    };
    if token.is_empty() {
        return Err(Error::InvalidToken);
    }
    Ok(token)
}

fn permissive_credential(value: &str) -> Result<String, Error> {
    let token = if value.starts_with("Bearer ") {
        Cow::Owned(value.replace("Bearer ", ""))
    } else if value.starts_with("Basic ") {
        Cow::Owned(value.replace("Basic ", ""))
    } else if value.starts_with("bearer ") {
        Cow::Owned(value.replace("bearer ", ""))
    } else if value.starts_with("AWS4-HMAC-SHA256") {
        Cow::Borrowed(aws4_credential(value).unwrap_or(value))
    } else {
        Cow::Borrowed(value)
    };
    if token.is_empty() {
        return Err(Error::InvalidToken);
    }
    Ok(token.into_owned())
}

fn raw_credential(value: &str) -> Result<String, Error> {
    if value.is_empty() {
        return Err(Error::InvalidToken);
    }
    Ok(value.to_owned())
}

fn aws4_credential(value: &str) -> Option<&str> {
    const PREFIX: &str = "Credential=";

    value
        .match_indices(PREFIX)
        .find_map(|(index, _)| aws4_bearer_token(&value[index + PREFIX.len()..]))
        .or_else(|| {
            value
                .match_indices(PREFIX)
                .find_map(|(index, _)| aws4_token(&value[index + PREFIX.len()..]))
        })
}

fn aws4_bearer_token(value: &str) -> Option<&str> {
    let value = value.strip_prefix("Bearer")?;
    let (whitespace_start, _) = value
        .char_indices()
        .find(|(_, character)| !character.is_whitespace())?;
    if whitespace_start == 0 {
        return None;
    }
    aws4_token(&value[whitespace_start..])
}

fn aws4_token(value: &str) -> Option<&str> {
    let end = value
        .find(|character: char| character.is_whitespace() || character == '/' || character == ',')
        .unwrap_or(value.len());
    let token = value.get(..end)?;
    (!token.is_empty()).then_some(token)
}

fn query_credential(parts: &Parts) -> Option<String> {
    let path = parts.uri.path();
    if !path.contains("generateContent") && !path.contains("streamGenerateContent") {
        return None;
    }
    let query = parts.uri.query()?;
    form_urlencoded::parse(query.as_bytes())
        .filter(|(name, _)| name == "key")
        .map(|(_, value)| value.into_owned())
        .last()
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderName, HeaderValue, Request, request::Parts};
    use rstest::rstest;

    use super::*;

    fn request_parts(uri: &str, headers: &[(&str, &str)]) -> Parts {
        let (mut parts, _) = Request::builder()
            .uri(uri)
            .body(())
            .expect("request")
            .into_parts();
        for (name, value) in headers {
            parts.headers.append(
                HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                HeaderValue::from_bytes(value.as_bytes()).expect("header value"),
            );
        }
        parts
    }

    fn token_text(extractor: &PythonHeaders, parts: &Parts) -> Result<String, Error> {
        match extractor.extract(parts)? {
            Credential::Token(token) => Ok(token.expose().to_owned()),
            Credential::Transport => Err(Error::InvalidToken),
        }
    }

    #[rstest]
    fn raw_litellm_header_is_accepted() {
        let parts = request_parts(
            "/v1/chat/completions",
            &[("x-litellm-api-key", "raw-token")],
        );

        assert_eq!(
            token_text(&PythonHeaders::default(), &parts).expect("token"),
            "raw-token"
        );
    }

    #[rstest]
    fn generic_api_key_header_is_kept_raw() {
        let parts = request_parts("/v1/chat/completions", &[("api-key", " raw token ")]);

        assert_eq!(
            token_text(&PythonHeaders::default(), &parts).expect("token"),
            " raw token "
        );
    }

    #[rstest]
    #[case::bearer("Bearer token", "token")]
    #[case::basic_payload_is_not_decoded("Basic dXNlcjpwYXNz", "dXNlcjpwYXNz")]
    #[case::lowercase_bearer("bearer token", "token")]
    #[case::replace_every_prefix("Bearer token Bearer suffix", "token suffix")]
    #[case::aws4_bearer(
        "AWS4-HMAC-SHA256 Credential=Bearer token/date/region/service/aws4_request, SignedHeaders=host, Signature=sig",
        "token"
    )]
    #[case::aws4_raw(
        "AWS4-HMAC-SHA256 Credential=raw-token/date/region/service/aws4_request, SignedHeaders=host, Signature=sig",
        "raw-token"
    )]
    #[case::preserve_trailing_whitespace("Bearer token ", "token ")]
    fn authorization_uses_strict_python_parser(#[case] value: &str, #[case] expected: &str) {
        let parts = request_parts("/v1/chat/completions", &[("authorization", value)]);

        assert_eq!(
            token_text(&PythonHeaders::default(), &parts).expect("token"),
            expected
        );
    }

    #[rstest]
    #[case::raw("raw-token", "raw-token")]
    #[case::bearer("Bearer token", "token")]
    #[case::basic_payload_is_not_decoded("Basic dXNlcjpwYXNz", "dXNlcjpwYXNz")]
    #[case::lowercase_bearer("bearer token", "token")]
    #[case::aws4_bearer(
        "AWS4-HMAC-SHA256 Credential=Bearer token/date/region/service/aws4_request, SignedHeaders=host, Signature=sig",
        "token"
    )]
    #[case::aws4_raw(
        "AWS4-HMAC-SHA256 Credential=raw-token/date/region/service/aws4_request, SignedHeaders=host, Signature=sig",
        "raw-token"
    )]
    #[case::aws4_without_credential_is_raw(
        "AWS4-HMAC-SHA256 malformed",
        "AWS4-HMAC-SHA256 malformed"
    )]
    #[case::preserve_whitespace(" raw-token ", " raw-token ")]
    fn litellm_header_uses_permissive_python_parser(#[case] value: &str, #[case] expected: &str) {
        let parts = request_parts("/v1/chat/completions", &[("x-litellm-api-key", value)]);

        assert_eq!(
            token_text(&PythonHeaders::default(), &parts).expect("token"),
            expected
        );
    }

    #[rstest]
    #[case::custom_over_litellm(
        Some("x-custom-key"),
        &[("x-custom-key", "Bearer custom"), ("x-litellm-api-key", "lower")],
        "/v1/chat/completions",
        "custom"
    )]
    #[case::custom_over_authorization(
        Some("x-custom-key"),
        &[("x-custom-key", "Bearer custom"), ("authorization", "Bearer lower")],
        "/v1/chat/completions",
        "custom"
    )]
    #[case::custom_over_api_key(
        Some("x-custom-key"),
        &[("x-custom-key", "Bearer custom"), ("api-key", "lower")],
        "/v1/chat/completions",
        "custom"
    )]
    #[case::custom_over_x_api_key(
        Some("x-custom-key"),
        &[("x-custom-key", "Bearer custom"), ("x-api-key", "lower")],
        "/v1/chat/completions",
        "custom"
    )]
    #[case::custom_over_google(
        Some("x-custom-key"),
        &[("x-custom-key", "Bearer custom"), ("x-goog-api-key", "lower")],
        "/v1/chat/completions",
        "custom"
    )]
    #[case::custom_over_apim(
        Some("x-custom-key"),
        &[("x-custom-key", "Bearer custom"), ("ocp-apim-subscription-key", "lower")],
        "/v1/chat/completions",
        "custom"
    )]
    #[case::custom_over_query(
        Some("x-custom-key"),
        &[("x-custom-key", "Bearer custom")],
        "/v1beta/models/g:generateContent?key=query",
        "custom"
    )]
    #[case::litellm_over_authorization(
        None,
        &[("x-litellm-api-key", "litellm"), ("authorization", "Bearer lower")],
        "/v1/chat/completions",
        "litellm"
    )]
    #[case::litellm_over_api_key(
        None,
        &[("x-litellm-api-key", "litellm"), ("api-key", "lower")],
        "/v1/chat/completions",
        "litellm"
    )]
    #[case::litellm_over_x_api_key(
        None,
        &[("x-litellm-api-key", "litellm"), ("x-api-key", "lower")],
        "/v1/chat/completions",
        "litellm"
    )]
    #[case::litellm_over_google(
        None,
        &[("x-litellm-api-key", "litellm"), ("x-goog-api-key", "lower")],
        "/v1/chat/completions",
        "litellm"
    )]
    #[case::litellm_over_apim(
        None,
        &[("x-litellm-api-key", "litellm"), ("ocp-apim-subscription-key", "lower")],
        "/v1/chat/completions",
        "litellm"
    )]
    #[case::litellm_over_query(
        None,
        &[("x-litellm-api-key", "litellm")],
        "/v1beta/models/g:generateContent?key=query",
        "litellm"
    )]
    #[case::authorization_over_api_key(
        None,
        &[("authorization", "Bearer authorization"), ("api-key", "lower")],
        "/v1/chat/completions",
        "authorization"
    )]
    #[case::authorization_over_x_api_key(
        None,
        &[("authorization", "Bearer authorization"), ("x-api-key", "lower")],
        "/v1/chat/completions",
        "authorization"
    )]
    #[case::authorization_over_google(
        None,
        &[("authorization", "Bearer authorization"), ("x-goog-api-key", "lower")],
        "/v1/chat/completions",
        "authorization"
    )]
    #[case::authorization_over_apim(
        None,
        &[("authorization", "Bearer authorization"), ("ocp-apim-subscription-key", "lower")],
        "/v1/chat/completions",
        "authorization"
    )]
    #[case::authorization_over_query(
        None,
        &[("authorization", "Bearer authorization")],
        "/v1beta/models/g:generateContent?key=query",
        "authorization"
    )]
    #[case::api_key_over_x_api_key(
        None,
        &[("api-key", "api-key"), ("x-api-key", "lower")],
        "/v1/chat/completions",
        "api-key"
    )]
    #[case::api_key_over_google(
        None,
        &[("api-key", "api-key"), ("x-goog-api-key", "lower")],
        "/v1/chat/completions",
        "api-key"
    )]
    #[case::api_key_over_apim(
        None,
        &[("api-key", "api-key"), ("ocp-apim-subscription-key", "lower")],
        "/v1/chat/completions",
        "api-key"
    )]
    #[case::api_key_over_query(
        None,
        &[("api-key", "api-key")],
        "/v1beta/models/g:generateContent?key=query",
        "api-key"
    )]
    #[case::x_api_key_over_google(
        None,
        &[("x-api-key", "x-api"), ("x-goog-api-key", "lower")],
        "/v1/chat/completions",
        "x-api"
    )]
    #[case::x_api_key_over_apim(
        None,
        &[("x-api-key", "x-api"), ("ocp-apim-subscription-key", "lower")],
        "/v1/chat/completions",
        "x-api"
    )]
    #[case::x_api_key_over_query(
        None,
        &[("x-api-key", "x-api")],
        "/v1beta/models/g:generateContent?key=query",
        "x-api"
    )]
    #[case::google_over_apim(
        None,
        &[("x-goog-api-key", "google"), ("ocp-apim-subscription-key", "lower")],
        "/v1/chat/completions",
        "google"
    )]
    #[case::google_over_query(
        None,
        &[("x-goog-api-key", "google")],
        "/v1beta/models/g:generateContent?key=query",
        "google"
    )]
    #[case::apim_over_query(
        None,
        &[("ocp-apim-subscription-key", "apim")],
        "/v1beta/models/g:generateContent?key=query",
        "apim"
    )]
    fn higher_priority_credential_wins(
        #[case] custom_header: Option<&str>,
        #[case] headers: &[(&str, &str)],
        #[case] uri: &str,
        #[case] expected: &str,
    ) {
        let extractor = PythonHeaders::new(
            custom_header
                .map(|name| HeaderName::from_bytes(name.as_bytes()).expect("custom header name")),
        );
        let parts = request_parts(uri, headers);

        assert_eq!(token_text(&extractor, &parts).expect("token"), expected);
    }

    #[rstest]
    fn absent_custom_header_falls_back_to_standard_headers() {
        let extractor = PythonHeaders::new(Some(HeaderName::from_static("x-custom-key")));
        let parts = request_parts(
            "/v1/chat/completions",
            &[("authorization", "Bearer standard")],
        );

        assert_eq!(
            token_text(&extractor, &parts).expect("fallback token"),
            "standard"
        );
    }

    #[rstest]
    #[case::empty("")]
    #[case::raw("not-a-bearer-token")]
    fn malformed_custom_header_overrides_lower_priority_headers(#[case] value: &str) {
        let extractor = PythonHeaders::new(Some(HeaderName::from_static("x-custom-key")));
        let parts = request_parts(
            "/v1/chat/completions",
            &[
                ("x-custom-key", value),
                ("authorization", "Bearer lower-priority"),
            ],
        );

        assert!(matches!(
            token_text(&extractor, &parts),
            Err(Error::InvalidToken)
        ));
    }

    #[rstest]
    #[case::raw_authorization("raw-token")]
    #[case::empty_bearer("Bearer ")]
    #[case::missing_aws_credential("AWS4-HMAC-SHA256")]
    fn malformed_selected_authorization_does_not_fall_through(#[case] value: &str) {
        let parts = request_parts(
            "/v1/chat/completions",
            &[("authorization", value), ("api-key", "lower-priority")],
        );

        assert!(matches!(
            token_text(&PythonHeaders::default(), &parts),
            Err(Error::InvalidToken)
        ));
    }

    #[rstest]
    #[case::empty_litellm(
        &[("x-litellm-api-key", ""), ("authorization", "Bearer fallback")],
        "/v1/chat/completions",
        "fallback"
    )]
    #[case::duplicate_empty_headers_are_missing(
        &[
            ("x-litellm-api-key", ""),
            ("x-litellm-api-key", ""),
            ("authorization", "Bearer fallback")
        ],
        "/v1/chat/completions",
        "fallback"
    )]
    #[case::empty_authorization(
        &[("authorization", ""), ("api-key", "fallback")],
        "/v1/chat/completions",
        "fallback"
    )]
    #[case::empty_api_key(
        &[("api-key", ""), ("x-api-key", "fallback")],
        "/v1/chat/completions",
        "fallback"
    )]
    #[case::empty_x_api_key(
        &[("x-api-key", ""), ("x-goog-api-key", "fallback")],
        "/v1/chat/completions",
        "fallback"
    )]
    #[case::empty_google(
        &[("x-goog-api-key", ""), ("ocp-apim-subscription-key", "fallback")],
        "/v1/chat/completions",
        "fallback"
    )]
    #[case::empty_apim(
        &[("ocp-apim-subscription-key", "")],
        "/v1beta/models/g:generateContent?key=fallback",
        "fallback"
    )]
    fn empty_standard_headers_are_missing(
        #[case] headers: &[(&str, &str)],
        #[case] uri: &str,
        #[case] expected: &str,
    ) {
        let parts = request_parts(uri, headers);

        assert_eq!(
            token_text(&PythonHeaders::default(), &parts).expect("fallback token"),
            expected
        );
    }

    #[rstest]
    #[case::litellm("x-litellm-api-key", "first", "second")]
    #[case::authorization("authorization", "Bearer first", "Bearer second")]
    #[case::api_key("api-key", "first", "second")]
    fn duplicate_selected_headers_fail_closed(
        #[case] name: &str,
        #[case] first: &str,
        #[case] second: &str,
    ) {
        let parts = request_parts("/v1/chat/completions", &[(name, first), (name, second)]);

        assert!(matches!(
            token_text(&PythonHeaders::default(), &parts),
            Err(Error::InvalidToken)
        ));
    }

    #[rstest]
    fn duplicate_custom_header_fails_closed() {
        let extractor = PythonHeaders::new(Some(HeaderName::from_static("x-custom-key")));
        let parts = request_parts(
            "/v1/chat/completions",
            &[
                ("x-custom-key", "Bearer first"),
                ("x-custom-key", "Bearer second"),
                ("authorization", "Bearer lower"),
            ],
        );

        assert!(matches!(
            token_text(&extractor, &parts),
            Err(Error::InvalidToken)
        ));
    }

    #[rstest]
    fn lower_priority_duplicates_do_not_defeat_valid_litellm_header() {
        let parts = request_parts(
            "/v1/chat/completions",
            &[
                ("x-litellm-api-key", "selected"),
                ("authorization", "Bearer first"),
                ("authorization", "Bearer second"),
            ],
        );

        assert_eq!(
            token_text(&PythonHeaders::default(), &parts).expect("selected token"),
            "selected"
        );
    }

    #[rstest]
    #[case::generate_content("/v1beta/models/g:generateContent?key=query+token", "query token")]
    #[case::stream_generate_content(
        "/v1beta/models/g:streamGenerateContent?key=query%2Ftoken",
        "query/token"
    )]
    fn gemini_query_key_uses_form_decoding(#[case] uri: &str, #[case] expected: &str) {
        let parts = request_parts(uri, &[]);

        assert_eq!(
            token_text(&PythonHeaders::default(), &parts).expect("query token"),
            expected
        );
    }

    #[rstest]
    fn last_gemini_query_key_wins() {
        let parts = request_parts("/v1beta/models/g:generateContent?key=first&key=last", &[]);

        assert_eq!(
            token_text(&PythonHeaders::default(), &parts).expect("query token"),
            "last"
        );
    }

    #[rstest]
    fn empty_last_gemini_query_key_does_not_reuse_earlier_value() {
        let parts = request_parts("/v1beta/models/g:generateContent?key=first&key=", &[]);

        assert!(matches!(
            token_text(&PythonHeaders::default(), &parts),
            Err(Error::InvalidToken)
        ));
    }

    #[rstest]
    fn query_key_is_ignored_outside_gemini_routes() {
        let parts = request_parts("/v1/chat/completions?key=query", &[]);

        assert!(matches!(
            token_text(&PythonHeaders::default(), &parts),
            Err(Error::InvalidToken)
        ));
    }
}
