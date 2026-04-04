use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Basic},
};
use base64::prelude::*;

pub async fn basic_auth(
    TypedHeader(Authorization(basic)): TypedHeader<Authorization<Basic>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let internal_api = BASE64_STANDARD
        .decode(dotenvy::var("INTERNAL_API_KEY").expect("INTERNAL_API_KEY var missing"))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let internal_api =
        String::from_utf8(internal_api).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let internal_api_username = internal_api
        .find(":")
        .map(|x| &internal_api[..x])
        .unwrap_or_default();

    let internal_api_password = internal_api
        .find(":")
        .map(|x| &internal_api[x + 1..])
        .unwrap_or_default();

    if basic.username() == internal_api_username && basic.password() == internal_api_password {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
