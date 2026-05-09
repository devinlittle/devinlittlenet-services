// used in gradegetter_backend/routes/auth.rs

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
pub struct SchoologyLogin {
    #[schema(example = "email@exmaple.com")]
    pub schoology_email: String,
    #[schema(example = "password")]
    pub schoology_password: String,
}

// used in gradegetter_backend/routes/internal.rs
#[derive(Deserialize, ToSchema)]
pub struct ForwardMessage {
    pub id: Uuid,
    pub status: ForwardStatus,
}

#[derive(Serialize, Deserialize, ToSchema, Debug, Clone, PartialEq, Display, EnumString)]
pub enum ForwardStatus {
    #[serde(rename = "Started,1")]
    Started,
    #[serde(rename = "Navigated to Schoology login,2")]
    Navigated,
    #[serde(rename = "Typed in Email,3")]
    TypedEmail,
    #[serde(rename = "Entered Email,4")]
    EnteredEmail,
    #[serde(rename = "Typed in Password,5")]
    TypedPassword,
    #[serde(rename = "Enter Password,6")]
    EnteredPassword,
    #[serde(rename = "Finished,7")]
    Finished,
    #[serde(rename = "Incorrect Email or Password,E")]
    ErrorInSetup,
}
