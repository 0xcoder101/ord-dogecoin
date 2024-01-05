use {
  super::{error::ApiError, *},
  axum::Json,
  utoipa::ToSchema,
};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[schema(as = ord::InscriptionDigest)]
#[serde(rename_all = "camelCase")]
pub struct InscriptionDigest {
  /// The inscription id.
  pub id: String,
  /// The inscription number.
  pub number: i64,
  /// The inscription location.
  pub location: String,
}
