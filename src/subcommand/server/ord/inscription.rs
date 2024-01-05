use {
  super::{error::ApiError, *},
  crate::{
    index::InscriptionEntry,
  },
  axum::Json,
  utoipa::ToSchema,
};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(as = ord::OrdInscription)]
#[serde(rename_all = "camelCase")]
pub struct OrdInscription {
  /// The inscription id.
  pub id: String,
  /// The inscription number.
  pub number: i64,
  /// The inscription content type.
  pub content_type: Option<String>,
  /// The inscription content body.
  pub content: Option<String>,
  /// The inscription owner.
  pub owner: Option<Address>,
  /// The inscription genesis block height.
  #[schema(format = "uint64")]
  pub genesis_height: u64,
  /// The inscription location.
  pub location: String,
  /// Collections of Inscriptions.
  pub collections: Vec<String>,
  /// The inscription sat index.  
  pub sat: Option<u64>,
}

