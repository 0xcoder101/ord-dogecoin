use bitcoin::{Address, Network, Script, ScriptHash};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use utoipa::ToSchema;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ScriptPubkey {
  /// Address.
  Address(String),
  /// Non-standard script hash.
  NonStandard(String),
}

impl Default for ScriptPubkey {
  fn default() -> Self {
    ScriptPubkey::NonStandard(String::new())
  }
}

impl From<ScriptKey> for ScriptPubkey {
  fn from(script_key: ScriptKey) -> Self {
    match script_key {
      ScriptKey::Address(address) => ScriptPubkey::Address(address.to_string()),
      ScriptKey::ScriptHash(hash) => ScriptPubkey::NonStandard(hash.to_string()),
    }
  }
}



#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum ScriptKey {
  Address(Address),
  ScriptHash(ScriptHash),
}

impl ScriptKey {
  pub fn from_address(address: Address) -> Self {
    ScriptKey::Address(address)
  }
  pub fn from_script(script: &Script, network: Network) -> Self {
    match Address::from_script(script, network) {
      Ok(address) => ScriptKey::Address(address),
      Err(_) => ScriptKey::ScriptHash(script.script_hash()),
    }
  }
}

impl Display for ScriptKey {
  fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
    write!(
      f,
      "{}",
      match self {
        ScriptKey::Address(address) => address.clone().to_string(),
        ScriptKey::ScriptHash(script_hash) => script_hash.to_string(),
      }
    )
  }
}