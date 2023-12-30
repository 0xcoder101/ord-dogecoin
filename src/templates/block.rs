use super::*;
use std::collections::HashMap;

impl Serialize for Height {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
  {
    // Call as_u64 to get a u64 representation of the height
    let height_as_u64 = self.0;
    serializer.serialize_u64(height_as_u64)
  }
}

#[derive(Serialize)]
pub struct BlockJson {
  hash: BlockHash,
  height: u64,
  txids: String,
  inputs_per_tx: HashMap<Txid, String>,
  outputs_per_tx: HashMap<Txid, String>,
  output_values_per_tx: HashMap<Txid, String>,
  output_addresses_per_tx: HashMap<Txid, String>,
  output_scripts_per_tx: HashMap<Txid, String>,
  inscriptions_per_tx: HashMap<Txid, (InscriptionId, Option<String>, Option<Vec<u8>>)>,
}

impl BlockJson {
  pub fn new(
    block: Block,
    height: u64,
    txids: String,
    inputs_per_tx: HashMap<Txid, String>,
    outputs_per_tx: HashMap<Txid, String>,
    output_values_per_tx: HashMap<Txid, String>,
    inscriptions_per_tx: HashMap<Txid, (InscriptionId, Option<String>, Option<Vec<u8>>)>,
    output_addresses_per_tx: HashMap<Txid, String>,
    output_scripts_per_tx: HashMap<Txid, String>,
  ) -> Self {
    let mut target = block.header.target().to_be_bytes();
    target.reverse();
    Self {
      hash: block.header.block_hash(),
      height: height.into(),
      txids,
      inputs_per_tx,
      outputs_per_tx,
      output_values_per_tx,
      inscriptions_per_tx,
      output_addresses_per_tx,
      output_scripts_per_tx
    }
  }
}

#[derive(Boilerplate)]
pub(crate) struct BlockHtml {
  hash: BlockHash,
  target: BlockHash,
  best_height: Height,
  block: Block,
  height: Height,
  inputs_per_tx: HashMap<Txid, String>,
  outputs_per_tx: HashMap<Txid, String>,
  output_values_per_tx: HashMap<Txid, String>,
  output_addresses_per_tx: HashMap<Txid, String>,
  inscriptions_per_tx: HashMap<Txid, (InscriptionId, Option<String>, Option<Vec<u8>>)>,
}

impl BlockHtml {
  pub(crate) fn new(
    block: Block,
    height: Height,
    best_height: Height,
    inputs_per_tx: HashMap<Txid, String>,
    outputs_per_tx: HashMap<Txid, String>,
    output_values_per_tx: HashMap<Txid, String>,
    inscriptions_per_tx: HashMap<Txid, (InscriptionId, Option<String>, Option<Vec<u8>>)>,
    output_addresses_per_tx: HashMap<Txid, String>,
  ) -> Self {
    let mut target = block.header.target().to_be_bytes();
    target.reverse();

    Self {
      hash: block.header.block_hash(),
      target: BlockHash::from_inner(target),
      block,
      height,
      best_height,
      inputs_per_tx,
      outputs_per_tx,
      output_values_per_tx,
      inscriptions_per_tx,
      output_addresses_per_tx,
    }
  }
}

impl PageContent for BlockHtml {
  fn title(&self) -> String {
    format!("Block {}", self.height)
  }
}
