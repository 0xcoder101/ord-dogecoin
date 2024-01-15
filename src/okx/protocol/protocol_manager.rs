
use crate::okx::datastore::{StateReader, ord::{DataStoreReadOnly, DataStoreReadWrite}};

use {
  super::*,
  crate::{
    index::BlockData,
    okx::{
      datastore::{ord::operation::{InscriptionOp, Action}, StateRWriter, StateReadOnly },
      protocol::ord as ord_proto,

    },
    Instant, Result,
  },
  bitcoin::Txid,
  bitcoincore_rpc::Client,
  bitcoin::{OutPoint, Transaction, TxOut},
  std::collections::HashMap,

};

pub struct ProtocolManager<'a, RW: StateRWriter> {
  client: &'a Client,
  state_read_write_store: &'a RW,
  config: &'a ProtocolConfig,
}

impl<'a, RW: StateRWriter> ProtocolManager<'a, RW,> {
  // Need three datastore, and they're all in the same writeRR transaction.
  pub fn new(client: &'a Client, state_read_write_store: &'a RW, config: &'a ProtocolConfig) -> Self {
    Self {
      client,
      state_read_write_store,
      config,
    }
  }

  pub(crate) fn index_block(
    &self,
    context: BlockContext,
    block: &BlockData,
    operations: HashMap<Txid, Vec<InscriptionOp>>,
  ) -> Result {
    let start = Instant::now();
    let mut inscriptions_size = 0;
    let mut outpoint_to_txout_cache: HashMap<OutPoint, TxOut> = HashMap::new();

    // skip the coinbase transaction.
    for (tx, txid) in block.txdata.iter() {
      // skip coinbase transaction.
      if tx
        .input
        .first()
        .map(|tx_in| tx_in.previous_output.is_null())
        .unwrap_or_default()
      {
        continue;
      }

      // index inscription operations.
      if let Some(tx_operations) = operations.get(txid) {
        
        // save all transaction operations to ord database.
        if self.config.enable_ord_receipts
          && context.blockheight >= self.config.first_inscription_height
        {
          ord_proto::save_transaction_operations(self.state_read_write_store.ord(), txid, tx_operations)?;
          inscriptions_size += tx_operations.len();
        }

        // foreach old Satpoint from tx_operations
        for operation in tx_operations {
            let op_old_satpoint = operation.old_satpoint;
            match operation.action {
                Action::New => self.insert_outpoint_to_txout(op_old_satpoint, &mut outpoint_to_txout_cache),
                Action::Transfer => {
                    // Do nothing
                }
            }
        }
      }
    }

    self.update_outpoint_to_txout(outpoint_to_txout_cache)?;

    log::info!(
      "Protocol Manager indexed block {} with ord inscriptions {} in {} ms",
      context.blockheight,
      inscriptions_size,
      (Instant::now() - start).as_millis(),
    );
    Ok(())
  }

  fn update_outpoint_to_txout(&self, outpoint_to_txout_cache: HashMap<OutPoint, TxOut>) -> Result {
    for (outpoint, txout) in outpoint_to_txout_cache {

      log::info!(
          "Shaneson output: {outpoint}, txout.value : {}, txout.script: {} ",
          txout.value,
          txout.script_pubkey
      );

      self
        .state_read_write_store
        .ord()
        .set_outpoint_to_txout(outpoint, &txout)
        .or(Err(anyhow!(
          "failed to get tx out! error: {} not found",
          outpoint
        )))?;

    }
    Ok(())
  }

  fn insert_outpoint_to_txout(
    &self,
    op_old_satpoint: SatPoint,
    outpoint_to_txout_cache: &mut HashMap<OutPoint, TxOut>,
    ) {
      let commit_transaction =
      &Index::get_transaction_retries(self.client, op_old_satpoint.outpoint.txid).unwrap().ok_or(anyhow!(
        "failed to Dogechain message commit transaction! error: {} not found",
        op_old_satpoint.outpoint.txid
      )).unwrap();
  
      // get satoshi offset
      let mut offset = 0;
      for (vout, output) in commit_transaction.output.iter().enumerate() {
        if vout < usize::try_from(op_old_satpoint.outpoint.vout).unwrap() {
          offset += output.value;
          continue;
        }
        offset += op_old_satpoint.offset;
        break;
      }
  
      let mut input_value = 0;
      for input in &commit_transaction.input {
        let value = if let Some(tx_out) = self.state_read_write_store
          .ord()
          .get_outpoint_to_txout(input.previous_output)
          .map_err(|e| anyhow!("failed to get tx out from state! error: {e}")).unwrap()
        {
          tx_out.value
        } else {
            // can't find, so insert, 
            let tx_out = Index::get_transaction_retries(self.client, input.previous_output.txid).unwrap()
                .map(|tx| {
                  tx.output
                    .get(usize::try_from(input.previous_output.vout).unwrap())
                    .unwrap()
                    .clone()
                }).unwrap();
              
            outpoint_to_txout_cache.insert(input.previous_output, tx_out.clone());
            tx_out.value
        };
        // value and input_value is useless now.
      }
  }
  
}
