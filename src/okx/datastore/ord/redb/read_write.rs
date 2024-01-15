use anyhow::Error;

use {
  super::*,
  crate::{
    index::OUTPOINT_TO_ENTRY,
    okx::datastore::ord::{DataStoreReadOnly, DataStoreReadWrite, InscriptionOp},
    InscriptionId, Result,
  },
  bitcoin::{consensus::Encodable, OutPoint, TxOut, Txid},
  redb::{ReadTransaction, WriteTransaction},
};

pub fn try_init_tables<'db, 'a>(
  wtx: &'a WriteTransaction<'db>,
  rtx: &'a ReadTransaction<'db>,
) -> Result<bool, redb::Error> {
  if rtx.open_table(ORD_TX_TO_OPERATIONS).is_err() {
    wtx.open_table(ORD_TX_TO_OPERATIONS)?;
    wtx.open_table(COLLECTIONS_KEY_TO_INSCRIPTION_ID)?;
    wtx.open_table(COLLECTIONS_INSCRIPTION_ID_TO_KINDS)?;
  }
  Ok(true)
}

pub struct OrdDbReadWriter<'db, 'a> {
  wtx: &'a WriteTransaction<'db>,
}

impl<'db, 'a> OrdDbReadWriter<'db, 'a>
where
  'db: 'a,
{
  pub fn new(wtx: &'a WriteTransaction<'db>) -> Self {
    Self { wtx }
  }
}

impl<'db, 'a> DataStoreReadOnly for OrdDbReadWriter<'db, 'a> {
  type Error = redb::Error;
  fn get_number_by_inscription_id(
    &self,
    inscription_id: InscriptionId,
  ) -> Result<Option<u64>, Self::Error> {
    read_only::new_with_wtx(self.wtx).get_number_by_inscription_id(inscription_id)
  }

  fn get_outpoint_to_txout(&self, outpoint: OutPoint) -> Result<Option<TxOut>, Self::Error> {
    read_only::new_with_wtx(self.wtx).get_outpoint_to_txout(outpoint)
  }

  fn get_transaction_operations(
    &self,
    txid: &bitcoin::Txid,
  ) -> Result<Vec<InscriptionOp>, Self::Error> {
    read_only::new_with_wtx(self.wtx).get_transaction_operations(txid)
  }

}

impl<'db, 'a> DataStoreReadWrite for OrdDbReadWriter<'db, 'a> {
  // OUTPOINT_TO_SCRIPT

  fn set_outpoint_to_txout(&self, outpoint: OutPoint, tx_out: &TxOut) -> Result<(), Self::Error> {

    let mut value = [0; 36];
    outpoint
      .consensus_encode(&mut value.as_mut_slice())
      .unwrap();

    let mut entry = Vec::new();
    tx_out.consensus_encode(&mut entry)?;

    self
      .wtx
      .open_table(OUTPOINT_TO_ENTRY)?
      .insert(&value, entry.as_slice())?;

    Ok(())
  }

  fn save_transaction_operations(
    &self,
    txid: &Txid,
    operations: &[InscriptionOp],
  ) -> Result<(), Self::Error> {
    self.wtx.open_table(ORD_TX_TO_OPERATIONS)?.insert(
      txid.to_string().as_str(),
      bincode::serialize(operations).unwrap().as_slice(),
    )?;
    Ok(())
  }
  
  fn set_inscription_by_collection_key(
    &self,
    key: &str,
    inscription_id: InscriptionId,
  ) -> Result<(), Self::Error> {
    let mut value = [0; 36];
    let (txid, index) = value.split_at_mut(32);
    txid.copy_from_slice(inscription_id.txid.as_ref());
    index.copy_from_slice(&inscription_id.index.to_be_bytes());
    self
      .wtx
      .open_table(COLLECTIONS_KEY_TO_INSCRIPTION_ID)?
      .insert(key, &value)?;
    Ok(())
  }

}

