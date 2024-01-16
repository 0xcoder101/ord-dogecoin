use super::*;
use crate::inscription::ParsedInscription;
use crate::okx::datastore::ord::operation::{Action, InscriptionOp};


pub(super) struct Flotsam {
  txid: Txid,
  inscription_id: InscriptionId,
  offset: u64,
  old_satpoint: SatPoint,
  origin: Origin,
}

enum Origin {
  New(u64),
  Old(SatPoint),
}

pub(super) struct InscriptionUpdater<'a, 'db, 'tx> {
  flotsam: Vec<Flotsam>,
  pub(super) operations: HashMap<Txid, Vec<InscriptionOp>>,
  height: u64,
  id_to_satpoint: &'a mut Table<'db, 'tx, &'static InscriptionIdValue, &'static SatPointValue>,
  id_to_txids: &'a mut Table<'db, 'tx, &'static InscriptionIdValue, &'static [u8]>,
  txid_to_tx: &'a mut Table<'db, 'tx, &'static [u8], &'static [u8]>,
  partial_txid_to_txids: &'a mut Table<'db, 'tx, &'static [u8], &'static [u8]>,
  value_receiver: &'a mut Receiver<TxOut>,
  id_to_entry: &'a mut Table<'db, 'tx, &'static InscriptionIdValue, InscriptionEntryValue>,
  pub(super) lost_sats: u64,
  pub(super) next_number: u64,
  number_to_id: &'a mut Table<'db, 'tx, u64, &'static InscriptionIdValue>,
  outpoint_to_value: &'a mut Table<'db, 'tx, &'static OutPointValue, u64>,
  outpoint_to_entry: &'a mut Table<'db, 'tx, &'static OutPointValue, &'static [u8]>,
  reward: u64,
  sat_to_inscription_id: &'a mut Table<'db, 'tx, u64, &'static InscriptionIdValue>,
  satpoint_to_id: &'a mut Table<'db, 'tx, &'static SatPointValue, &'static InscriptionIdValue>,
  timestamp: u32,
  value_cache: &'a mut HashMap<OutPoint, u64>,
  tx_out_cache: &'a mut HashMap<OutPoint, TxOut>,
}

impl<'a, 'db, 'tx> InscriptionUpdater<'a, 'db, 'tx> {
  pub(super) fn new(
    height: u64,
    id_to_satpoint: &'a mut Table<'db, 'tx, &'static InscriptionIdValue, &'static SatPointValue>,
    id_to_txids: &'a mut Table<'db, 'tx, &'static InscriptionIdValue, &'static [u8]>,
    txid_to_tx: &'a mut Table<'db, 'tx, &'static [u8], &'static [u8]>,
    partial_txid_to_txids: &'a mut Table<'db, 'tx, &'static [u8], &'static [u8]>,
    value_receiver: &'a mut Receiver<TxOut>,
    id_to_entry: &'a mut Table<'db, 'tx, &'static InscriptionIdValue, InscriptionEntryValue>,
    lost_sats: u64,
    number_to_id: &'a mut Table<'db, 'tx, u64, &'static InscriptionIdValue>,
    outpoint_to_value: &'a mut Table<'db, 'tx, &'static OutPointValue, u64>,
    outpoint_to_entry: &'a mut Table<'db, 'tx, &'static OutPointValue, &'static [u8]>,
    sat_to_inscription_id: &'a mut Table<'db, 'tx, u64, &'static InscriptionIdValue>,
    satpoint_to_id: &'a mut Table<'db, 'tx, &'static SatPointValue, &'static InscriptionIdValue>,
    timestamp: u32,
    value_cache: &'a mut HashMap<OutPoint, u64>,
    tx_out_cache: &'a mut HashMap<OutPoint, TxOut>,
  ) -> Result<Self> {
    let next_number = number_to_id
      .iter()?
      .next_back()
      .and_then(|result| result.ok())
      .map(|(number, _id)| number.value() + 1)
      .unwrap_or(0);

    Ok(Self {
      flotsam: Vec::new(),
      operations: HashMap::new(),
      height,
      id_to_satpoint,
      id_to_txids,
      txid_to_tx,
      partial_txid_to_txids,
      value_receiver,
      id_to_entry,
      lost_sats,
      next_number,
      number_to_id,
      outpoint_to_value,
      outpoint_to_entry,
      reward: Height(height).subsidy(),
      sat_to_inscription_id,
      satpoint_to_id,
      timestamp,
      value_cache,
      tx_out_cache
    })
  }

  pub(super) fn index_transaction_inscriptions(
    &mut self,
    tx: &Transaction,
    txid: Txid,
    input_sat_ranges: Option<&VecDeque<(u64, u64)>>,
  ) -> Result<u64> {
    // prepare a vec to build inscriptions
    let mut inscriptions = Vec::new();
    let mut input_value = 0;
    
    // loop each txInputs
    for tx_in in &tx.input {
      if tx_in.previous_output.is_null() {
        input_value += Height(self.height).subsidy();
      } else {
        for (old_satpoint, inscription_id) in
          Index::inscriptions_on_output(self.satpoint_to_id, tx_in.previous_output)?
        {
          inscriptions.push(
            Flotsam {
              txid: txid,
              inscription_id: inscription_id,
              offset: input_value + old_satpoint.offset,
              old_satpoint: old_satpoint,
              origin: Origin::Old(old_satpoint),
            }
          );
        }

        // okx logic multi-level cache for UTXO set to get to the input amount
        let _value1 = if let Some(tx_out) = self.tx_out_cache.get(&tx_in.previous_output)
        {
          tx_out.value
        } else if let Some(tx_out) =
          Index::transaction_output_by_outpoint(self.outpoint_to_entry, tx_in.previous_output)?
        {
          tx_out.value
        } else {
          let tx_out = self.value_receiver.blocking_recv().ok_or_else(|| {
            anyhow!(
              "failed to get transaction for {}",
              tx_in.previous_output.txid
            )
          })?;
          self
            .tx_out_cache
            .insert(tx_in.previous_output, tx_out.clone());
          tx_out.value
        };

        let _value2 = if let Some(value) = self.value_cache.remove(&tx_in.previous_output) {
          value
        } else if let Some(value) = self
          .outpoint_to_value
          .remove(&tx_in.previous_output.store())?
        {
          value.value()
        } else {
          let _tx_out = self.value_receiver.blocking_recv().ok_or_else(|| {
            anyhow!(
              "failed to get transaction for {}",
              tx_in.previous_output.txid
            )
          })?;
          _tx_out.value
        };
        
        log::info!(
            "Shaneon debug, value1: {}", _value1
        );

        log::info!(
          "Shaneon debug, value2: {}", _value2
        );

        input_value += _value2;
      }
    }

    if inscriptions.iter().all(|flotsam| flotsam.offset != 0) {
          let previous_txid = tx.input[0].previous_output.txid;
          let previous_txid_bytes: [u8; 32] = previous_txid.into_inner();
          let mut txids_vec = vec![];

          let txs = match self
            .partial_txid_to_txids
            .get(&previous_txid_bytes.as_slice())?
          {
            Some(partial_txids) => {
              let txids = partial_txids.value();
              let mut txs = vec![];
              txids_vec = txids.to_vec();
              for i in 0..txids.len() / 32 {
                let txid = &txids[i * 32..i * 32 + 32];
                let tx_result = self.txid_to_tx.get(txid)?;
                let tx_result = tx_result.unwrap();
                let tx_buf = tx_result.value();
                let mut cursor = std::io::Cursor::new(tx_buf);
                let tx = bitcoin::Transaction::consensus_decode(&mut cursor)?;
                txs.push(tx);
              }
              txs.push(tx.clone());
              txs
            }
            None => {
              vec![tx.clone()]
            }
          };

          match Inscription::from_transactions(txs) {
            ParsedInscription::None => {
              // todo: clean up db
            }

            ParsedInscription::Partial => {
              let mut txid_vec = txid.into_inner().to_vec();
              txids_vec.append(&mut txid_vec);

              self
                .partial_txid_to_txids
                .remove(&previous_txid_bytes.as_slice())?;
              self
                .partial_txid_to_txids
                .insert(&txid.into_inner().as_slice(), txids_vec.as_slice())?;

              let mut tx_buf = vec![];
              tx.consensus_encode(&mut tx_buf)?;
              self
                .txid_to_tx
                .insert(&txid.into_inner().as_slice(), tx_buf.as_slice())?;
            }

            ParsedInscription::Complete(_inscription) => {
              self
                .partial_txid_to_txids
                .remove(&previous_txid_bytes.as_slice())?;

              let mut tx_buf = vec![];
              tx.consensus_encode(&mut tx_buf)?;
              self
                .txid_to_tx
                .insert(&txid.into_inner().as_slice(), tx_buf.as_slice())?;

              let mut txid_vec = txid.into_inner().to_vec();
              txids_vec.append(&mut txid_vec);

              let mut inscription_id = [0_u8; 36];
              unsafe {
                std::ptr::copy_nonoverlapping(txids_vec.as_ptr(), inscription_id.as_mut_ptr(), 32)
              }
              self
                .id_to_txids
                .insert(&inscription_id, txids_vec.as_slice())?;

              let _txid = Txid::from_slice(&txids_vec[0..32]).unwrap();
              let og_inscription_id = InscriptionId {
                txid: _txid,
                index: 0
              };
              
              // TODO: old_satpoint set to 0:0 temporarily
              inscriptions.push(Flotsam {
                txid: _txid,
                old_satpoint: SatPoint {
                  outpoint: tx.input[0].previous_output,
                  offset: 0,
                },
                inscription_id: og_inscription_id,
                offset: 0,
                origin: Origin::New(input_value - tx.output.iter().map(|txout| txout.value).sum::<u64>()),
              });  
            }
          }
    } 

    let is_coinbase = tx
      .input
      .first()
      .map(|tx_in| tx_in.previous_output.is_null())
      .unwrap_or_default();

    if is_coinbase {
      inscriptions.append(&mut self.flotsam);
    }

    inscriptions.sort_by_key(|flotsam| flotsam.offset);
    let mut inscriptions = inscriptions.into_iter().peekable();

    let mut output_value = 0;
    for (vout, tx_out) in tx.output.iter().enumerate() {
      let end = output_value + tx_out.value;

      while let Some(flotsam) = inscriptions.peek() {
        if flotsam.offset >= end {
          break;
        }

        let new_satpoint = SatPoint {
          outpoint: OutPoint {
            txid,
            vout: vout.try_into().unwrap(),
          },
          offset: flotsam.offset - output_value,
        };

        self.update_inscription_location(
          input_sat_ranges,
          false,
          inscriptions.next().unwrap(),
          new_satpoint,
        )?;
      }

      output_value = end;

      self.value_cache.insert(
        OutPoint {
          vout: vout.try_into().unwrap(),
          txid,
        },
        tx_out.value,
      );

      // shaneson add
      self.tx_out_cache.insert(
        OutPoint {
          vout: vout.try_into().unwrap(),
          txid,
        },
        tx_out.clone(),
      );
    }

    if is_coinbase {
      for flotsam in inscriptions {
        let new_satpoint = SatPoint {
          outpoint: OutPoint::null(),
          offset: self.lost_sats + flotsam.offset - output_value,
        };
        self.update_inscription_location(input_sat_ranges, is_coinbase, flotsam, new_satpoint)?;
      }

      Ok(self.reward - output_value)
    } else {
      self.flotsam.extend(inscriptions.map(|flotsam| Flotsam {
        offset: self.reward + flotsam.offset - output_value,
        ..flotsam
      }));
      self.reward += input_value - output_value;
      Ok(0)
    }
  }

  fn update_inscription_location(
    &mut self,
    input_sat_ranges: Option<&VecDeque<(u64, u64)>>,
    is_coinbase: bool,
    flotsam: Flotsam,
    new_satpoint: SatPoint,
  ) -> Result {
    let inscription_id = flotsam.inscription_id.store();

    match flotsam.origin {
      Origin::Old(old_satpoint) => {
        self.satpoint_to_id.remove(&old_satpoint.store())?;
      }
      Origin::New(fee) => {
        self
          .number_to_id
          .insert(&self.next_number, &inscription_id)?;

        let mut sat = None;
        if let Some(input_sat_ranges) = input_sat_ranges {
          let mut offset = 0;
          for (start, end) in input_sat_ranges {
            let size = end - start;
            if offset + size > flotsam.offset {
              let n = start + flotsam.offset - offset;
              self.sat_to_inscription_id.insert(&n, &inscription_id)?;
              sat = Some(Sat(n));
              break;
            }
            offset += size;
          }
        }

        self.id_to_entry.insert(
          &inscription_id,
          &InscriptionEntry {
            fee,
            height: self.height,
            number: self.next_number,
            sat,
            timestamp: self.timestamp,
          }
          .store(),
        )?;

        self.next_number += 1;
      }
    }

    let new_satpoint = new_satpoint.store();

    // // from block reward,

    // shaneson add
    self
    .operations
    .entry(flotsam.txid)
    .or_default()
    .push(InscriptionOp {
      txid: flotsam.txid,
      inscription_number: self
        .id_to_entry
        .get(&flotsam.inscription_id.store())?
        .map(|entry| InscriptionEntry::load(entry.value()).number),
      inscription_id: flotsam.inscription_id,
      action: match flotsam.origin {
        Origin::Old(_) => Action::Transfer,
        Origin::New(_)=> Action::New,
      },
      old_satpoint: flotsam.old_satpoint,
      new_satpoint: Some(Entry::load(new_satpoint)),
    });

    self.satpoint_to_id.insert(&new_satpoint, &inscription_id)?;
    self.id_to_satpoint.insert(&inscription_id, &new_satpoint)?;

    Ok(())
  }

}
