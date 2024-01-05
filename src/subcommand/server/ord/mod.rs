use {
  super::*,
  crate::okx::datastore::ord::{Action, InscriptionOp},
};

mod inscription;
mod outpoint;
mod transaction;

pub(super) use {inscription::*, outpoint::*, transaction::*};

#[derive(Debug, thiserror::Error)]
pub enum OrdError {
  #[error("operation not found")]
  OperationNotFound,
  #[error("block not found")]
  BlockNotFound,
}

#[derive(Debug, Clone)]
enum Origin {
  New {
    cursed: bool,
    unbound: bool,
    inscription: Inscription,
  },
  Old,
}

#[derive(Debug, Clone)]
struct Flotsam {
  txid: Txid,
  inscription_id: InscriptionId,
  offset: u64,
  old_satpoint: SatPoint,
  origin: Origin,
}

