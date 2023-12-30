use super::*;

#[derive(Boilerplate)]
pub(crate) struct TransactionHtml {
  blockhash: Option<BlockHash>,
  chain: Chain,
  inscription: Option<InscriptionId>,
  transaction: Transaction,
  txid: Txid,
}

impl TransactionHtml {
  pub(crate) fn new(
    transaction: Transaction,
    blockhash: Option<BlockHash>,
    inscription: Option<InscriptionId>,
    chain: Chain,
  ) -> Self {
    Self {
      txid: transaction.txid(),
      blockhash,
      chain,
      inscription,
      transaction,
    }
  }
}

impl PageContent for TransactionHtml {
  fn title(&self) -> String {
    format!("Transaction {}", self.txid)
  }
}


