use super::*;

#[derive(Boilerplate)]
pub(crate) struct OutputHtml {
  pub(crate) outpoint: OutPoint,
  pub(crate) list: Option<List>,
  pub(crate) chain: Chain,
  pub(crate) output: TxOut,
  pub(crate) inscriptions: Vec<InscriptionId>,
}

impl PageContent for OutputHtml {
  fn title(&self) -> String {
    format!("Output {}", self.outpoint)
  }
}
