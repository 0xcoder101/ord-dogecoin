use super::*;

#[derive(Boilerplate)]
pub(crate) struct InputHtml {
  pub(crate) path: (u64, usize, usize),
  pub(crate) input: TxIn,
}

impl PageContent for InputHtml {
  fn title(&self) -> String {
    format!("Input /{}/{}/{}", self.path.0, self.path.1, self.path.2)
  }
}