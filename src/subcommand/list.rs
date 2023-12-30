use super::*;

#[derive(Debug, Parser)]
pub(crate) struct List {
  #[clap(help = "List sats in <OUTPOINT>.")]
  outpoint: OutPoint,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Output {
  pub output: OutPoint,
  pub start: u64,
  pub size: u64,
  pub rarity: Rarity,
}

impl List {
  pub(crate) fn run(self, options: Options) -> Result {
    let index = Index::open(&options)?;

    index.update()?;

    match index.list(self.outpoint)? {
      Some(crate::index::List::Unspent(ranges)) => {
        let mut outputs = Vec::new();
        for (output, start, size, rarity) in list(self.outpoint, ranges) {
          outputs.push(Output {
            output,
            start,
            size,
            rarity,
          });
        }

        print_json(outputs)?;

        Ok(())
      }
      Some(crate::index::List::Spent) => Err(anyhow!("output spent.")),
      None => Err(anyhow!("output not found")),
    }
  }
}

fn list(outpoint: OutPoint, ranges: Vec<(u64, u64)>) -> Vec<(OutPoint, u64, u64, Rarity)> {
  ranges
    .into_iter()
    .map(|(start, end)| {
      let size = u64::try_from(end - start).unwrap();
      let rarity = Sat(start).rarity();

      (outpoint, start, size, rarity)
    })
    .collect()
}
