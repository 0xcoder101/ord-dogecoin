use {super::*, crate::wallet::Wallet};

#[derive(Debug, Parser)]
pub(crate) struct Sats {
  #[clap(
    long,
    help = "Find satoshis listed in first column of tab-separated value file <TSV>."
  )]
  tsv: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
pub struct OutputTsv {
  pub sat: String,
  pub output: OutPoint,
}

#[derive(Serialize, Deserialize)]
pub struct OutputRare {
  pub sat: Sat,
  pub output: OutPoint,
  pub offset: u64,
  pub rarity: Rarity,
}

impl Sats {
  pub(crate) fn run(&self, options: Options) -> Result {
    let index = Index::open(&options)?;
    index.update()?;

    let utxos = index.get_unspent_output_ranges(Wallet::load(&options)?)?;

    if let Some(path) = &self.tsv {
      let mut output = Vec::new();
      for (outpoint, sat) in sats_from_tsv(
        utxos,
        &fs::read_to_string(path)
          .with_context(|| format!("I/O error reading `{}`", path.display()))?,
      )? {
        output.push(OutputTsv {
          sat: sat.into(),
          output: outpoint,
        });
      }
      print_json(output)?;
    } else {
      let mut output = Vec::new();
      for (outpoint, sat, offset, rarity) in rare_sats(utxos) {
        output.push(OutputRare {
          sat,
          output: outpoint,
          offset,
          rarity,
        });
      }
      print_json(output)?;
    }

    Ok(())
  }
}

fn rare_sats(utxos: Vec<(OutPoint, Vec<(u64, u64)>)>) -> Vec<(OutPoint, Sat, u64, Rarity)> {
  utxos
    .into_iter()
    .flat_map(|(outpoint, sat_ranges)| {
      let mut offset = 0;
      sat_ranges.into_iter().filter_map(move |(start, end)| {
        let sat = Sat(start);
        let rarity = sat.rarity();
        let start_offset = offset;
        offset += u64::try_from(end - start).unwrap();
        if rarity > Rarity::Common {
          Some((outpoint, sat, start_offset, rarity))
        } else {
          None
        }
      })
    })
    .collect()
}

fn sats_from_tsv(
  utxos: Vec<(OutPoint, Vec<(u64, u64)>)>,
  tsv: &str,
) -> Result<Vec<(OutPoint, &str)>> {
  let mut needles = Vec::new();
  for (i, line) in tsv.lines().enumerate() {
    if line.is_empty() || line.starts_with('#') {
      continue;
    }

    if let Some(value) = line.split('\t').next() {
      let sat = Sat::from_str(value).map_err(|err| {
        anyhow!(
          "failed to parse sat from string \"{value}\" on line {}: {err}",
          i + 1,
        )
      })?;

      needles.push((sat, value));
    }
  }
  needles.sort();

  let mut haystacks = utxos
    .into_iter()
    .flat_map(|(outpoint, ranges)| {
      ranges
        .into_iter()
        .map(move |(start, end)| (start, end, outpoint))
    })
    .collect::<Vec<(u64, u64, OutPoint)>>();
  haystacks.sort();

  let mut i = 0;
  let mut j = 0;
  let mut results = Vec::new();
  while i < needles.len() && j < haystacks.len() {
    let (needle, value) = needles[i];
    let (start, end, outpoint) = haystacks[j];

    if needle >= start && needle < end {
      results.push((outpoint, value));
    }

    if needle >= end {
      j += 1;
    } else {
      i += 1;
    }
  }

  Ok(results)
}

#[cfg(test)]
mod tests {
  use {super::*, std::fmt::Write};

  #[test]
  fn identify_no_rare_sats() {
    assert_eq!(
      rare_sats(vec![(
        outpoint(1),
        vec![
          (51 * COIN_VALUE, 100 * COIN_VALUE),
          (1234, 5678)
        ],
      )]),
      Vec::new()
    )
  }

  #[test]
  #[ignore]
  fn identify_one_rare_sat() {
    assert_eq!(
      rare_sats(vec![(
        outpoint(1),
        vec![
          (10, 80),
          (50 * COIN_VALUE, 100 * COIN_VALUE)
        ],
      )]),
      vec![(
        outpoint(1),
        Sat(50 * COIN_VALUE),
        70,
        Rarity::Uncommon
      )]
    )
  }

  #[test]
  #[ignore]
  fn identify_two_rare_sats() {
    assert_eq!(
      rare_sats(vec![(
        outpoint(1),
        vec![(0, 100), (1050000000000000, 1150000000000000)],
      )]),
      vec![
        (outpoint(1), Sat(0), 0, Rarity::Mythic),
        (outpoint(1), Sat(1050000000000000), 100, Rarity::Epic)
      ]
    )
  }
  
  #[test]
  fn identify_from_tsv_none() {
    assert_eq!(
      sats_from_tsv(vec![(outpoint(1), vec![(0, 1)])], "1\n").unwrap(),
      Vec::new()
    )
  }

  #[test]
  fn identify_from_tsv_single() {
    assert_eq!(
      sats_from_tsv(vec![(outpoint(1), vec![(0, 1)])], "0\n").unwrap(),
      vec![(outpoint(1), "0"),]
    )
  }

  #[test]
  fn identify_from_tsv_two_in_one_range() {
    assert_eq!(
      sats_from_tsv(vec![(outpoint(1), vec![(0, 2)])], "0\n1\n").unwrap(),
      vec![(outpoint(1), "0"), (outpoint(1), "1"),]
    )
  }

  #[test]
  fn identify_from_tsv_out_of_order_tsv() {
    assert_eq!(
      sats_from_tsv(vec![(outpoint(1), vec![(0, 2)])], "1\n0\n").unwrap(),
      vec![(outpoint(1), "0"), (outpoint(1), "1"),]
    )
  }

  #[test]
  fn identify_from_tsv_out_of_order_ranges() {
    assert_eq!(
      sats_from_tsv(vec![(outpoint(1), vec![(1, 2), (0, 1)])], "1\n0\n").unwrap(),
      vec![(outpoint(1), "0"), (outpoint(1), "1"),]
    )
  }

  #[test]
  fn identify_from_tsv_two_in_two_ranges() {
    assert_eq!(
      sats_from_tsv(vec![(outpoint(1), vec![(0, 1), (1, 2)])], "0\n1\n").unwrap(),
      vec![(outpoint(1), "0"), (outpoint(1), "1"),]
    )
  }

  #[test]
  fn identify_from_tsv_two_in_two_outputs() {
    assert_eq!(
      sats_from_tsv(
        vec![(outpoint(1), vec![(0, 1)]), (outpoint(2), vec![(1, 2)])],
        "0\n1\n"
      )
      .unwrap(),
      vec![(outpoint(1), "0"), (outpoint(2), "1"),]
    )
  }

  #[test]
  fn identify_from_tsv_ignores_extra_columns() {
    assert_eq!(
      sats_from_tsv(vec![(outpoint(1), vec![(0, 1)])], "0\t===\n").unwrap(),
      vec![(outpoint(1), "0"),]
    )
  }

  #[test]
  fn identify_from_tsv_ignores_empty_lines() {
    assert_eq!(
      sats_from_tsv(vec![(outpoint(1), vec![(0, 1)])], "0\n\n\n").unwrap(),
      vec![(outpoint(1), "0"),]
    )
  }

  #[test]
  fn identify_from_tsv_ignores_comments() {
    assert_eq!(
      sats_from_tsv(vec![(outpoint(1), vec![(0, 1)])], "0\n#===\n").unwrap(),
      vec![(outpoint(1), "0"),]
    )
  }

  #[test]
  fn parse_error_reports_line_and_value() {
    assert_eq!(
      sats_from_tsv(vec![(outpoint(1), vec![(0, 1)])], "0\n===\n")
        .unwrap_err()
        .to_string(),
      "failed to parse sat from string \"===\" on line 2: invalid digit found in string",
    )
  }

}
