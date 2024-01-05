use super::*;

pub(crate) struct Rtx<'a>(pub(crate) redb::ReadTransaction<'a>);

impl Rtx<'_> {
  pub(crate) fn block_height(&self) -> Result<Option<Height>> {
    Ok(
      self
        .0
        .open_table(HEIGHT_TO_BLOCK_HEADER)?
        .range(0..)?
        .next_back()
        .and_then(|result| result.ok())
        .map(|(height, _header)| Height(height.value())),
    )
  }

  pub(crate) fn block_count(&self) -> Result<u64> {
    Ok(
      self
        .0
        .open_table(HEIGHT_TO_BLOCK_HEADER)?
        .range(0..)?
        .next_back()
        .and_then(|result| result.ok())
        .map(|(height, _header)| height.value() + 1)
        .unwrap_or(0),
    )
  }

  pub(crate) fn block_hash(&self, height: Option<u64>) -> Result<Option<BlockHash>> {
    match height {
      Some(height) => Ok(
        self
          .0
          .open_table(HEIGHT_TO_BLOCK_HEADER)?
          .get(height)?
          .map(|hash| BlockHash::load(*hash.value())),
      ),
      None => Ok(
        self
          .0
          .open_table(HEIGHT_TO_BLOCK_HEADER)?
          .range(0..)?
          .next_back()
          .and_then(|result| result.ok())
          .map(|(_height, hash)| BlockHash::load(*hash.value())),
      ),
    }
  }

  pub(crate) fn latest_block(&self) -> Result<Option<(Height, BlockHash)>> {
    Ok(
      self
        .0
        .open_table(HEIGHT_TO_BLOCK_HEADER)?
        .range(0..)?
        .next_back()
        .and_then(|result| result.ok())
        .map(|(height, hash)| (Height(height.value()), BlockHash::load(*hash.value()))),
    )
  }
}

