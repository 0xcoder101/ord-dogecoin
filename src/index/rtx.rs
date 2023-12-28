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

  pub(crate) fn block_count(&self) -> Result<u32> {
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

  pub(crate) fn block_hash(&self, height: Option<u32>) -> Result<Option<BlockHash>> {
    let height_to_block_header = self.0.open_table(HEIGHT_TO_BLOCK_HEADER)?;

    Ok(
      match height {
        Some(height) => height_to_block_header.get(height)?,
        None => height_to_block_header
          .range(0..)?
          .next_back()
          .transpose()?
          .map(|(_height, header)| header),
      }
      .map(|header| Header::load(*header.value()).block_hash()),
    )
  }
}


// use super::*;

// pub(crate) struct Rtx<'a>(pub(crate) redb::ReadTransaction<'a>);

// impl Rtx<'_> {
//   pub(crate) fn height(&self) -> Result<Option<Height>> {
//     Ok(
//       self
//         .0
//         .open_table(HEIGHT_TO_BLOCK_HASH)?
//         .range(0..)?
//         .rev()
//         .next()
//         .map(|(height, _hash)| Height(height.value())),
//     )
//   }

//   pub(crate) fn block_count(&self) -> Result<u64> {
//     Ok(
//       self
//         .0
//         .open_table(HEIGHT_TO_BLOCK_HASH)?
//         .range(0..)?
//         .rev()
//         .next()
//         .map(|(height, _hash)| height.value() + 1)
//         .unwrap_or(0),
//     )
//   }

//   pub(crate) fn block_hash(&self, height: Option<u32>) -> Result<Option<BlockHash>> {
//     Ok(
//         self
//           .0
//           .open_table(HEIGHT_TO_BLOCK_HASH)?
//           .range(0..)?
//           .rev()
//           .next()
//           .map(|(_height, hash)| BlockHash::from_slice(hash.value()).ok().unwrap() ),
//     )  
//   }
// }
