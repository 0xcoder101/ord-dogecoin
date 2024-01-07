use {super::*, updater::BlockData};

#[derive(Debug, PartialEq)]
pub(crate) enum ReorgError {
  Recoverable { height: u64, depth: u64 },
  Unrecoverable,
}

impl fmt::Display for ReorgError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      ReorgError::Recoverable { height, depth } => {
        write!(f, "{depth} block deep reorg detected at height {height}")
      }
      ReorgError::Unrecoverable => write!(f, "unrecoverable reorg detected"),
    }
  }
}

impl std::error::Error for ReorgError {}

const MAX_SAVEPOINTS: usize = 7;
const SAVEPOINT_INTERVAL: u64 = 10;
const CHAIN_TIP_DISTANCE: u64 = 21;

pub(crate) struct Reorg {}

impl Reorg {

  pub(crate) fn detect_reorg(block: &BlockData, height: u64, index: &Index) -> Result {
    let bitcoind_prev_blockhash = block.header.prev_blockhash;

    match index.block_hash(height.checked_sub(1))? {
      Some(index_prev_blockhash) if index_prev_blockhash == bitcoind_prev_blockhash => Ok(()),
      Some(index_prev_blockhash) if index_prev_blockhash != bitcoind_prev_blockhash => {
        let max_recoverable_reorg_depth =
          (MAX_SAVEPOINTS as u64 - 1) * SAVEPOINT_INTERVAL + height % SAVEPOINT_INTERVAL;

        for depth in 1..max_recoverable_reorg_depth {
          let index_block_hash = index.block_hash(height.checked_sub(depth))?;
          let bitcoind_block_hash = index
            .client
            .get_block_hash(height.saturating_sub(depth))
            .into_option()?;

          if index_block_hash == bitcoind_block_hash {
            return Err(anyhow!(ReorgError::Recoverable { height, depth }));
          }
        }

        Err(anyhow!(ReorgError::Unrecoverable))
      }
      _ => Ok(()),
    }
  }
  
  pub(crate) fn handle_reorg(index: &Index, height: u64, depth: u64) -> Result {
    log::info!("shaneson testing reorg at {depth} at height {height}");

    log::info!("rolling back database after reorg of depth {depth} at height {height}");

    if let redb::Durability::None = index.durability {
      panic!("set index durability to `Durability::Immediate` to test reorg handling");
    }

    let mut wtx: WriteTransaction<'_> = index.begin_write()?;
    let oldest_savepoint =
      wtx.get_persistent_savepoint(wtx.list_persistent_savepoints()?.min().unwrap())?;

    wtx.restore_savepoint(&oldest_savepoint)?;

    Index::increment_statistic(&wtx, Statistic::Commits, 1)?;
    wtx.commit()?;

    log::info!(
      "successfully rolled back database to height {}",
      index.block_count()?
    );

    Ok(())
  }

  pub(crate) fn update_savepoints(index: &Index, height: u64) -> Result {
    log::debug!("shaneson checking height {}", height);

    if (height % 50 == 0) {
      log::debug!("shaneson trying save point, index.durability {:?}", index.durability);
      let wtx = index.begin_write()?;
      wtx.persistent_savepoint()?;
      Index::increment_statistic(&wtx, Statistic::Commits, 1)?;
      wtx.commit()?;
      log::debug!("shaneson creating savepoint success {}", height);

    }

    // if cfg!(test) {
    // } else {
    //   if let redb::Durability::None = index.durability {
    //     return Ok(());
    //   }
  
    //   let chain_height = index.get_chain_height().unwrap();  
    //   if (height < SAVEPOINT_INTERVAL || height % SAVEPOINT_INTERVAL == 0)
    //     && (chain_height.saturating_sub(height)<= CHAIN_TIP_DISTANCE ) 
    //   {
    //     let wtx = index.begin_write()?;
  
    //     let savepoints = wtx.list_persistent_savepoints()?.collect::<Vec<u64>>();
  
    //     if savepoints.len() >= MAX_SAVEPOINTS {
    //       wtx.delete_persistent_savepoint(savepoints.into_iter().min().unwrap())?;
    //     }
  
    //     Index::increment_statistic(&wtx, Statistic::Commits, 1)?;
    //     wtx.commit()?;
  
    //     let wtx = index.begin_write()?;
  
    //     log::debug!("creating savepoint at height {}", height);
    //     wtx.persistent_savepoint()?;
  
    //     Index::increment_statistic(&wtx, Statistic::Commits, 1)?;
    //     wtx.commit()?;
    //   }
    // }
    
    Ok(())
  }
}
