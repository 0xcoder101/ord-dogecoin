use crate::inscription::ParsedInscription;
use std::{io::Cursor, option};

use {
  self::{
    entry::{
      HeaderValue, Entry, InscriptionIdValue, OutPointValue, SatPointValue, SatRange,
    },
    reorg::*,
    updater::Updater,
  },
  super::*,
  crate::wallet::Wallet,
  bitcoin::BlockHeader,
  bitcoincore_rpc::{json::{GetBlockHeaderResult, GetBlockResult}, Auth, Client, },
  chrono::SubsecRound,
  indicatif::{ProgressBar, ProgressStyle},
  okx::{
    datastore::{
      ord::{self, redb::try_init_tables as try_init_ord, DataStoreReadOnly}
    }
  },
  log::log_enabled,
  redb::{
    Database, DatabaseError, MultimapTable, MultimapTableDefinition, MultimapTableHandle,
    ReadOnlyTable, ReadableMultimapTable, ReadableTable, RedbKey, RedbValue, StorageError, Table,
    TableDefinition, TableHandle, WriteTransaction,
  },
  // redb::{Database, ReadableTable, Table, TableDefinition, WriteStrategy, WriteTransaction, Savepoint},
  std::collections::HashMap,
  std::sync::atomic::{self, AtomicBool},
};

pub(super) use self::{
  entry::{InscriptionEntry, InscriptionEntryValue},
  updater::BlockData,
};

mod entry;
mod fetcher;
mod reorg;
mod rtx;
mod updater;

const SCHEMA_VERSION: u64 = 3;

macro_rules! define_table {
  ($name:ident, $key:ty, $value:ty) => {
    pub const $name: TableDefinition<$key, $value> = TableDefinition::new(stringify!($name));
  };
}

define_table! { HEIGHT_TO_BLOCK_HEADER, u64, &HeaderValue }
// define_table! { HEIGHT_TO_BLOCK_HASH, u64, &HeaderValue }
define_table! { INSCRIPTION_ID_TO_INSCRIPTION_ENTRY, &InscriptionIdValue, InscriptionEntryValue }
define_table! { INSCRIPTION_ID_TO_SATPOINT, &InscriptionIdValue, &SatPointValue }
define_table! { INSCRIPTION_NUMBER_TO_INSCRIPTION_ID, u64, &InscriptionIdValue }
define_table! { INSCRIPTION_ID_TO_TXIDS, &InscriptionIdValue, &[u8] }
define_table! { INSCRIPTION_TXID_TO_TX, &[u8], &[u8] }
define_table! { PARTIAL_TXID_TO_INSCRIPTION_TXIDS, &[u8], &[u8] }
define_table! { OUTPOINT_TO_SAT_RANGES, &OutPointValue, &[u8] }
define_table! { OUTPOINT_TO_VALUE, &OutPointValue, u64}
define_table! { SATPOINT_TO_INSCRIPTION_ID, &SatPointValue, &InscriptionIdValue }
define_table! { SAT_TO_INSCRIPTION_ID, u64, &InscriptionIdValue }
define_table! { SAT_TO_SATPOINT, u64, &SatPointValue }
define_table! { STATISTIC_TO_COUNT, u64, u64 }
define_table! { WRITE_TRANSACTION_STARTING_BLOCK_COUNT_TO_TIMESTAMP, u64, u128 }

define_table! { OUTPOINT_TO_ENTRY, &OutPointValue, &[u8] }

pub(crate) struct Index {
  auth: Auth,
  client: Client,
  database: Database,
  durability: redb::Durability,
  path: PathBuf,
  first_inscription_height: u64,
  genesis_block_coinbase_transaction: Transaction,
  genesis_block_coinbase_txid: Txid,
  height_limit: Option<u64>,
  reorged: AtomicBool,
  rpc_url: String,
  unrecoverably_reorged: AtomicBool,
  options: Options,
}

#[derive(Debug, PartialEq)]
pub enum List {
  Spent,
  Unspent(Vec<(u64, u64)>),
}

#[derive(Copy, Clone)]
#[repr(u64)]
pub(crate) enum Statistic {
  Schema = 0,
  Commits = 1,
  LostSats = 2,
  OutputsTraversed = 3,
  SatRanges = 4,
}

impl Statistic {
  fn key(self) -> u64 {
    self.into()
  }
}

impl From<Statistic> for u64 {
  fn from(statistic: Statistic) -> Self {
    statistic as u64
  }
}

#[derive(Serialize)]
pub(crate) struct Info {
  pub(crate) blocks_indexed: u64,
  pub(crate) branch_pages: u64,
  pub(crate) fragmented_bytes: u64,
  pub(crate) index_file_size: u64,
  pub(crate) index_path: PathBuf,
  pub(crate) leaf_pages: u64,
  pub(crate) metadata_bytes: u64,
  pub(crate) outputs_traversed: u64,
  pub(crate) page_size: usize,
  pub(crate) sat_ranges: u64,
  pub(crate) stored_bytes: u64,
  pub(crate) transactions: Vec<TransactionInfo>,
  pub(crate) tree_height: u32,
  pub(crate) utxos_indexed: u64,
}

#[derive(Serialize)]
pub(crate) struct TransactionInfo {
  pub(crate) starting_block_count: u64,
  pub(crate) starting_timestamp: u128,
}

trait BitcoinCoreRpcResultExt<T> {
  fn into_option(self) -> Result<Option<T>>;
}

impl<T> BitcoinCoreRpcResultExt<T> for Result<T, bitcoincore_rpc::Error> {
  fn into_option(self) -> Result<Option<T>> {
    match self {
      Ok(ok) => Ok(Some(ok)),
      Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(
        bitcoincore_rpc::jsonrpc::error::RpcError { code: -8, .. },
      ))) => Ok(None),
      Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(
        bitcoincore_rpc::jsonrpc::error::RpcError { message, .. },
      )))
        if message.ends_with("not found") =>
      {
        Ok(None)
      }
      Err(err) => Err(err.into()),
    }
  }
}

impl Index {
  pub(crate) fn open(options: &Options) -> Result<Self> {

    // cookie
    let cookie_file = options
      .cookie_file()
      .map_err(|err| anyhow!("failed to get cookie file path: {err}"))?;
    let rpc_url = options.rpc_url();
    log::info!(
      "Connecting to Dogecoin Core RPC server at {rpc_url} using credentials from `{}`",
      cookie_file.display()
    );
    let auth = Auth::CookieFile(cookie_file);
    let client = Client::new(&rpc_url, auth.clone()).context("failed to connect to RPC URL")?;

    // rpc
    // let rpc_url = options.rpc_url();
    // let rpc_pass = options.get_rpc_password();
    // let rpc_user = options.get_rpc_username();
    // let auth = Auth::UserPass(rpc_user, rpc_pass);
    // let client = Client::new(&rpc_url, auth.clone()).context("failed to connect to RPC URL")?;

    let data_dir = options.data_dir()?;
    if let Err(err) = fs::create_dir_all(&data_dir) {
      bail!("failed to create data dir `{}`: {err}", data_dir.display());
    }
    
    let path = if let Some(path) = &options.index {
      path.clone()
    } else {
      data_dir.join("index.redb")
    };

    if let Err(err) = fs::create_dir_all(path.parent().unwrap()) {
      bail!(
        "failed to create data dir `{}`: {err}",
        path.parent().unwrap().display()
      );
    }

    let db_cache_size = match options.db_cache_size {
      Some(db_cache_size) => db_cache_size,
      None => {
        let mut sys = System::new();
        sys.refresh_memory();
        usize::try_from(sys.total_memory() / 4)?
      }
    };

    log::info!("Setting DB cache size to {} bytes", db_cache_size);

    let database = match Database::builder()
      .set_cache_size(db_cache_size)
      .open(&path)
    {
      Ok(database) => {
        log::info!("open database success");

        let schema_version = database
          .begin_read()?
          .open_table(STATISTIC_TO_COUNT)?
          .get(&Statistic::Schema.key())?
          .map(|x| x.value())
          .unwrap_or(0);

        match schema_version.cmp(&SCHEMA_VERSION) {
          cmp::Ordering::Less =>
            bail!(
              "index at `{}` appears to have been built with an older, incompatible version of ord, consider deleting and rebuilding the index: index schema {schema_version}, ord schema {SCHEMA_VERSION}",
              path.display()
            ),
          cmp::Ordering::Greater =>
            bail!(
              "index at `{}` appears to have been built with a newer, incompatible version of ord, consider updating ord: index schema {schema_version}, ord schema {SCHEMA_VERSION}",
              path.display()
            ),
          cmp::Ordering::Equal => {
          }
        }

        database
      }
      Err(_) => {       
        log::info!("open database fail. create one.");
 
        let database = Database::builder()
          .set_cache_size(db_cache_size)
          .create(&path)?;

        let tx = database.begin_write()?;

        #[cfg(test)]
        let tx = {
          let mut tx = tx;
          tx.set_durability(redb::Durability::None);
          tx
        };

        tx.open_table(HEIGHT_TO_BLOCK_HEADER)?;
        // tx.open_table(HEIGHT_TO_BLOCK_HASH)?;

        tx.open_table(INSCRIPTION_ID_TO_INSCRIPTION_ENTRY)?;
        tx.open_table(INSCRIPTION_ID_TO_SATPOINT)?;
        tx.open_table(INSCRIPTION_NUMBER_TO_INSCRIPTION_ID)?;
        tx.open_table(INSCRIPTION_ID_TO_TXIDS)?;
        tx.open_table(INSCRIPTION_TXID_TO_TX)?;
        tx.open_table(PARTIAL_TXID_TO_INSCRIPTION_TXIDS)?;
        tx.open_table(OUTPOINT_TO_VALUE)?;
        tx.open_table(SATPOINT_TO_INSCRIPTION_ID)?;
        tx.open_table(SAT_TO_INSCRIPTION_ID)?;
        tx.open_table(SAT_TO_SATPOINT)?;
        tx.open_table(WRITE_TRANSACTION_STARTING_BLOCK_COUNT_TO_TIMESTAMP)?;

        // shaneson add
        tx.open_table(OUTPOINT_TO_ENTRY)?;
        

        tx.open_table(STATISTIC_TO_COUNT)?
          .insert(&Statistic::Schema.key(), &SCHEMA_VERSION)?;

        if options.index_sats {
          tx.open_table(OUTPOINT_TO_SAT_RANGES)?
            .insert(&OutPoint::null().store(), [].as_slice())?;
        }

        tx.commit()?;

        database
      }
    };

    let genesis_block_coinbase_transaction =
      options.chain().genesis_block().coinbase().unwrap().clone();

    // shaneson checking
    let durability = if cfg!(test) {
      redb::Durability::None
    } else {
      redb::Durability::Immediate
    };

    Ok(Self {
      genesis_block_coinbase_txid: genesis_block_coinbase_transaction.txid(),
      auth,
      client,
      database,
      durability,
      path,
      first_inscription_height: options.first_inscription_height(),
      genesis_block_coinbase_transaction,
      height_limit: options.height_limit,
      reorged: AtomicBool::new(false),
      rpc_url,
      unrecoverably_reorged: AtomicBool::new(false),
      options: options.clone(),
    })
  }

  pub(crate) fn get_unspent_outputs(&self, _wallet: Wallet) -> Result<BTreeMap<OutPoint, Amount>> {
    let mut utxos = BTreeMap::new();
    utxos.extend(
      self
        .client
        .list_unspent(None, None, None, None, None)?
        .into_iter()
        .map(|utxo| {
          let outpoint = OutPoint::new(utxo.txid, utxo.vout);
          let amount = utxo.amount;

          (outpoint, amount)
        }),
    );

    #[derive(Deserialize)]
    pub(crate) struct JsonOutPoint {
      txid: bitcoin::Txid,
      vout: u32,
    }

    for JsonOutPoint { txid, vout } in self
      .client
      .call::<Vec<JsonOutPoint>>("listlockunspent", &[])?
    {
      utxos.insert(
        OutPoint { txid, vout },
        Amount::from_sat(self.client.get_raw_transaction(&txid)?.output[vout as usize].value),
      );
    }
    let rtx = self.database.begin_read()?;
    let outpoint_to_value = rtx.open_table(OUTPOINT_TO_VALUE)?;
    for outpoint in utxos.keys() {
      if outpoint_to_value.get(&outpoint.store())?.is_none() {
        return Err(anyhow!(
          "output in Dogecoin Core wallet but not in ord index: {outpoint}"
        ));
      }
    }

    Ok(utxos)
  }

  // shaneson add
  pub(crate) fn get_outpoint_entry(&self, outpoint: OutPoint) -> Result<Option<TxOut>> {
    let _TxOut = self
    .database
    .begin_read()?
    .open_table(OUTPOINT_TO_ENTRY)?
    .get(&outpoint.store())?
    .map(|x| Decodable::consensus_decode(&mut io::Cursor::new(x.value())).unwrap());
    
    log::info!(
        "txOut: {:?}", _TxOut
    );

    Ok(_TxOut)
  }

  pub(crate) fn get_unspent_output_ranges(
    &self,
    wallet: Wallet,
  ) -> Result<Vec<(OutPoint, Vec<(u64, u64)>)>> {
    self
      .get_unspent_outputs(wallet)?
      .into_keys()
      .map(|outpoint| match self.list(outpoint)? {
        Some(List::Unspent(sat_ranges)) => Ok((outpoint, sat_ranges)),
        Some(List::Spent) => bail!("output {outpoint} in wallet but is spent according to index"),
        None => bail!("index has not seen {outpoint}"),
      })
      .collect()
  }

  pub(crate) fn has_sat_index(&self) -> Result<bool> {
    match self.begin_read()?.0.open_table(OUTPOINT_TO_SAT_RANGES) {
      Ok(_) => Ok(true),
      Err(redb::TableError::TableDoesNotExist(_)) => Ok(false),
      Err(err) => Err(err.into()),
    }
  }

  fn require_sat_index(&self, feature: &str) -> Result {
    if !self.has_sat_index()? {
      bail!("{feature} requires index created with `--index-sats` flag")
    }

    Ok(())
  }

  pub(crate) fn info(&self) -> Result<Info> {
    let wtx = self.begin_write()?;

    let stats = wtx.stats()?;

    let info = {
      let statistic_to_count = wtx.open_table(STATISTIC_TO_COUNT)?;
      let sat_ranges = statistic_to_count
        .get(&Statistic::SatRanges.key())?
        .map(|x| x.value())
        .unwrap_or(0);
      let outputs_traversed = statistic_to_count
        .get(&Statistic::OutputsTraversed.key())?
        .map(|x| x.value())
        .unwrap_or(0);
      
      let _block_indexed = wtx
        .open_table(HEIGHT_TO_BLOCK_HEADER)?
        .range(0..)?
        .next_back()
        .and_then(|result| result.ok())
        .map(|(height, _header)| height.value() + 1)
        .unwrap_or(0);

      Info {
        index_path: self.path.clone(),
        blocks_indexed: _block_indexed,
        branch_pages: stats.branch_pages(),
        fragmented_bytes: stats.fragmented_bytes(),
        index_file_size: fs::metadata(&self.path)?.len(),
        leaf_pages: stats.leaf_pages(),
        metadata_bytes: stats.metadata_bytes(),
        sat_ranges,
        outputs_traversed,
        page_size: stats.page_size(),
        stored_bytes: stats.stored_bytes(),
        transactions: wtx
          .open_table(WRITE_TRANSACTION_STARTING_BLOCK_COUNT_TO_TIMESTAMP)?
          .range(0..)?
          .flat_map(|result| {
            result.map(
              |(starting_block_count, starting_timestamp)| TransactionInfo {
                starting_block_count: starting_block_count.value(),
                starting_timestamp: starting_timestamp.value(),
              },
            )
          })
          .collect(),
        tree_height: stats.tree_height(),
        utxos_indexed: wtx.open_table(OUTPOINT_TO_SAT_RANGES)?.len()?,
      }
    };

    Ok(info)
  }

  pub(crate) fn ord_get_txs_inscriptions(
      &self,
      txs: &Vec<Txid>,
  ) -> Result<Vec<(bitcoin::Txid, Vec<ord::InscriptionOp>)>> {
      let rtx = self.database.begin_read()?;
      let ord_db = ord::OrdDbReader::new(&rtx);
      let mut result = Vec::new();
      for txid in txs {
        let inscriptions = ord_db.get_transaction_operations(txid)?;
        if inscriptions.is_empty() {
          continue;
        }
        result.push((*txid, inscriptions));
      }
      Ok(result)
  }

  pub(crate) fn get_block_info_by_hash(&self, hash: BlockHash) -> Result<Option<GetBlockResult>> {
    self.client.get_block_info(&hash).into_option()
  }

  pub(crate) fn ord_txid_inscriptions(
    &self,
    txid: &Txid,
  ) -> Result<Option<Vec<ord::InscriptionOp>>> {
    let rtx = self.database.begin_read().unwrap();
    let ord_db = ord::OrdDbReader::new(&rtx);
    let res = ord_db.get_transaction_operations(txid)?;

    if res.is_empty() {
      let tx = self.client.get_raw_transaction_info(txid)?;
      if let Some(tx_blockhash) = tx.blockhash {
        let tx_bh = self.client.get_block_header_info(&tx_blockhash)?;
        let parsed_height = self.height()?;
        if parsed_height.is_none() || tx_bh.height as u64 > parsed_height.unwrap().0 {
          return Ok(None);
        }
      } else {
        return Err(anyhow!("can't get tx block hash: {txid}"));
      }
    }

    Ok(Some(res))
  }

  pub(crate) fn update(&self) -> Result {
    let mut updater = Updater::new(self)?;

    loop {
      match updater.update_index() {
        Ok(ok) => return Ok(ok),
        Err(err) => {
          log::info!("{}", err.to_string());

          match err.downcast_ref() {
            Some(&ReorgError::Recoverable { height, depth }) => {
              Reorg::handle_reorg(self, height, depth)?;

              updater = Updater::new(self)?;
            }
            Some(&ReorgError::Unrecoverable) => {
              self
                .unrecoverably_reorged
                .store(true, atomic::Ordering::Relaxed);
              return Err(anyhow!(ReorgError::Unrecoverable));
            }
            _ => return Err(err),
          };
        }
      }
    }
  }

  pub(crate) fn is_reorged(&self) -> bool {
    self.reorged.load(atomic::Ordering::Relaxed)
  }

  fn begin_read(&self) -> Result<rtx::Rtx> {
    Ok(rtx::Rtx(self.database.begin_read()?))
  }

  fn begin_write(&self) -> Result<WriteTransaction> {
    if cfg!(test) {
      let mut tx = self.database.begin_write()?;
      tx.set_durability(redb::Durability::None);
      Ok(tx)
    } else {
      Ok(self.database.begin_write()?)
    }
  }

  fn increment_statistic(wtx: &WriteTransaction, statistic: Statistic, n: u64) -> Result {
    let mut statistic_to_count = wtx.open_table(STATISTIC_TO_COUNT)?;
    let value = statistic_to_count
      .get(&(statistic.key()))?
      .map(|x| x.value())
      .unwrap_or(0)
      + n;
    statistic_to_count.insert(&statistic.key(), &value)?;
    Ok(())
  }

  #[cfg(test)]
  pub(crate) fn statistic(&self, statistic: Statistic) -> u64 {
    self
      .database
      .begin_read()
      .unwrap()
      .open_table(STATISTIC_TO_COUNT)
      .unwrap()
      .get(&statistic.key())
      .unwrap()
      .map(|x| x.value())
      .unwrap_or(0)
  }

  // shaneson: TODO
  pub(crate) fn is_unrecoverably_reorged(&self) -> bool {
    self.unrecoverably_reorged.load(atomic::Ordering::Relaxed)
  }

  pub(crate) fn get_chain_network(&self) -> Network {
    self.options.chain().network()
  }

  pub(crate) fn height(&self) -> Result<Option<Height>> {
    self.begin_read()?.block_height()
  }

  pub(crate) fn block_count(&self) -> Result<u64> {
    self.begin_read()?.block_count()
  }

  pub(crate) fn block_hash(&self, height: Option<u64>) -> Result<Option<BlockHash>> {
    self.begin_read()?.block_hash(height)
  }

  pub(crate) fn blocks(&self, take: usize) -> Result<Vec<(u64, BlockHash)>> {
    let rtx = self.begin_read()?;

    let block_count = rtx.block_count()?;

    let height_to_block_header = rtx.0.open_table(HEIGHT_TO_BLOCK_HEADER)?;

    let mut blocks = Vec::with_capacity(block_count.try_into().unwrap());

    for next in height_to_block_header
      .range(0..block_count)?
      .rev()
      .take(take)
    {
      let next = next?;
      blocks.push((next.0.value(), Entry::load(*next.1.value())));
    }

    Ok(blocks)
  }

  pub(crate) fn rare_sat_satpoints(&self) -> Result<Option<Vec<(Sat, SatPoint)>>> {
    if self.has_sat_index()? {
      let mut result = Vec::new();

      let rtx = self.database.begin_read()?;

      let sat_to_satpoint = rtx.open_table(SAT_TO_SATPOINT)?;

      for range in sat_to_satpoint.range(0..)? {
        let (sat, satpoint) = range?;
        result.push((Sat(sat.value()), Entry::load(*satpoint.value())));
      }

      Ok(Some(result))
    } else {
      Ok(None)
    }
  }

  pub(crate) fn get_chain_height(&self) -> Result<u64> {
    Ok(self.client.get_block_count().unwrap())
  }

  pub(crate) fn rare_sat_satpoint(&self, sat: Sat) -> Result<Option<SatPoint>> {
    if self.has_sat_index()? {
      Ok(
        self
          .database
          .begin_read()?
          .open_table(SAT_TO_SATPOINT)?
          .get(&sat.n())?
          .map(|satpoint| Entry::load(*satpoint.value())),
      )
    } else {
      Ok(None)
    }
  }

  pub(crate) fn block_header(&self, hash: BlockHash) -> Result<Option<BlockHeader>> {
    self.client.get_block_header(&hash).into_option()
  }

  pub(crate) fn block_header_info(&self, hash: BlockHash) -> Result<Option<GetBlockHeaderResult>> {
    self.client.get_block_header_info(&hash).into_option()
  }

  pub(crate) fn get_block_by_height(&self, height: u64) -> Result<Option<Block>> {
    Ok(
      self
        .client
        .get_block_hash(height.into())
        .into_option()?
        .map(|hash| self.client.get_block(&hash))
        .transpose()?,
    )
  }

  pub(crate) fn get_block_by_hash(&self, hash: BlockHash) -> Result<Option<Block>> {
    self.client.get_block(&hash).into_option()
  }

  pub(crate) fn get_inscription_id_by_sat(&self, sat: Sat) -> Result<Option<InscriptionId>> {
    Ok(
      self
        .database
        .begin_read()?
        .open_table(SAT_TO_INSCRIPTION_ID)?
        .get(&sat.n())?
        .map(|inscription_id| Entry::load(*inscription_id.value())),
    )
  }

  pub(crate) fn get_inscription_id_by_inscription_number(&self, n: u64) -> Result<Option<InscriptionId>> {
    Ok(
      self
        .database
        .begin_read()?
        .open_table(INSCRIPTION_NUMBER_TO_INSCRIPTION_ID)?
        .get(&n)?
        .map(|id| Entry::load(*id.value())),
    )
  }

  pub(crate) fn get_inscription_satpoint_by_id(&self, inscription_id: InscriptionId) -> Result<Option<SatPoint>> {
    Ok(
      self
        .database
        .begin_read()?
        .open_table(INSCRIPTION_ID_TO_SATPOINT)?
        .get(&inscription_id.store())?
        .map(|satpoint| Entry::load(*satpoint.value())),
    )
  }

  pub(crate) fn get_inscription_by_id(&self, inscription_id: InscriptionId) -> Result<Option<Inscription>> {
    if self
      .database
      .begin_read()?
      .open_table(INSCRIPTION_ID_TO_SATPOINT)?
      .get(&inscription_id.store())?
      .is_none()
    {
      return Ok(None);
    }

    let reader = self.database.begin_read()?;

    let table = reader.open_table(INSCRIPTION_ID_TO_TXIDS)?;
    let txids_result = table.get(&inscription_id.store())?;

    match txids_result {
      Some(txids) => {
        let mut txs = vec![];

        let txids = txids.value();

        for i in 0..txids.len() / 32 {
          let txid_buf = &txids[i * 32..i * 32 + 32];
          let table = reader.open_table(INSCRIPTION_TXID_TO_TX)?;
          let tx_result = table.get(txid_buf)?;

          match tx_result {
            Some(tx_result) => {
              let tx_buf = tx_result.value().to_vec();
              let mut cursor = Cursor::new(tx_buf);
              let tx = bitcoin::Transaction::consensus_decode(&mut cursor)?;
              txs.push(tx);
            }
            None => return Ok(None),
          }
        }

        let parsed_inscription = Inscription::from_transactions(txs);

        match parsed_inscription {
          ParsedInscription::None => return Ok(None),
          ParsedInscription::Partial => return Ok(None),
          ParsedInscription::Complete(inscription) => Ok(Some(inscription)),
        }
      }

      None => return Ok(None),
    }
  }

  pub(crate) fn get_inscriptions_on_output(&self, outpoint: OutPoint) -> Result<Vec<InscriptionId>> {
    Ok(
      Self::inscriptions_on_output(
        &self
          .database
          .begin_read()?
          .open_table(SATPOINT_TO_INSCRIPTION_ID)?,
        outpoint,
      )?
      .into_iter()
      .map(|(_satpoint, inscription_id)| inscription_id)
      .collect(),
    )
  }

  // shaneson add
  pub(crate) fn transaction_output_by_outpoint(
    outpoint_to_entry: &impl ReadableTable<&'static OutPointValue, &'static [u8]>,
    outpoint: OutPoint,
  ) -> Result<Option<TxOut>> {
    Ok(
      outpoint_to_entry
        .get(&outpoint.store())?
        .map(|x| Decodable::consensus_decode(&mut io::Cursor::new(x.value())).unwrap()),
    )
  }

  // shaneson add
  pub(crate) fn get_transaction_output_by_outpoint(
    &self,
    outpoint: OutPoint,
  ) -> Result<Option<TxOut>> {
    Self::transaction_output_by_outpoint(
      &self.database.begin_read()?.open_table(OUTPOINT_TO_ENTRY)?,
      outpoint,
    )
  }

  pub(crate) fn latest_block(&self) -> Result<Option<(Height, BlockHash)>> {
    self.begin_read()?.latest_block()
  }

  pub(crate) fn get_transaction(&self, txid: Txid) -> Result<Option<Transaction>> {
    if txid == self.genesis_block_coinbase_txid {
      Ok(Some(self.genesis_block_coinbase_transaction.clone()))
    } else {
      self.client.get_raw_transaction(&txid).into_option()
    }
  }

  pub(crate) fn get_transaction_blockhash(&self, txid: Txid) -> Result<Option<BlockHash>> {
    Ok(
      self
        .client
        .get_raw_transaction_info(&txid)
        .into_option()?
        .and_then(|info| {
          if info.in_active_chain.unwrap_or_default() {
            info.blockhash
          } else {
            None
          }
        }),
    )
  }

  pub(crate) fn is_transaction_in_active_chain(&self, txid: Txid) -> Result<bool> {
    Ok(
      self
        .client
        .get_raw_transaction_info(&txid)
        .into_option()?
        .and_then(|info| info.in_active_chain)
        .unwrap_or(false),
    )
  }

  pub(crate) fn find(&self, sat: u64) -> Result<Option<SatPoint>> {
    self.require_sat_index("find")?;

    let rtx = self.begin_read()?;

    if rtx.block_count()? <= Sat(sat).height().n() {
      return Ok(None);
    }

    let outpoint_to_sat_ranges = rtx.0.open_table(OUTPOINT_TO_SAT_RANGES)?;

    for range in outpoint_to_sat_ranges.range::<&[u8; 36]>(&[0; 36]..)? {
      let (key, value) = range?;
      let mut offset = 0;
      for chunk in value.value().chunks_exact(11) {
        let (start, end) = SatRange::load(chunk.try_into().unwrap());
        if start <= sat && sat < end {
          return Ok(Some(SatPoint {
            outpoint: Entry::load(*key.value()),
            offset: offset + sat - start,
          }));
        }
        offset += end - start;
      }
    }

    Ok(None)
  }

  fn list_inner(&self, outpoint: OutPointValue) -> Result<Option<Vec<u8>>> {
    Ok(
      self
        .database
        .begin_read()?
        .open_table(OUTPOINT_TO_SAT_RANGES)?
        .get(&outpoint)?
        .map(|outpoint| outpoint.value().to_vec()),
    )
  }

  pub(crate) fn list(&self, outpoint: OutPoint) -> Result<Option<List>> {
    self.require_sat_index("list")?;

    let array = outpoint.store();

    let sat_ranges = self.list_inner(array)?;

    match sat_ranges {
      Some(sat_ranges) => Ok(Some(List::Unspent(
        sat_ranges
          .chunks_exact(11)
          .map(|chunk| SatRange::load(chunk.try_into().unwrap()))
          .collect(),
      ))),
      None => {
        if self.is_transaction_in_active_chain(outpoint.txid)? {
          Ok(Some(List::Spent))
        } else {
          Ok(None)
        }
      }
    }
  }

  pub(crate) fn blocktime(&self, height: Height) -> Result<Blocktime> {
    let height = height.n();

    match self.get_block_by_height(height)? {
      Some(block) => Ok(Blocktime::confirmed(block.header.time)),
      None => {
        let tx = self.database.begin_read()?;

        let current = tx.open_table(HEIGHT_TO_BLOCK_HEADER)?
          .range(0..)?
          .next_back()
          .and_then(|result| result.ok())
          .map(|(height, _header)| height)
          .map(|x| x.value())
          .unwrap_or(0);

        let expected_blocks = height.checked_sub(current).with_context(|| {
          format!("current {current} height is greater than sat height {height}")
        })?;

        Ok(Blocktime::Expected(
          Utc::now()
            .round_subsecs(0)
            .checked_add_signed(chrono::Duration::seconds(
              10 * 60 * i64::try_from(expected_blocks)?,
            ))
            .ok_or_else(|| anyhow!("block timestamp out of range"))?,
        ))
      }
    }
  }

  // shaneson add
  pub(crate) fn get_transaction_info(
    &self,
    txid: &bitcoin::Txid,
  ) -> Result<Option<bitcoincore_rpc::json::GetRawTransactionResult>> {
    if *txid == self.genesis_block_coinbase_txid {
      Ok(None)
    } else {
      self
        .client
        .get_raw_transaction_info(txid)
        .into_option()
    }
  }

  // shaneson todo: check
  pub(crate) fn get_inscriptions(
    &self,
    n: Option<usize>,
  ) -> Result<BTreeMap<SatPoint, InscriptionId>> {
    let mut inscriptions: Vec<(SatPoint, InscriptionId)> = Vec::new();

    for (range) in self
          .database.begin_read()?
          .open_table(SATPOINT_TO_INSCRIPTION_ID)?
          .range::<&[u8; 44]>(&[0; 44]..)? {
        let (satpoint, id) = range?;
        inscriptions.push((Entry::load(*satpoint.value()), Entry::load(*id.value())));
    }

    Ok(inscriptions
        .into_iter()
        .take(n.unwrap_or(usize::MAX))
        .collect()
    )
  }

  pub(crate) fn get_homepage_inscriptions(&self) -> Result<Vec<InscriptionId>> {
    let mut inscriptions: Vec<(InscriptionId)> = Vec::new();

    for result in self
        .database
        .begin_read()?
        .open_table(INSCRIPTION_NUMBER_TO_INSCRIPTION_ID)?
        .iter()?
        .rev()
        .take(8)
        .next()
      {
          let (_number, id) = result? ;
          inscriptions.push(Entry::load(*id.value()));
      }

    Ok(inscriptions)
  }

  pub(crate) fn get_latest_inscriptions_with_prev_and_next(
    &self,
    n: usize,
    from: Option<u64>,
  ) -> Result<(Vec<InscriptionId>, Option<u64>, Option<u64>)> {
    let rtx = self.database.begin_read()?;

    let inscription_number_to_inscription_id =
      rtx.open_table(INSCRIPTION_NUMBER_TO_INSCRIPTION_ID)?;

    let (latest) = match inscription_number_to_inscription_id.iter()?.rev().next() {
      Some(result) => result?.0.value(),
      None => return Ok(Default::default()),
    };

    // shaneson todo
    let from = from.unwrap_or(latest);

    let prev = if let Some(prev) = from.checked_sub(n.try_into()?) {
      inscription_number_to_inscription_id
        .get(&prev)?
        .map(|_| prev)
    } else {
      None
    };

    let next = if from < latest {
      Some(
        from
          .checked_add(n.try_into()?)
          .unwrap_or(latest)
          .min(latest),
      )
    } else {
      None
    };

    // Entry::load(*id.value()))
    let inscriptions = inscription_number_to_inscription_id
      .range(..=from)?
      .rev()
      .take(n)
      .map(|result| Entry::load(*(result.unwrap()).1.value()) )
      // shaneson delete: .map(|(_number, id)| Entry::load(*id.value()))
      .collect();

    Ok((inscriptions, prev, next))
  }

  pub(crate) fn get_feed_inscriptions(&self, n: usize) -> Result<Vec<(u64, InscriptionId)>> {
    Ok(
      self
        .database
        .begin_read()?
        .open_table(INSCRIPTION_NUMBER_TO_INSCRIPTION_ID)?
        .iter()?
        .rev()
        .take(n)
        .flat_map(|result| result.map(|(number, id)| (number.value(), Entry::load(*id.value()))))
        // shaneson update: .map(|(number, id)| (number.value(), Entry::load(*id.value())))
        .collect()
    )
  }

  pub(crate) fn get_inscription_entry(
    &self,
    inscription_id: InscriptionId,
  ) -> Result<Option<InscriptionEntry>> {
    Ok(
      self
        .database
        .begin_read()?
        .open_table(INSCRIPTION_ID_TO_INSCRIPTION_ENTRY)?
        .get(&inscription_id.store())?
        .map(|value: redb::AccessGuard<'_, (u64, u64, u64, u64, u32)>| InscriptionEntry::load(value.value())),
    )
  }

  // shaneson add
  pub(crate) fn get_transaction_retries_by_index(
    &self,
    txid: Txid,
  ) -> Result<Option<Transaction>> {
    Index::get_transaction_retries(&self.client, txid)
  }
  
  // shaneson add 
  pub(crate) fn get_transaction_retries(
    client: &Client,
    txid: Txid,
  ) -> Result<Option<Transaction>> {
    let mut errors = 0;

    loop {
      match client.get_raw_transaction(&txid).into_option() {
        Err(err) => {
          if cfg!(test) {
            return Err(err);
          }
          errors += 1;
          let seconds = 1 << errors;
          log::warn!("failed to fetch transaction {txid}, retrying in {seconds}s: {err}");

          if seconds > 120 {
            log::error!("would sleep for more than 120s, giving up");
            return Err(err);
          }

          thread::sleep(Duration::from_secs(seconds));
        }
        Ok(result) => return Ok(result),
      }
    }
  }

  // shaneson check
  fn get_satpoint_by_inscriptionId<'a: 'tx, 'tx>(
    id_to_satpoint: &'a impl ReadableTable<&'static InscriptionIdValue, &'static SatPointValue>,
    outpoint: &InscriptionIdValue,
  ) -> Result<Option<SatPoint>>{
      Ok(
        id_to_satpoint.get(outpoint)?
        .map(|value| SatPoint::load(*(value.value())))
      )
  }

  // shaneson check
  fn inscriptions_on_output<'a: 'tx, 'tx>(
    satpoint_to_id: &'a impl ReadableTable<&'static SatPointValue, &'static InscriptionIdValue>,
    outpoint: OutPoint,
  ) -> Result<impl Iterator<Item = (SatPoint, InscriptionId)> + 'tx> {
    let start = SatPoint {
      outpoint,
      offset: 0,
    }
    .store();

    let end = SatPoint {
      outpoint,
      offset: u64::MAX,
    }
    .store();

    let mut sats_and_inscriptions: Vec<(SatPoint, InscriptionId)> = Vec::new();

    for result in satpoint_to_id.range::<&[u8; 44]>(&start..=&end)? {
      let (satpoint, id) = result?;
      sats_and_inscriptions.push((Entry::load(*satpoint.value()), Entry::load(*id.value())));
    }

    Ok(sats_and_inscriptions.into_iter())
  }

}