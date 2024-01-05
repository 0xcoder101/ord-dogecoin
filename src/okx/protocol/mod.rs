
pub(crate) mod ord;
pub(crate) mod protocol_manager;

pub use self::protocol_manager::ProtocolManager;

use {
  crate::Options,
  bitcoin::Network,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BlockContext {
  pub network: Network,
  pub blockheight: u64,
  pub blocktime: u32,
}
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
  first_inscription_height: u64,
  enable_ord_receipts: bool,
}

impl ProtocolConfig {
  pub(crate) fn new_with_options(options: &Options) -> Self {
    let mut config = Self {
      first_inscription_height: options.first_inscription_height(),
      enable_ord_receipts: true
    };
    config
  }
}
