use {
  self::{
    deserialize_from_str::DeserializeFromStr,
    error::{ApiError, OptionExt, ServerError, ServerResult},
  },
  super::*,
  crate::page_config::PageConfig,
  crate::templates::{
    BlockJson, BlockHtml, HomeHtml, InputHtml, InscriptionHtml, InscriptionJson,
    InscriptionsHtml, OutputHtml, PageContent,
    PageHtml, PreviewAudioHtml, PreviewImageHtml, PreviewPdfHtml, PreviewTextHtml,
    PreviewUnknownHtml, PreviewVideoHtml, RangeHtml, RareTxt, SatHtml, TransactionHtml,
  },
  axum::{
    body,
    extract::{Extension, Json, Path, Query},
    headers::UserAgent,
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router, TypedHeader,
  },
  axum_server::Handle,
  rust_embed::RustEmbed,
  rustls_acme::{
    acme::{LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY},
    axum::AxumAcceptor,
    caches::DirCache,
    AcmeConfig,
  },
  std::{cmp::Ordering, str},
  tokio_stream::StreamExt,
  tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    set_header::SetResponseHeaderLayer,
  },
  std::collections::HashMap,
  serde_json::to_string,
};

mod error;
mod ord;
mod api;
mod response;

use self::api::*;
use self::response::ApiResponse;

enum BlockQuery {
  Height(u64),
  Hash(BlockHash),
}

impl FromStr for BlockQuery {
  type Err = Error;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Ok(if s.len() == 64 {
      BlockQuery::Hash(s.parse()?)
    } else {
      BlockQuery::Height(s.parse()?)
    })
  }
}

enum SpawnConfig {
  Https(AxumAcceptor),
  Http,
  Redirect(String),
}

#[derive(Deserialize)]
struct InscriptionsByOutputsQuery {
  outputs: String,
}

#[derive(Deserialize)]
struct Search {
  query: String,
}

#[derive(RustEmbed)]
#[folder = "static"]
struct StaticAssets;

struct StaticHtml {
  title: &'static str,
  html: &'static str,
}

impl PageContent for StaticHtml {
  fn title(&self) -> String {
    self.title.into()
  }
}

impl Display for StaticHtml {
  fn fmt(&self, f: &mut Formatter) -> fmt::Result {
    f.write_str(self.html)
  }
}

#[derive(Debug, Parser)]
pub(crate) struct Server {
  #[clap(
    long,
    default_value = "0.0.0.0",
    help = "Listen on <ADDRESS> for incoming requests."
  )]
  address: String,
  #[clap(
    long,
    help = "Request ACME TLS certificate for <ACME_DOMAIN>. This ord instance must be reachable at <ACME_DOMAIN>:443 to respond to Let's Encrypt ACME challenges."
  )]
  acme_domain: Vec<String>,
  #[clap(
    long,
    help = "Listen on <HTTP_PORT> for incoming HTTP requests. [default: 80]."
  )]
  http_port: Option<u16>,
  #[clap(
    long,
    group = "port",
    help = "Listen on <HTTPS_PORT> for incoming HTTPS requests. [default: 443]."
  )]
  https_port: Option<u16>,
  #[clap(long, help = "Store ACME TLS certificates in <ACME_CACHE>.")]
  acme_cache: Option<PathBuf>,
  #[clap(long, help = "Provide ACME contact <ACME_CONTACT>.")]
  acme_contact: Vec<String>,
  #[clap(long, help = "Serve HTTP traffic on <HTTP_PORT>.")]
  http: bool,
  #[clap(long, help = "Serve HTTPS traffic on <HTTPS_PORT>.")]
  https: bool,
  #[clap(long, help = "Redirect HTTP traffic to HTTPS.")]
  redirect_http_to_https: bool,
}

impl Server {
  pub(crate) fn run(self, options: Options, index: Arc<Index>, handle: Handle) -> Result {
    Runtime::new()?.block_on(async {
      let clone = index.clone();
      thread::spawn(move || loop {
        if let Err(error) = clone.update() {
          log::warn!("{error}");
        }
        thread::sleep(Duration::from_millis(5000));
      });

      let config = options.load_config()?;
      let acme_domains = self.acme_domains()?;

      let page_config = Arc::new(PageConfig {
        chain: options.chain(),
        domain: acme_domains.first().cloned(),
      });

      let api_v1_router = Router::new()
        .route(
          "/ord/tx/:txid/inscriptions",
          get(ord::ord_txid_inscriptions),
        );

      let api_router = Router::new().nest("/v1", api_v1_router);

      let router = Router::new()
        .route("/", get(Self::home))
        .route("/block-count", get(Self::block_count))
        .route("/block/:query", get(Self::block))
        .route("/blocks/:query/:endquery", get(Self::blocks))
        .route("/bounties", get(Self::bounties))
        .route("/content/:inscription_id", get(Self::content))
        .route("/faq", get(Self::faq))
        .route("/favicon.ico", get(Self::favicon))
        .route("/feed.xml", get(Self::feed))
        .route("/input/:block/:transaction/:input", get(Self::input))
        .route("/inscription/:inscription_id", get(Self::inscription))
        .route("/inscriptions", get(Self::inscriptions))
        .route("/inscriptions/:from", get(Self::inscriptions_from))
        .route("/shibescription/:inscription_id", get(Self::inscription))
        .route("/shibescriptions", get(Self::inscriptions))
        .route("/shibescriptions/:from", get(Self::inscriptions_from))
        .route("/shibescriptions_on_outputs", get(Self::inscriptions_by_outputs))
        .route("/install.sh", get(Self::install_script))
        .route("/ordinal/:sat", get(Self::ordinal))
        .route("/output/:output", get(Self::output))
        .route("/preview/:inscription_id", get(Self::preview))
        .route("/range/:start/:end", get(Self::range))
        .route("/rare.txt", get(Self::rare_txt))
        .route("/sat/:sat", get(Self::sat))
        .route("/search", get(Self::search_by_query))
        .route("/search/:query", get(Self::search_by_path))
        .route("/static/*path", get(Self::static_asset))
        .route("/status", get(Self::status))
        .route("/tx/:txid", get(Self::transaction))
        .nest("/api", api_router)
        .layer(Extension(index))
        .layer(Extension(page_config))
        .layer(Extension(Arc::new(config)))
        .layer(SetResponseHeaderLayer::if_not_present(
          header::CONTENT_SECURITY_POLICY,
          HeaderValue::from_static("default-src 'self'"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
          header::STRICT_TRANSPORT_SECURITY,
          HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        ))
        .layer(
          CorsLayer::new()
            .allow_methods([http::Method::GET])
            .allow_origin(Any),
        )
        .layer(CompressionLayer::new());

      match (self.http_port(), self.https_port()) {
        (Some(http_port), None) => {
          self
            .spawn(router, handle, http_port, SpawnConfig::Http)?
            .await??
        }
        (None, Some(https_port)) => {
          self
            .spawn(
              router,
              handle,
              https_port,
              SpawnConfig::Https(self.acceptor(&options)?),
            )?
            .await??
        }
        (Some(http_port), Some(https_port)) => {
          let http_spawn_config = if self.redirect_http_to_https {
            SpawnConfig::Redirect(if https_port == 443 {
              format!("https://{}", acme_domains[0])
            } else {
              format!("https://{}:{https_port}", acme_domains[0])
            })
          } else {
            SpawnConfig::Http
          };

          let (http_result, https_result) = tokio::join!(
            self.spawn(router.clone(), handle.clone(), http_port, http_spawn_config)?,
            self.spawn(
              router,
              handle,
              https_port,
              SpawnConfig::Https(self.acceptor(&options)?),
            )?
          );
          http_result.and(https_result)??;
        }
        (None, None) => unreachable!(),
      }

      Ok(())
    })
  }

  fn spawn(
    &self,
    router: Router,
    handle: Handle,
    port: u16,
    config: SpawnConfig,
  ) -> Result<task::JoinHandle<io::Result<()>>> {
    let addr = (self.address.as_str(), port)
      .to_socket_addrs()?
      .next()
      .ok_or_else(|| anyhow!("failed to get socket addrs"))?;

    if !integration_test() {
      eprintln!(
        "Listening on {}://{addr}",
        match config {
          SpawnConfig::Https(_) => "https",
          _ => "http",
        }
      );
    }

    Ok(tokio::spawn(async move {
      match config {
        SpawnConfig::Https(acceptor) => {
          axum_server::Server::bind(addr)
            .handle(handle)
            .acceptor(acceptor)
            .serve(router.into_make_service())
            .await
        }
        SpawnConfig::Redirect(destination) => {
          axum_server::Server::bind(addr)
            .handle(handle)
            .serve(
              Router::new()
                .fallback(Self::redirect_http_to_https)
                .layer(Extension(destination))
                .into_make_service(),
            )
            .await
        }
        SpawnConfig::Http => {
          axum_server::Server::bind(addr)
            .handle(handle)
            .serve(router.into_make_service())
            .await
        }
      }
    }))
  }

  fn acme_cache(acme_cache: Option<&PathBuf>, options: &Options) -> Result<PathBuf> {
    let acme_cache = if let Some(acme_cache) = acme_cache {
      acme_cache.clone()
    } else {
      options.data_dir()?.join("acme-cache")
    };

    Ok(acme_cache)
  }

  fn acme_domains(&self) -> Result<Vec<String>> {
    if !self.acme_domain.is_empty() {
      Ok(self.acme_domain.clone())
    } else {
      Ok(vec![sys_info::hostname()?])
    }
  }

  fn http_port(&self) -> Option<u16> {
    if self.http || self.http_port.is_some() || (self.https_port.is_none() && !self.https) {
      Some(self.http_port.unwrap_or(80))
    } else {
      None
    }
  }

  fn https_port(&self) -> Option<u16> {
    if self.https || self.https_port.is_some() {
      Some(self.https_port.unwrap_or(443))
    } else {
      None
    }
  }

  fn acceptor(&self, options: &Options) -> Result<AxumAcceptor> {
    let config = AcmeConfig::new(self.acme_domains()?)
      .contact(&self.acme_contact)
      .cache_option(Some(DirCache::new(Self::acme_cache(
        self.acme_cache.as_ref(),
        options,
      )?)))
      .directory(if cfg!(test) {
        LETS_ENCRYPT_STAGING_DIRECTORY
      } else {
        LETS_ENCRYPT_PRODUCTION_DIRECTORY
      });

    let mut state = config.state();

    let acceptor = state.axum_acceptor(Arc::new(
      rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(state.resolver()),
    ));

    tokio::spawn(async move {
      while let Some(result) = state.next().await {
        match result {
          Ok(ok) => log::info!("ACME event: {:?}", ok),
          Err(err) => log::error!("ACME error: {:?}", err),
        }
      }
    });

    Ok(acceptor)
  }

  fn index_height(index: &Index) -> ServerResult<Height> {
    index.height()?.ok_or_not_found(|| "genesis block")
  }

  async fn sat(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(DeserializeFromStr(sat)): Path<DeserializeFromStr<Sat>>,
  ) -> ServerResult<PageHtml<SatHtml>> {
    let satpoint = index.rare_sat_satpoint(sat)?;

    Ok(
      SatHtml {
        sat,
        satpoint,
        blocktime: index.blocktime(sat.height())?,
        inscription: index.get_inscription_id_by_sat(sat)?,
      }
      .page(page_config, index.has_sat_index()?),
    )
  }

  async fn ordinal(Path(sat): Path<String>) -> Redirect {
    Redirect::to(&format!("/sat/{sat}"))
  }

  async fn output(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(outpoint): Path<OutPoint>,
  ) -> ServerResult<PageHtml<OutputHtml>> {
    let list = if index.has_sat_index()? {
      index.list(outpoint)?
    } else {
      None
    };

    let output = if outpoint == OutPoint::null() {
      let mut value = 0;

      if let Some(List::Unspent(ranges)) = &list {
        for (start, end) in ranges {
          value += u64::try_from(end - start).unwrap();
        }
      }

      TxOut {
        value,
        script_pubkey: Script::new(),
      }
    } else {
      index
        .get_transaction(outpoint.txid)?
        .ok_or_not_found(|| format!("output {outpoint}"))?
        .output
        .into_iter()
        .nth(outpoint.vout as usize)
        .ok_or_not_found(|| format!("output {outpoint}"))?
    };

    let inscriptions = index.get_inscriptions_on_output(outpoint)?;

    Ok(
      OutputHtml {
        outpoint,
        inscriptions,
        list,
        chain: page_config.chain,
        output,
      }
      .page(page_config, index.has_sat_index()?),
    )
  }

  async fn range(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path((DeserializeFromStr(start), DeserializeFromStr(end))): Path<(
      DeserializeFromStr<Sat>,
      DeserializeFromStr<Sat>,
    )>,
  ) -> ServerResult<PageHtml<RangeHtml>> {
    match start.cmp(&end) {
      Ordering::Equal => Err(ServerError::BadRequest("empty range".to_string())),
      Ordering::Greater => Err(ServerError::BadRequest(
        "range start greater than range end".to_string(),
      )),
      Ordering::Less => Ok(RangeHtml { start, end }.page(page_config, index.has_sat_index()?)),
    }
  }

  async fn rare_txt(Extension(index): Extension<Arc<Index>>) -> ServerResult<RareTxt> {
    Ok(RareTxt(index.rare_sat_satpoints()?.ok_or_else(|| {
      ServerError::NotFound(
        "tracking rare sats requires index created with `--index-sats` flag".into(),
      )
    })?))
  }

  async fn home(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
  ) -> ServerResult<PageHtml<HomeHtml>> {
    Ok(
      HomeHtml::new(index.blocks(100)?, index.get_homepage_inscriptions()?)
        .page(page_config, index.has_sat_index()?),
    )
  }

  async fn install_script() -> Redirect {
    Redirect::to("https://raw.githubusercontent.com/apezord/ord-dogecoin/master/install.sh")
  }

  async fn block(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(DeserializeFromStr(query)): Path<DeserializeFromStr<BlockQuery>>,
  ) -> ServerResult<PageHtml<BlockHtml>> {
    let (block, height) = match query {
      BlockQuery::Height(height) => {
        let block = index
            .get_block_by_height(height)?
            .ok_or_not_found(|| format!("block {height}"))?;

        (block, height)
      }
      BlockQuery::Hash(hash) => {
        let info = index
            .block_header_info(hash)?
            .ok_or_not_found(|| format!("block {hash}"))?;

        let block = index
            .get_block_by_hash(hash)?
            .ok_or_not_found(|| format!("block {hash}"))?;

        (block, info.height as u64)
      }
    };

    // Prepare the inputs_per_tx map
    let inputs_per_tx = block.txdata.iter()
        .map(|tx| {
          let txid = tx.txid();
          let inputs = tx.input.iter()
              .map(|input| input.previous_output.to_string())
              .collect::<Vec<_>>()
              .join(",");
          (txid, inputs)
        })
        .collect::<HashMap<_, _>>();

    // Prepare the outputs_per_tx map
    let outputs_per_tx = block.txdata.iter()
        .map(|tx| {
          let txid = tx.txid();
          let outputs = tx.output.iter()
              .enumerate()  // Enumerate the iterator to get the index of each output
              .map(|(vout, _output)| {
                let outpoint = OutPoint::new(txid, vout as u32);  // Create the OutPoint from txid and vout
                outpoint.to_string()  // Convert the OutPoint to a string
              })
              .collect::<Vec<_>>()
              .join(",");
          (txid, outputs)
        })
        .collect::<HashMap<_, _>>();

    // Prepare the output values per tx
    let output_values_per_tx = block.txdata.iter()
        .map(|tx| {
          let txid = tx.txid();
          let output_values = tx.output.iter()
              .map(|output| output.value.to_string())
              .collect::<Vec<_>>()
              .join(",");
          (txid, output_values)
        })
        .collect::<HashMap<_, _>>();

    let output_addresses_per_tx: HashMap<_, _> = block.txdata.iter()
        .map(|tx| {
          let txid = tx.txid();
          let addresses = tx.output.iter()
              .map(|output| page_config.chain.address_from_script(&output.script_pubkey)
                  .map(|address| address.to_string())
                  .unwrap_or_else(|_| String::new()))
              .collect::<Vec<_>>()
              .join(",");
          (txid, addresses)
        })
        .collect();

    let inscriptions_per_tx: HashMap<_, _> = block.txdata.iter()
        .filter_map(|tx| {
          let txid = tx.txid();
          match index.get_inscription_by_id(txid.into()) {
            Ok(Some(inscription)) => {
              let inscription_id = InscriptionId::from(txid);
              let content_type = inscription.content_type().map(|s| s.to_string());  // Convert content type to Option<String>
              let content = inscription.into_body();
              Some((txid, (inscription_id, content_type, content)))
            }
            _ => None,
          }
        })
        .collect();

    Ok(
      BlockHtml::new(block, Height(height), Self::index_height(&index)?, inputs_per_tx,  outputs_per_tx, output_values_per_tx, inscriptions_per_tx, output_addresses_per_tx)
          .page(page_config, index.has_sat_index()?),
    )
  }

  async fn blocks(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(path): Path<(u64, u64)>
  ) -> Result<String, ServerError> {
    let (height, endheight) = path;
    let mut blocks = vec![];
    for height in height..endheight {
      let block = index
          .get_block_by_height(height)?
          .ok_or_not_found(|| format!("block {}", height))?;

      let txids = block.txdata.iter()
          .map(|tx| tx.txid().to_string())
          .collect::<Vec<_>>()
          .join(",");

      // Prepare the inputs_per_tx map
      let inputs_per_tx = block.txdata.iter()
          .map(|tx| {
            let txid = tx.txid();
            let inputs = tx.input.iter()
                .map(|input| input.previous_output.to_string())
                .collect::<Vec<_>>()
                .join(",");
            (txid, inputs)
          })
          .collect::<HashMap<_, _>>();

      // Prepare the outputs_per_tx map
      let outputs_per_tx = block.txdata.iter()
          .map(|tx| {
            let txid = tx.txid();
            let outputs = tx.output.iter()
                .enumerate()  // Enumerate the iterator to get the index of each output
                .map(|(vout, _output)| {
                  let outpoint = OutPoint::new(txid, vout as u32);  // Create the OutPoint from txid and vout
                  outpoint.to_string()  // Convert the OutPoint to a string
                })
                .collect::<Vec<_>>()
                .join(",");
            (txid, outputs)
          })
          .collect::<HashMap<_, _>>();

      // Prepare the output values per tx
      let output_values_per_tx = block.txdata.iter()
          .map(|tx| {
            let txid = tx.txid();
            let output_values = tx.output.iter()
                .map(|output| output.value.to_string())
                .collect::<Vec<_>>()
                .join(",");
            (txid, output_values)
          })
          .collect::<HashMap<_, _>>();

      let output_addresses_per_tx: HashMap<_, _> = block.txdata.iter()
          .map(|tx| {
            let txid = tx.txid();
            let addresses = tx.output.iter()
                .map(|output| page_config.chain.address_from_script(&output.script_pubkey)
                    .map(|address| address.to_string())
                    .unwrap_or_else(|_| String::new()))
                .collect::<Vec<_>>()
                .join(",");
            (txid, addresses)
          })
          .collect();

      let output_scripts_per_tx: HashMap<_, _> = block.txdata.iter()
          .map(|tx| {
            let txid = tx.txid();
            let scripts = tx.output.iter()
                .map(|output| {
                  // Convert the byte array to a hexadecimal string.
                  // If the byte array is empty, this will result in an empty string.
                  hex::encode(&output.script_pubkey)
                })
                .collect::<Vec<_>>()
                .join(",");
            (txid, scripts)
          })
          .collect();

      let inscriptions_per_tx: HashMap<_, _> = block.txdata.iter()
          .filter_map(|tx| {
            let txid = tx.txid();
            match index.get_inscription_by_id(txid.into()) {
              Ok(Some(inscription)) => {
                let inscription_id = InscriptionId::from(txid);
                let content_type = inscription.content_type().map(|s| s.to_string());  // Convert content type to Option<String>

                // Check if content_type starts with "image" or "video"
                let content = if let Some(ref ct) = content_type {
                  if ct.starts_with("image") || ct.starts_with("video") {
                    // If it's an image or video, set content to None
                    None
                  } else {
                    // Otherwise, use the actual content
                    inscription.into_body()
                  }
                } else {
                  // If there's no content type, use the actual content
                  inscription.into_body()
                };

                Some((txid, (inscription_id, content_type, content)))
              }
              _ => None,
            }
          })
          .collect();

      blocks.push(
        BlockJson::new(block, Height(height).0, txids, inputs_per_tx,  outputs_per_tx, output_values_per_tx, inscriptions_per_tx, output_addresses_per_tx, output_scripts_per_tx)
      );
    }

    // This will convert the Vec<BlocksJson> into a JSON string
    let blocks_json = to_string(&blocks).context("Failed to serialize blocks")?;

    Ok(blocks_json)
  }

  async fn transaction(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(txid): Path<Txid>,
  ) -> ServerResult<PageHtml<TransactionHtml>> {
    let inscription = index.get_inscription_by_id(txid.into())?;

    let blockhash = index.get_transaction_blockhash(txid)?;

    Ok(
      TransactionHtml::new(
        index
          .get_transaction(txid)?
          .ok_or_not_found(|| format!("transaction {txid}"))?,
        blockhash,
        inscription.map(|_| txid.into()),
        page_config.chain,
      )
      .page(page_config, index.has_sat_index()?),
    )
  }

  async fn status(Extension(index): Extension<Arc<Index>>) -> (StatusCode, &'static str) {
    if index.is_reorged() {
      (
        StatusCode::OK,
        "reorg detected, please rebuild the database.",
      )
    } else {
      (
        StatusCode::OK,
        StatusCode::OK.canonical_reason().unwrap_or_default(),
      )
    }
  }

  async fn search_by_query(
    Extension(index): Extension<Arc<Index>>,
    Query(search): Query<Search>,
  ) -> ServerResult<Redirect> {
    Self::search(&index, &search.query).await
  }

  async fn search_by_path(
    Extension(index): Extension<Arc<Index>>,
    Path(search): Path<Search>,
  ) -> ServerResult<Redirect> {
    Self::search(&index, &search.query).await
  }

  async fn search(index: &Index, query: &str) -> ServerResult<Redirect> {
    Self::search_inner(index, query)
  }

  fn search_inner(index: &Index, query: &str) -> ServerResult<Redirect> {
    lazy_static! {
      static ref HASH: Regex = Regex::new(r"^[[:xdigit:]]{64}$").unwrap();
      static ref OUTPOINT: Regex = Regex::new(r"^[[:xdigit:]]{64}:\d+$").unwrap();
      static ref INSCRIPTION_ID: Regex = Regex::new(r"^[[:xdigit:]]{64}i\d+$").unwrap();
    }

    let query = query.trim();

    if HASH.is_match(query) {
      if index.block_header(query.parse().unwrap())?.is_some() {
        Ok(Redirect::to(&format!("/block/{query}")))
      } else {
        Ok(Redirect::to(&format!("/tx/{query}")))
      }
    } else if OUTPOINT.is_match(query) {
      Ok(Redirect::to(&format!("/output/{query}")))
    } else if INSCRIPTION_ID.is_match(query) {
      Ok(Redirect::to(&format!("/shibescription/{query}")))
    } else {
      Ok(Redirect::to(&format!("/sat/{query}")))
    }
  }

  async fn favicon(user_agent: Option<TypedHeader<UserAgent>>) -> ServerResult<Response> {
    if user_agent
      .map(|user_agent| {
        user_agent.as_str().contains("Safari/")
          && !user_agent.as_str().contains("Chrome/")
          && !user_agent.as_str().contains("Chromium/")
      })
      .unwrap_or_default()
    {
      Ok(
        Self::static_asset(Path("/favicon.png".to_string()))
          .await
          .into_response(),
      )
    } else {
      Ok(
        (
          [(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'unsafe-inline'"),
          )],
          Self::static_asset(Path("/favicon.svg".to_string())).await?,
        )
          .into_response(),
      )
    }
  }

  async fn feed(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
  ) -> ServerResult<Response> {
    let mut builder = rss::ChannelBuilder::default();

    let chain = page_config.chain;
    let  TITLE = String::from("Shibescriptions");
    match chain {
      Chain::Mainnet => builder.title(TITLE),
      _ => builder.title(format!("Shibescriptions – {chain:?}")),
    };

    builder.generator(Some("ord".to_string()));

    for (number, id) in index.get_feed_inscriptions(300)? {
      builder.item(
        rss::ItemBuilder::default()
          .title(Some(format!("Shibescription {number}")))
          .link(Some(format!("/shibescription/{id}")))
          .guid(Some(rss::Guid {
            value: format!("/shibescription/{id}"),
            permalink: true,
          }))
          .build(),
      );
    }

    Ok(
      (
        [
          (header::CONTENT_TYPE, "application/rss+xml"),
          (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'unsafe-inline'",
          ),
        ],
        builder.build().to_string(),
      )
        .into_response(),
    )
  }

  async fn static_asset(Path(path): Path<String>) -> ServerResult<Response> {
    let content = StaticAssets::get(if let Some(stripped) = path.strip_prefix('/') {
      stripped
    } else {
      &path
    })
    .ok_or_not_found(|| format!("asset {path}"))?;
    let body = body::boxed(body::Full::from(content.data));
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    Ok(
      Response::builder()
        .header(header::CONTENT_TYPE, mime.as_ref())
        .body(body)
        .unwrap(),
    )
  }

  async fn block_count(Extension(index): Extension<Arc<Index>>) -> ServerResult<String> {
    Ok(index.block_count()?.to_string())
  }

  async fn input(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(path): Path<(u64, usize, usize)>,
  ) -> Result<PageHtml<InputHtml>, ServerError> {
    let not_found = || format!("input /{}/{}/{}", path.0, path.1, path.2);

    let block = index
      .get_block_by_height(path.0)?
      .ok_or_not_found(not_found)?;

    let transaction = block
      .txdata
      .into_iter()
      .nth(path.1)
      .ok_or_not_found(not_found)?;

    let input = transaction
      .input
      .into_iter()
      .nth(path.2)
      .ok_or_not_found(not_found)?;

    Ok(InputHtml { path, input }.page(page_config, index.has_sat_index()?))
  }

  async fn faq() -> Redirect {
    Redirect::to("https://docs.ordinals.com/faq/")
  }

  async fn bounties() -> Redirect {
    Redirect::to("https://docs.ordinals.com/bounty/")
  }

  async fn content(
    Extension(index): Extension<Arc<Index>>,
    Extension(config): Extension<Arc<Config>>,
    Path(inscription_id): Path<InscriptionId>,
  ) -> ServerResult<Response> {
    if config.is_hidden(inscription_id) {
      return Ok(PreviewUnknownHtml.into_response());
    }

    let inscription = index
      .get_inscription_by_id(inscription_id)?
      .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

    Ok(
      Self::content_response(inscription)
        .ok_or_not_found(|| format!("inscription {inscription_id} content"))?
        .into_response(),
    )
  }

  fn content_response(inscription: Inscription) -> Option<(HeaderMap, Vec<u8>)> {
    let mut headers = HeaderMap::new();

    headers.insert(
      header::CONTENT_TYPE,
      inscription
        .content_type()
        .unwrap_or("application/octet-stream")
        .parse()
        .unwrap(),
    );
    headers.insert(
      header::CONTENT_SECURITY_POLICY,
      HeaderValue::from_static("default-src 'unsafe-eval' 'unsafe-inline' data:"),
    );
    headers.insert(
      header::CACHE_CONTROL,
      HeaderValue::from_static("max-age=31536000, immutable"),
    );

    Some((headers, inscription.into_body()?))
  }

  async fn preview(
    Extension(index): Extension<Arc<Index>>,
    Extension(config): Extension<Arc<Config>>,
    Path(inscription_id): Path<InscriptionId>,
  ) -> ServerResult<Response> {
    if config.is_hidden(inscription_id) {
      return Ok(PreviewUnknownHtml.into_response());
    }

    let inscription = index
      .get_inscription_by_id(inscription_id)?
      .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

    return match inscription.media() {
      Media::Audio => Ok(PreviewAudioHtml { inscription_id }.into_response()),
      Media::Iframe => Ok(
        Self::content_response(inscription)
          .ok_or_not_found(|| format!("inscription {inscription_id} content"))?
          .into_response(),
      ),
      Media::Image => Ok(
        (
          [(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self' 'unsafe-inline'",
          )],
          PreviewImageHtml { inscription_id },
        )
          .into_response(),
      ),
      Media::Pdf => Ok(
        (
          [(
            header::CONTENT_SECURITY_POLICY,
            "script-src-elem 'self' https://cdn.jsdelivr.net",
          )],
          PreviewPdfHtml { inscription_id },
        )
          .into_response(),
      ),
      Media::Text => {
        let content = inscription
          .body()
          .ok_or_not_found(|| format!("inscription {inscription_id} content"))?;
        Ok(
          PreviewTextHtml {
            text: str::from_utf8(content)
              .map_err(|err| anyhow!("Failed to decode {inscription_id} text: {err}"))?,
          }
          .into_response(),
        )
      }
      Media::Unknown => Ok(PreviewUnknownHtml.into_response()),
      Media::Video => Ok(PreviewVideoHtml { inscription_id }.into_response()),
    };
  }

  async fn inscription(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(inscription_id): Path<InscriptionId>,
  ) -> ServerResult<PageHtml<InscriptionHtml>> {
    let entry = index
      .get_inscription_entry(inscription_id)?
      .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

    let inscription = index
      .get_inscription_by_id(inscription_id)?
      .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

    let satpoint = index
      .get_inscription_satpoint_by_id(inscription_id)?
      .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

    let output = index
      .get_transaction(satpoint.outpoint.txid)?
      .ok_or_not_found(|| format!("inscription {inscription_id} current transaction"))?
      .output
      .into_iter()
      .nth(satpoint.outpoint.vout.try_into().unwrap())
      .ok_or_not_found(|| format!("inscription {inscription_id} current transaction output"))?;

    let previous = if let Some(previous) = entry.number.checked_sub(1) {
      Some(
        index
          .get_inscription_id_by_inscription_number(previous)?
          .ok_or_not_found(|| format!("inscription {previous}"))?,
      )
    } else {
      None
    };

    let next = index.get_inscription_id_by_inscription_number(entry.number + 1)?;

    Ok(
      InscriptionHtml {
        chain: page_config.chain,
        genesis_fee: entry.fee,
        genesis_height: entry.height,
        inscription,
        inscription_id,
        next,
        number: entry.number,
        output,
        previous,
        sat: entry.sat,
        satpoint,
        timestamp: timestamp(entry.timestamp),
      }
      .page(page_config, index.has_sat_index()?),
    )
  }

  async fn inscriptions(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
  ) -> ServerResult<PageHtml<InscriptionsHtml>> {
    Self::inscriptions_inner(page_config, index, None).await
  }

  async fn inscriptions_by_outputs(
    Extension(server_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Query(query): Query<InscriptionsByOutputsQuery>,
  ) -> ServerResult<Response> {
    let mut all_inscription_jsons = Vec::new();

    // Split the outputs string into individual outputs
    let outputs = query.outputs.split(',');

    for output in outputs {
      // Split the output into tx_id and vout
      let parts: Vec<&str> = output.split(':').collect();
      if parts.len() != 2 {
        return Err(
          ServerError::BadRequest("wrong output format".to_string())
        );
      }

      let tx_id = Txid::from_str(parts[0]).map_err(
        |_| ServerError::BadRequest("wrong tx id format".to_string()))?;
      let vout = parts[1].parse::<u32>().map_err(
        |_| ServerError::BadRequest("wrong vout format".to_string()))?;

      // Create OutPoint
      let outpoint = OutPoint::new(tx_id, vout);

      // Query the index for inscriptions on this OutPoint
      let inscriptions = index
          .get_inscriptions_on_output(outpoint)?;

      for inscription_id in inscriptions {
        let inscription = index
            .get_inscription_by_id(inscription_id)?
            .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

        let entry = index
            .get_inscription_entry(inscription_id)?
            .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

        let inscription_json = InscriptionJson {
          content_length: inscription.content_length(),
          content_type: inscription.content_type().map(|s| s.to_string()),
          genesis_height: entry.height,
          inscription_id: inscription_id,
          inscription_number: entry.number,
          timestamp: entry.timestamp,
          tx_id: tx_id.to_string(),
          vout
        };

        all_inscription_jsons.push(inscription_json);
      }
    }

    // Build your response
    Ok(Json(all_inscription_jsons).into_response())
  }

  async fn inscriptions_from(
    Extension(page_config): Extension<Arc<PageConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(from): Path<u64>,
  ) -> ServerResult<PageHtml<InscriptionsHtml>> {
    Self::inscriptions_inner(page_config, index, Some(from)).await
  }

  async fn inscriptions_inner(
    page_config: Arc<PageConfig>,
    index: Arc<Index>,
    from: Option<u64>,
  ) -> ServerResult<PageHtml<InscriptionsHtml>> {
    let (inscriptions, prev, next) = index.get_latest_inscriptions_with_prev_and_next(100, from)?;
    Ok(
      InscriptionsHtml {
        inscriptions,
        next,
        prev,
      }
      .page(page_config, index.has_sat_index()?),
    )
  }

  async fn redirect_http_to_https(
    Extension(mut destination): Extension<String>,
    uri: Uri,
  ) -> Redirect {
    if let Some(path_and_query) = uri.path_and_query() {
      destination.push_str(path_and_query.as_str());
    }

    Redirect::to(&destination)
  }
}
