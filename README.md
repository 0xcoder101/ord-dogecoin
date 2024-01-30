# Shibes

ℹ️ This is a fork/based on [apezord/ord-dogecoin](https://github.com/apezord/ord-dogecoin)

## Key differences

‼️ DISCLAIMER: OUR CODE MAY STILL HAVE BUGS️

We included the real wonky block rewards from block 0 until block 144,999. We invite you to critically review our code in `src/epoch.rs`. We are convinced that doginals should use actual block rewards instead of a simplified version.

## Required env vars

On the root level of this repo you'll find a `subsidies.json` and `starting_sats.json` file. When starting ord you will need to set the location of these files to env variables. Example: 

If your `wonky-ord-dogecoin` dir is `/home/dogeuser/wonky-ord-dogecoin` then set the vars: `SUBSIDIES_PATH=/home/dogeuser/wonky-ord-dogecoin/subsidies.json` and `STARTING_SATS_PATH=/home/dogeuser/wonky-ord-dogecoin/starting_sats.json`.

## README.md from apezord/ord-dogecoin

You should periodically create checkpoints of the redb database that you can restore from. Dogecoin has more reorgs than bitcoin due to its 1 minute block times and casey/ord does not handle reorgs. There is an open issue [here](https://github.com/casey/ord/issues/148).

You can donate to apezord here:

BTC - `1GKa8TBGK9UkY5PrigiP5eixDeYAsmdBC4`

DOGE - `DNmrp12LfsVwy2Q2B5bvpQ1HU7zCAczYob`

`ord`
=====

`ord` is an index, block explorer, and command-line wallet. It is experimental
software with no warranty. See [LICENSE](LICENSE) for more details.

Ordinal theory imbues satoshis with numismatic value, allowing them to
be collected and traded as curios.

Ordinal numbers are serial numbers for satoshis, assigned in the order in which
they are mined, and preserved across transactions.

See [the docs](https://docs.ordinals.com) for documentation and guides.

See [the BIP](bip.mediawiki) for a technical description of the assignment and
transfer algorithm.

See [the project board](https://github.com/users/casey/projects/3/) for
currently prioritized issues.

See [milestones](https://github.com/casey/ord/milestones) to get a sense of
where the project is and where it's going.

Join [the Discord server](https://discord.gg/87cjuz4FYg) to chat with fellow
ordinal degenerates.

Tune in to the [Twitch stream](https://www.twitch.tv/ordinalsofficial) to watch us work on this project!

Wallet
------

`ord` relies on Dogecoin Core for private key management and transaction signing.
This has a number of implications that you must understand in order to use
`ord` wallet commands safely:

- Dogecoin Core is not aware of inscriptions and does not perform sat
  control. Using `dogecoin-cli` commands and RPC calls with `ord` wallets may
  lead to loss of inscriptions.

- `ord wallet` commands automatically load the `ord` wallet given by the
  `--wallet` option, which defaults to 'ord'. Keep in mind that after running
  an `ord wallet` command, an `ord` wallet may be loaded.

- Because `ord` has access to your Dogecoin Core wallets, `ord` should not be
  used with wallets that contain a material amount of funds. Keep ordinal and
  cardinal wallets segregated.

### Pre-alpha wallet migration

Alpha `ord` wallets are not compatible with wallets created by previous
versions of `ord`. To migrate, use `ord wallet send` from the old wallet to
send sats and inscriptions to addresses generated by the new wallet with `ord
wallet receive`.

Installation
------------

`ord` is written in Rust and can be built from
[source](https://github.com/casey/ord). Pre-built binaries are available on the
[releases page](https://github.com/casey/ord/releases).

You can install the latest pre-built binary from the command line with:

```sh
curl --proto '=https' --tlsv1.2 -fsLS https://ordinals.com/install.sh | bash -s
```

Once `ord` is installed, you should be able to run `ord --version` on the
command line.

Building
--------

On Debian and Ubuntu, `ord` requires `libssl-dev` when building from source:

```
sudo apt-get install libssl-dev
```

You'll also need Rust:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

To build `ord` from source:

```
git clone https://github.com/casey/ord.git
cd ord
cargo build --release
```

The default location for the `ord` binary once built is `./target/release/ord`.

`ord` requires `rustc` version 1.67.0 or later. Run `rustc --version` to ensure you have this version. Run `rustup update` to get the latest stable release.


Syncing
-------

`ord` requires a synced `dogecoind` node with `-txindex` to build the index of
satoshi locations. `ord` communicates with `dogecoind` via RPC.

If `dogecoind` is run locally by the same user, without additional
configuration, `ord` should find it automatically by reading the `.cookie` file
from `dogecoind`'s datadir, and connecting using the default RPC port.

If `dogecoind` is not on mainnet, is not run by the same user, has a non-default
datadir, or a non-default port, you'll need to pass additional flags to `ord`.
See `ord --help` for details.

Logging
--------

`ord` uses [env_logger](https://docs.rs/env_logger/latest/env_logger/). Set the
`RUST_LOG` environment variable in order to turn on logging. For example, run
the server and show `info`-level log messages and above:

```
$ RUST_LOG=info cargo run server
```

New Releases
------------

Release commit messages use the following template:

```
Release x.y.z

- Bump version: x.y.z → x.y.z
- Update changelog
- Update dependencies
- Update database schema version
```
