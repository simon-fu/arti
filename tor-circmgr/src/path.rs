// TODO: I'm not sure this belongs in circmgr, but this is the best place
// I can think of for now.

pub mod dirpath;
pub mod exitpath;

use tor_chanmgr::ChanMgr;
use tor_netdir::{NetDir, Relay};
use tor_proto::channel::Channel;
use tor_proto::circuit::ClientCirc;

use futures::task::{Spawn, SpawnExt};
use rand::{CryptoRng, Rng};

use crate::{Error, Result};

pub enum TorPath<'a> {
    // TODO: wrong type; this needs something that can be a chantarget only.
    OneHop(Relay<'a>),
    Path(Vec<Relay<'a>>),
}

pub trait PathBuilder {
    fn pick_path<'a, R: Rng>(&self, rng: &mut R, netdir: &'a NetDir) -> Result<TorPath<'a>>;
}

impl<'a> TorPath<'a> {
    async fn get_channel<TR>(&self, chanmgr: &ChanMgr<TR>) -> Result<Channel>
    where
        TR: tor_chanmgr::transport::Transport,
    {
        use TorPath::*;
        match self {
            OneHop(r) => Ok(chanmgr.get_or_launch(r).await?),

            Path(p) if p.len() == 0 => Err(Error::NoRelays("Path with no entries!".into())),
            Path(p) => Ok(chanmgr.get_or_launch(&p[0]).await?),
        }
    }

    pub async fn build_circuit<TR, R, S>(
        &self,
        rng: &mut R,
        chanmgr: &ChanMgr<TR>,
        spawn: &S,
    ) -> Result<ClientCirc>
    where
        TR: tor_chanmgr::transport::Transport,
        R: Rng + CryptoRng,
        S: Spawn,
    {
        use TorPath::*;
        let chan = self.get_channel(chanmgr).await?;
        let (pcirc, reactor) = chan.new_circ(rng).await?;

        spawn.spawn(async {
            let _ = reactor.run().await;
        })?;

        match self {
            OneHop(_) => {
                let circ = pcirc.create_firsthop_fast(rng).await?;
                Ok(circ)
            }
            Path(p) => {
                let mut circ = pcirc.create_firsthop_ntor(rng, &p[0]).await?;
                for relay in p[1..].iter() {
                    circ.extend_ntor(rng, relay).await?;
                }
                Ok(circ)
            }
        }
    }
}