


use tor_linkspec::HasAddrs;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use std::sync::{Arc, Mutex};
use rand::seq::SliceRandom;
use crate::{NetDir, WeightRole, Relay};
use anyhow::{Result, Context};

/// TODO: add doc
pub fn make_ed25519_id(s: &str) -> Result<Ed25519Identity> {
    let ed = base64::decode_config(s, base64::STANDARD_NO_PAD)
    .with_context(|| "Bad hex of Ed25519Identity")?;

    let ed = Ed25519Identity::from_bytes(&ed)
    .with_context(|| "Wrong length of Ed25519Identity")?;

    Ok(ed)
}

/// TODO: add doc
pub fn make_ids<T>(ids: Vec<T>) -> Result<Arc<[Ed25519Identity]>>
where
    T: AsRef<str>
{
    let mut ed_ids = Vec::with_capacity(ids.len());
    for s in ids {
        let s = s.as_ref();
        let ed = make_ed25519_id(s)?;
        ed_ids.push(ed);
    }

    Ok(ed_ids.into())
}

/// TODO: add doc
pub fn hack() -> &'static HackNetDir {
    lazy_static::lazy_static! {
        static ref INST: HackNetDir = Default::default();
    }
    &*INST
}

/// TODO: add doc
#[derive(Default)]
pub struct HackNetDir {
    data: Arc<Mutex<HackData>>,
}

impl HackNetDir {
    /// TODO: add doc
    pub fn data<'a>(&'a self) -> std::sync::MutexGuard<'a, HackData> {
        self.data.lock().expect("HackNetDir poisoned lock")
    }

    /// TODO: add doc
    pub(crate) fn pick_relay<'a, R, P>(
        &self,
        netdir: &'a NetDir,
        rng: &mut R,
        role: WeightRole,
        usable: &P,
    ) -> Option<Relay<'a>>
    where
        R: rand::Rng,
        P: FnMut(&Relay<'a>) -> bool,
    {
        let data = self.data();
        let ids = data.by_role(role);
        pick_relay(ids, netdir, rng, role, usable)
    }

    /// TODO: add doc
    pub(crate) fn pick_n_relays<'a, R, P>(
        &self,
        netdir: &'a NetDir,
        rng: &mut R,
        n: usize,
        role: WeightRole,
        usable: &P,
    ) -> Option<Vec<Relay<'a>>> 
    where
        R: rand::Rng,
        P: FnMut(&Relay<'a>) -> bool,
    {
        let data = self.data();
        let ids = data.by_role(role);
        pick_n_relays(ids, netdir, rng, n, role, usable)
    }
}


/// TODO: add doc
#[derive(Default)]
pub struct HackData {
    /// TODO: add doc
    guards: Option<Arc<[Ed25519Identity]>>,

    /// TODO: add doc
    middles:  Option<Arc<[Ed25519Identity]>>,

    /// TODO: add doc
    exits:  Option<Arc<[Ed25519Identity]>>,


    /// TODO: add doc
    begin_dirs:  Option<Arc<[Ed25519Identity]>>,

    /// TODO: add doc
    unweighteds:  Option<Arc<[Ed25519Identity]>>,
}

impl HackData {
    /// TODO: add doc
    pub fn by_role(&self, role: WeightRole) -> &Option<Arc<[Ed25519Identity]>> {
        match role {
            WeightRole::Guard => &self.guards,
            WeightRole::Middle => &self.middles,
            WeightRole::Exit => &self.exits,
            WeightRole::BeginDir => &self.begin_dirs,
            WeightRole::Unweighted => &self.unweighteds,
        }
    }

    /// TODO: add doc
    pub fn guards_mut(&mut self) -> &mut Option<Arc<[Ed25519Identity]>> {
        &mut self.guards
    }

    /// TODO: add doc
    pub fn middles_mut(&mut self) -> &mut Option<Arc<[Ed25519Identity]>> {
        &mut self.middles
    }

    /// TODO: add doc
    pub fn exits_mut(&mut self) -> &mut Option<Arc<[Ed25519Identity]>> {
        &mut self.exits
    }

    /// TODO: add doc
    pub fn begin_dirs_mut(&mut self) -> &mut Option<Arc<[Ed25519Identity]>> {
        &mut self.begin_dirs
    }

    /// TODO: add doc
    pub fn unweighteds_mut(&mut self) -> &mut Option<Arc<[Ed25519Identity]>> {
        &mut self.unweighteds
    }
}

pub(crate) fn pick_relay<'a, R, P>(
    ids: &Option<Arc<[Ed25519Identity]>>,
    netdir: &'a NetDir,
    rng: &mut R,
    role: WeightRole,
    _usable: &P,
) -> Option<Relay<'a>>
where
    R: rand::Rng,
    P: FnMut(&Relay<'a>) -> bool,
{
    match ids {
        Some(ids) => {
            let r = ids.choose(rng);
            if let Some(id) = r {
                let relay = netdir.by_id(id);
                if let Some(relay) = &relay {
                    println!("pick_relay: role [{:?}], [{}] -> {:?}", role, id, relay.addrs());
                }
                return relay;
            }
        },
        None => {},
    }
    println!("pick_relay: role [{:?}] None", role);
    None

}

/// TODO: add doc
pub(crate) fn pick_n_relays<'a, R, P>(
    ids: &Option<Arc<[Ed25519Identity]>>,
    netdir: &'a NetDir,
    rng: &mut R,
    n: usize,
    role: WeightRole,
    _usable: &P,
) -> Option<Vec<Relay<'a>>> 
where
    R: rand::Rng,
    P: FnMut(&Relay<'a>) -> bool,
{
    match ids {
        Some(ids) => {
            let mut relays = Vec::new();
            let iter  = ids.choose_multiple(rng, n);
            for id in iter {
                if let Some(relay) = netdir.by_id(id) {
                    println!("pick_relay_n: role [{:?}], [{}] -> {:?}", role, id, relay.addrs());
                    relays.push(relay);
                }
            }
            if relays.len() > 0 {
                println!("pick_n_relays: role [{:?}], num [{}]", role, relays.len());
                return Some(relays);
            }
        },
        None => {},
    }
    println!("pick_n_relays: role [{:?}] None", role);
    None

}





