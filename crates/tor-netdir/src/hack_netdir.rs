


use tor_linkspec::HasAddrs;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_netdoc::doc::netstatus::RelayFlags;
use std::sync::{Arc, Mutex};
use rand::seq::SliceRandom;
use crate::{NetDir, WeightRole, Relay};
use anyhow::{Result, Context};


macro_rules! dbgd {
    ($disable:expr, $($arg:tt)* ) => (
        if !$disable {
            tracing::debug!($($arg)*) // comment out this line to disable log
        }
    );
}


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
        let mut data = self.data();
        let disable_log = data.disable_log;
        let (ids, planb) = data.by_role(role);
        pick_relay(disable_log, ids, planb, netdir, rng, role, usable)
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
        let mut data = self.data();
        let disable_log = data.disable_log;
        let (ids, planb) = data.by_role(role);
        pick_n_relays(disable_log, ids, planb, netdir, rng, n, role, usable)
    }
}


/// TODO: add doc
#[derive(Default)]
pub struct HackData {
    
    /// TODO: add doc
    disable_log: bool,

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

    /// TODO: add doc
    planb_guards: Option<Vec<Ed25519Identity>>,

    /// TODO: add doc
    planb_middles: Option<Vec<Ed25519Identity>>,

    /// TODO: add doc
    planb_exits: Option<Vec<Ed25519Identity>>,

    /// TODO: add doc
    planb_begin_dirs: Option<Vec<Ed25519Identity>>,

    /// TODO: add doc
    planb_unweighteds: Option<Vec<Ed25519Identity>>,
}

impl HackData {
    /// TODO: add doc
    pub fn by_role(&mut self, role: WeightRole) -> (&Option<Arc<[Ed25519Identity]>>, &mut Option<Vec<Ed25519Identity>>) {
        match role {
            WeightRole::Guard => (&self.guards, &mut self.planb_guards),
            WeightRole::Middle => (&self.middles, &mut self.planb_middles),
            WeightRole::Exit => (&self.exits, &mut self.planb_exits),
            WeightRole::BeginDir => (&self.begin_dirs, &mut self.planb_begin_dirs),
            WeightRole::Unweighted => (&self.unweighteds, &mut self.planb_unweighteds),
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

    /// TODO: add doc
    pub fn planb_guards_mut(&mut self) -> &mut Option<Vec<Ed25519Identity>> {
        &mut self.planb_guards
    }
}

pub(crate) fn pick_relay<'a, R, P>(
    disable_log: bool,
    ids: &Option<Arc<[Ed25519Identity]>>,
    planb: &mut Option<Vec<Ed25519Identity>>,
    netdir: &'a NetDir,
    rng: &mut R,
    role: WeightRole,
    usable: &P,
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
                    dbgd!(disable_log, "pick_relay: role [{:?}], [{}] -> {:?}", role, id, relay.addrs());
                }
                return relay;
            }
        },
        None => {},
    }

    if let Some(planb) = planb { 
        return pick_planb(disable_log, planb, netdir, rng, role, usable)
    }

    dbgd!(disable_log, "pick_relay: role [{:?}] None", role);
    None

}

/// TODO: add doc
pub(crate) fn pick_n_relays<'a, R, P>(
    disable_log: bool,
    ids: &Option<Arc<[Ed25519Identity]>>,
    planb: &mut Option<Vec<Ed25519Identity>>,
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
    match ids {
        Some(ids) => {
            let mut relays = Vec::new();
            let iter  = ids.choose_multiple(rng, n);
            for id in iter {
                if let Some(relay) = netdir.by_id(id) {
                    dbgd!(disable_log, "pick_relay_n: role [{:?}], [{}] -> {:?}", role, id, relay.addrs());
                    relays.push(relay);
                }
            }
            if relays.len() > 0 {
                dbgd!(disable_log, "pick_n_relays: role [{:?}], num [{}]", role, relays.len());
                return Some(relays);
            }
        },
        None => {},
    }

    if let Some(planb) = planb { 
        return Some(pick_n_planb(disable_log, planb, netdir, rng, n, role, usable))
    }

    
    dbgd!(disable_log, "pick_n_relays: role [{:?}] None", role);
    None

}

pub(crate) fn pick_planb<'a, R, P>(
    disable_log: bool,
    planb: &mut Vec<Ed25519Identity>,
    netdir: &'a NetDir,
    rng: &mut R,
    role: WeightRole,
    _usable: &P,
) -> Option<Relay<'a>>
where
    R: rand::Rng,
    P: FnMut(&Relay<'a>) -> bool,
{
    let mut choosed_relay = None;
    let r = planb.choose(rng);
    if let Some(id) = r {
        choosed_relay = netdir.by_id(id);
        if let Some(planb) = &choosed_relay {
            dbgd!(disable_log, "pick_relay: planb, role [{:?}], [{}] -> {:?}", role, id, planb.addrs());
            return choosed_relay;
        } 
    }

    let flags = flags_by_role(role);

    planb.clear();
    let mut iter = netdir.relays().filter(|v|v.rs().flags().contains(flags));
    for _ in 0..planb.capacity() {
        match iter.next() {
            Some(relay) => { 
                dbgd!(disable_log, "pick_relay: init planb, role [{:?}], [{}] -> {:?}", role, relay.id(), relay.addrs());
                planb.push(relay.id().clone());
                if choosed_relay.is_none() { 
                    choosed_relay = Some(relay);
                }
            },
            None => {
                break;
            },
        }
    }

    if choosed_relay.is_none() {
        dbgd!(disable_log, "pick_relay: planb, role None");
    }
    
    return choosed_relay;

}


pub(crate) fn pick_n_planb<'a, R, P>(
    disable_log: bool,
    planb: &mut Vec<Ed25519Identity>,
    netdir: &'a NetDir,
    rng: &mut R,
    n: usize,
    role: WeightRole,
    _usable: &P,
) -> Vec<Relay<'a>>
where
    R: rand::Rng,
    P: FnMut(&Relay<'a>) -> bool,
{
    let mut relays = Vec::new();

    {
        let iter  = planb.choose_multiple(rng, n);
        for id in iter {
            if let Some(relay) = netdir.by_id(id) {
                dbgd!(disable_log, "pick_relay_n: planb, role [{:?}], [{}] -> {:?}", role, id, relay.addrs());
                relays.push(relay);
            }
        }
    }

    if relays.len() == 0 { 
        let flags = flags_by_role(role);

        planb.clear();
        let mut iter = netdir.relays().filter(|v|v.rs().flags().contains(flags));
        for _ in 0..planb.capacity() {
            match iter.next() {
                Some(relay) => { 
                    dbgd!(disable_log, "pick_relay_n: init planb, role [{:?}], [{}] -> {:?}", role, relay.id(), relay.addrs());
                    planb.push(relay.id().clone());
                    if relays.len() < n { 
                        relays.push(relay);
                    }
                },
                None => {
                    break;
                },
            }
        }
    }

    dbgd!(disable_log, "pick_n_relays: planb, role [{:?}], num [{}]", role, relays.len());
    return relays;
}

fn flags_by_role(role: WeightRole) -> RelayFlags {
    match role {
        WeightRole::Guard => RelayFlags::GUARD,
        WeightRole::Middle => RelayFlags::GUARD,
        WeightRole::Exit => RelayFlags::EXIT,
        WeightRole::BeginDir => RelayFlags::HSDIR,
        WeightRole::Unweighted => RelayFlags::GUARD,
    }
}