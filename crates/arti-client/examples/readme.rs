// @@ begin test lint list maintained by maint/add_warning @@
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::dbg_macro)]
#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used)]
//! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

use tokio_crate as tokio;
use arti_client::box_socks;


// curl -vv  -x socks5h://localhost:9150 http://wtfismyip.com/json
// bootstrap::download 会下载结点信息？
// 

use std::{str::FromStr, sync::Arc, net::SocketAddr, time::Duration};

use anyhow::{Result, Context};
use arti_client::{config::TorClientConfigBuilder, TorClient, StreamPrefs};
use futures::{AsyncWriteExt, AsyncReadExt};
use strum::EnumString;
use tokio::net::TcpStream;
use tor_netdir::{NetDir, hack_prefer_guards};




/*

bootstrap process
=================
- TorClientBuilder::create_bootstrapped()
- TorClientBuilder::create_unbootstrapped()
- TorClient<R>::bootstrap()
- TorClient<R>::bootstrap_inner()
    self.dirmgr: Arc<dyn tor_dirmgr::DirProvider>
    self.dirmgr.bootstrap() 
- DirMgr::bootstrap()
- DirMgr::download_forever()
- bootstrap::download(Weak<DirMgr<R>>)
- bootstrap::download_attempt(&Arc<DirMgr<R>>,)
- bootstrap::fetch_multiple(Arc<DirMgr<R>>)
    let circmgr = dirmgr.circmgr()?;
    let netdir = dirmgr.netdir(tor_netdir::Timeliness::Timely).ok();
- bootstrap::fetch_single(Arc<CircMgr<R>>)
- tor_dirclient::get_resource()
- Arc<CircMgr<R>>::get_or_launch_dir()


connect process
===============
- TorClient::connect_with_prefs()
- TorClient::get_or_launch_exit_circ()
- Arc<CircMgr<R>>::get_or_launch_exit()

*/

macro_rules! dbgd {
    ($($arg:tt)* ) => (
        tracing::info!($($arg)*) // comment out this line to disable log
    );
}

#[derive(Debug, PartialEq, EnumString)]
enum Cmd {
    Simple,
    Manual,
}

#[tokio::main]
async fn main() -> Result<()> {
    // tracing_subscriber::fmt::init();
    tracing_subscriber::fmt()
    .with_max_level(tracing::Level::INFO)
    .init();
    
    let cmd = Cmd::from_str("Simple")?;
    // let cmd = Cmd::from_str("Manual")?;
    match cmd {
        Cmd::Simple => simple_proxy().await,
        Cmd::Manual => manual_download_dir().await,
    }
}

async fn manual_download_dir() -> Result<()> { 
    
    let netdir = pull_netdir().await.with_context(||"pull_netdir fail")?;
    dbgd!("pull_netdir done");

    // let guard_ids = vec![
    //     fallback::make_ed25519_id("FK7SwWET47+2UjP1b03TqGbGo4uJnjhomp4CnH7Ntv8"),
    //     fallback::make_ed25519_id("ciWaq9i2Xj4qVPcx9pLfRP9b6J9T1ZwEnC83blSpUcc"),
    //     fallback::make_ed25519_id("5nHccFo2jQ2b7PDxEdY5vNcPn++nHZJRW32SbLJMqnQ"),
    //     fallback::make_ed25519_id("w2j7gp0fAqDOsHt8ruIJM6wdFZz3/UEMiH4MGw3behE"),
    //     fallback::make_ed25519_id("TipUY3Pag9HRNflLHLlXaePDfaCMUVLOMHabRN3nU6g"),
    // ];
    // netdir.filter_guards(guard_ids);
    // // for id_str in &guard_ids {
    // //     let id: Ed25519Identity = id.parse()?;
    // //     let r = netdir.by_id(&id);
    // //     dbgd!("search guard [{}] -> [{}]", id, r.is_some());
    // // }
    


    let total_relays = netdir.relays().count();
    let mut relay_works = Vec::new();
    for (index, relay) in netdir.relays().enumerate() {
        let index = index + 1;
        // let r = netdir.by_id(relay.id());

        // dbgd!("realy => {:?}, {:?}\n", relay.rs(), relay.md());
        if !relay.rs().is_flagged_guard() {
            dbgd!("relay[{}/{}]: [{}] ignore NOT guard, {:?}", index, total_relays, relay.id(), relay.rs().flags());
            continue;
        }

        let mut connect_able = false;
        for addr in relay.rs().addrs() {
            dbgd!("relay[{}/{}]: [{}] -> [{}] connecting", index, total_relays, relay.id(), addr);
            const TIMEOUT: Duration = Duration::from_secs(5);
            let r = connect_with_timeout(addr, TIMEOUT).await;
            match r {
                Ok(_s) => {
                    dbgd!("relay[{}/{}]: [{}] -> [{}] connect ok", index, total_relays, relay.id(), addr);
                    connect_able = true;
                },
                Err(e) => {
                    dbgd!("relay[{}/{}]: [{}] -> [{}] connect fail [{:?}]", index, total_relays, relay.id(), addr, e);
                },
            }
        }
        if connect_able {
            relay_works.push(relay);
        }
        dbgd!("on-going: connect-able relays {}\n", relay_works.len());
    }
    dbgd!("connect attempts done, connect-able relays {}", relay_works.len());

    Ok(())
}

async fn connect_with_timeout(addr: &SocketAddr, timeout: Duration) -> Result<()> {
    let _s = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
    // .with_context(||"timeout")??;
    Ok(())
}

async fn pull_netdir() -> Result<Arc<NetDir>> {
    let config = {
        let builder = TorClientConfigBuilder::from_directories(STATE_DIR, CACHE_DIR);
        builder.build()?
    };
    
    
    let socks_args = Some(box_socks::SocksArgs {
        server: "127.0.0.1:7890".to_owned(),
        username: None,
        password: None,
        max_targets: None,
    });

    let runtime = box_socks::create_runtime(socks_args)?;

        
    let builder = TorClient::with_runtime(runtime)
    .config(config);
    let client = builder.create_bootstrapped().await?;

    let netdir = client.dirmgr().timely_netdir()?;

    Ok(netdir)
}

const STATE_DIR: &str = "/tmp/arti-client/state";
const CACHE_DIR: &str = "/tmp/arti-client/cache";

async fn simple_proxy() -> Result<()> {
    // {
    //     let r =  arti_client::config::default_config_file()?;
    //     eprintln!("default_config_file: [{:?}]", r);
    // }

    // let guard_ids = vec![
    //     fallback::make_ed25519_id("FK7SwWET47+2UjP1b03TqGbGo4uJnjhomp4CnH7Ntv8"),
    //     fallback::make_ed25519_id("ciWaq9i2Xj4qVPcx9pLfRP9b6J9T1ZwEnC83blSpUcc"),
    //     fallback::make_ed25519_id("5nHccFo2jQ2b7PDxEdY5vNcPn++nHZJRW32SbLJMqnQ"),
    //     fallback::make_ed25519_id("w2j7gp0fAqDOsHt8ruIJM6wdFZz3/UEMiH4MGw3behE"),
    //     fallback::make_ed25519_id("TipUY3Pag9HRNflLHLlXaePDfaCMUVLOMHabRN3nU6g"),
    // ];
    // hack_prefer_guards::set_prefer_guards(guard_ids);

    let guard_ids = vec![
        "FK7SwWET47+2UjP1b03TqGbGo4uJnjhomp4CnH7Ntv8",
        "ciWaq9i2Xj4qVPcx9pLfRP9b6J9T1ZwEnC83blSpUcc",
        "5nHccFo2jQ2b7PDxEdY5vNcPn++nHZJRW32SbLJMqnQ",
        "w2j7gp0fAqDOsHt8ruIJM6wdFZz3/UEMiH4MGw3behE",
        "TipUY3Pag9HRNflLHLlXaePDfaCMUVLOMHabRN3nU6g",
    ];
    hack_prefer_guards::set_prefer_guards_str(guard_ids)?;

    let mut builder = TorClientConfigBuilder::from_directories(STATE_DIR, CACHE_DIR);
    
    // builder.tor_network().set_fallback_caches(vec![fallback::make(
    //     "B9208EAD1E688E9EE43A05159ACD4638EB4DFD8A",
    //     "LTbH9g0Ol5jVSUy6GVgRyOSeYVTctU/xyAEwYqh385o",
    //     &[
    //         "140.78.100.16:8443"
    //     ],
    // )]);

    builder.tor_network().set_fallback_caches(vec![
        fallback::make(
            "160B5805A781D93390D4A2AE05EA9C5B438E7967",
            "eFCu/xAod8SMUmLvtfsibUKYf5HgTT7kylb3lpKp2tA",
            &[
                "162.200.149.221:9001"
            ],
        ),

        // Peer ed25519 id not as expected
        fallback::make(
            "2479ADEEA2FB4B99CB887C962ABBC648B44F7B6F",
            "Rq3RHdRQQdjbpmF4VBgMvi6a3lOHNnXM0K6qwlxHj5Q",
            &[
                "77.162.68.75:9001"
            ],
        ),

        // Doesn't seem to be a tor relay
        fallback::make(
            "EF18418EE9B5E5CCD0BB7546869AC10BA625BAC8",
            "YU12MoJWSmk+4N90lEY1vG9kXLffr80/1Lroeo6Xsvo",
            &[
                "185.191.127.231:443"
            ],
        ),
    ]);


    let config = builder.build()?;
    // eprintln!("config: {:?}", config);


    eprintln!("connecting to Tor...");

    let socks_args = Some(box_socks::SocksArgs {
        server: "127.0.0.1:7890".to_owned(),
        username: None,
        password: None,
        max_targets: Some(0),
    });
    // let socks_args = None;

    let runtime = box_socks::create_runtime(socks_args)?;
    


    let tor_client = TorClient::with_runtime(runtime)
    .config(config)
    .create_bootstrapped()
    .await?;
    eprintln!("====== connected Tor with runtime");

    // let tor_client = TorClient::with_runtime(runtime)
    // .config(config)
    // .create_unbootstrapped()?;

    // let guard_ids = vec![
    //     fallback::make_ed25519_id("FK7SwWET47+2UjP1b03TqGbGo4uJnjhomp4CnH7Ntv8"),
    //     fallback::make_ed25519_id("ciWaq9i2Xj4qVPcx9pLfRP9b6J9T1ZwEnC83blSpUcc"),
    //     fallback::make_ed25519_id("5nHccFo2jQ2b7PDxEdY5vNcPn++nHZJRW32SbLJMqnQ"),
    //     fallback::make_ed25519_id("w2j7gp0fAqDOsHt8ruIJM6wdFZz3/UEMiH4MGw3behE"),
    //     fallback::make_ed25519_id("TipUY3Pag9HRNflLHLlXaePDfaCMUVLOMHabRN3nU6g"),
    // ];
    // let netdir = tor_client.dirmgr().timely_netdir()?;
    // netdir.filter_guards(guard_ids);

    // tor_client.bootstrap().await?;
    // eprintln!("====== bootstrap done");

    eprintln!("connecting to example.com...");

    // Initiate a connection over Tor to example.com, port 80.
    // let mut stream = tor_client.connect(("example.com", 80)).await?;

    let mut stream = tor_client.connect_with_prefs(("example.com", 80), StreamPrefs::new().ipv4_only()).await?;


    eprintln!("sending request...");

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;

    // IMPORTANT: Make sure the request was written.
    // Arti buffers data, so flushing the buffer is usually required.
    stream.flush().await?;

    eprintln!("reading response...");

    // Read and print the result.
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    println!("{}", String::from_utf8_lossy(&buf));

    println!("done");

    Ok(())
}

pub mod fallback {
    use arti_client::config::dir::{FallbackDirBuilder, FallbackDir};
    use tor_llcrypto::pk::{rsa::RsaIdentity, ed25519::Ed25519Identity};
    
    pub fn make_ed25519_id(ed: &str) -> Ed25519Identity {
        let ed = base64::decode_config(ed, base64::STANDARD_NO_PAD)
            .expect("Bad hex in built-in fallback list");
        let ed = Ed25519Identity::from_bytes(&ed).expect("Wrong length in built-in fallback list");
        ed
    }

    pub fn make(rsa: &str, ed: &str, ports: &[&str]) -> FallbackDirBuilder {
        let rsa = RsaIdentity::from_hex(rsa).expect("Bad hex in built-in fallback list");
        let ed = base64::decode_config(ed, base64::STANDARD_NO_PAD)
            .expect("Bad hex in built-in fallback list");
        let ed = Ed25519Identity::from_bytes(&ed).expect("Wrong length in built-in fallback list");
        let mut bld = FallbackDir::builder();
        bld.rsa_identity(rsa).ed_identity(ed);

        ports
            .iter()
            .map(|s| s.parse().expect("Bad socket address in fallbacklist"))
            .for_each(|p| {
                bld.orports().push(p);
            });

        bld
    }
}







// use std::{sync::Arc, net::SocketAddr, time::Duration};

// use anyhow::{Result, Context};
// use arti_client::{TorClient, config::TorClientConfigBuilder, box_socks};
// use tokio::net::TcpStream;
// use tokio_crate as tokio;

// use futures::io::{AsyncReadExt, AsyncWriteExt};
// use tor_netdir::NetDir;

// const STATE_DIR: &str = "/tmp/arti-client/state";
// const CACHE_DIR: &str = "/tmp/arti-client/cache";

// macro_rules! dbgd {
//     ($($arg:tt)* ) => (
//         tracing::info!($($arg)*) // comment out this line to disable log
//     );
// }


// #[tokio::main]
// async fn main() -> Result<()> {
//     // Arti uses the `tracing` crate for logging. Install a handler for this, to print Arti's logs.
//     tracing_subscriber::fmt::init();

//     {
//         let r =  arti_client::config::default_config_files()?;
//         eprintln!("default_config_files: [{:?}]", r);
//     }


//     // The client config includes things like where to store persistent Tor network state.
//     // The defaults provided are the same as the Arti standalone application, and save data
//     // to a conventional place depending on operating system (for example, ~/.local/share/arti
//     // on Linux platforms)
//     // let config = TorClientConfig::default();

//     let config = TorClientConfigBuilder::from_directories(STATE_DIR, CACHE_DIR)
//     .build()?;
//     eprintln!("config: {:?}", config);

    
//     eprintln!("connecting to Tor...");

//     // We now let the Arti client start and bootstrap a connection to the network.
//     // (This takes a while to gather the necessary consensus state, etc.)
//     // let tor_client = TorClient::create_bootstrapped(config).await?;

//     // let runtime = tor_rtcompat::PreferredRuntime::current()
//     // .expect("TorClient could not get an asynchronous runtime; are you running in the right context?");

//     let socks_args = Some(box_socks::SocksArgs {
//         server: "127.0.0.1:7890".to_owned(),
//         username: None,
//         password: None,
//         max_targets: None,
//     });
//     let runtime = box_socks::create_runtime(socks_args)?;
//     // let runtime = socks_runtime::create("127.0.0.1:7890".to_owned(), None, None)?;
    
    
//     let tor_client = TorClient::with_runtime(runtime)
//     .config(config)
//     .create_bootstrapped()
//     .await?;
//     eprintln!("====== connected Tor with runtime");


//     eprintln!("connecting to example.com...");

//     // Initiate a connection over Tor to example.com, port 80.
//     let mut stream = tor_client.connect(("example.com", 80)).await?;

//     eprintln!("sending request...");

//     stream
//         .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
//         .await?;

//     // IMPORTANT: Make sure the request was written.
//     // Arti buffers data, so flushing the buffer is usually required.
//     stream.flush().await?;

//     eprintln!("reading response...");

//     // Read and print the result.
//     let mut buf = Vec::new();
//     stream.read_to_end(&mut buf).await?;

//     println!("{}", String::from_utf8_lossy(&buf));

//     Ok(())
// }


// async fn manual_download_dir() -> Result<()> { 
    
//     let netdir = pull_netdir().await.with_context(||"pull_netdir fail")?;
//     dbgd!("pull_netdir done");

//     let total_relays = netdir.relays().count();
//     let mut relay_works = Vec::new();
//     for (index, relay) in netdir.relays().enumerate() {
//         let index = index + 1;
//         // let r = netdir.by_id(relay.id());

//         // dbgd!("realy => {:?}, {:?}\n", relay.rs(), relay.md());
//         if !relay.rs().is_flagged_guard() {
//             dbgd!("relay[{}/{}]: [{}] ignore NOT guard, {:?}", index, total_relays, relay.id(), relay.rs().flags());
//             continue;
//         }

//         let mut connect_able = false;
//         for addr in relay.rs().addrs() {
//             dbgd!("relay[{}/{}]: [{}] -> [{}] connecting", index, total_relays, relay.id(), addr);
//             const TIMEOUT: Duration = Duration::from_secs(5);
//             let r = connect_with_timeout(addr, TIMEOUT).await;
//             match r {
//                 Ok(_s) => {
//                     dbgd!("relay[{}/{}]: [{}] -> [{}] connect ok", index, total_relays, relay.id(), addr);
//                     connect_able = true;
//                 },
//                 Err(e) => {
//                     dbgd!("relay[{}/{}]: [{}] -> [{}] connect fail [{:?}]", index, total_relays, relay.id(), addr, e);
//                 },
//             }
//         }
//         if connect_able {
//             relay_works.push(relay);
//         }
//         dbgd!("on-going: connect-able relays {}\n", relay_works.len());
//     }
//     dbgd!("connect attempts done, connect-able relays {}", relay_works.len());

//     Ok(())
// }

// async fn connect_with_timeout(addr: &SocketAddr, timeout: Duration) -> Result<()> {
//     let _s = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
//     // .with_context(||"timeout")??;
//     Ok(())
// }

// async fn pull_netdir() -> Result<Arc<NetDir>> {
//     let config = {
//         let builder = TorClientConfigBuilder::from_directories(STATE_DIR, CACHE_DIR);
//         builder.build()?
//     };
    
    
//     let socks_args = Some(box_socks::SocksArgs {
//         server: "127.0.0.1:7890".to_owned(),
//         username: None,
//         password: None,
//         max_targets: None,
//     });

//     let runtime = box_socks::create_runtime(socks_args)?;

        
//     let builder = TorClient::with_runtime(runtime)
//     .config(config);
//     let client = builder.create_bootstrapped().await?;

//     let netdir = client.dirmgr().timely_netdir()?;

//     Ok(netdir)
// }

