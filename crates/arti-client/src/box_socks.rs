use tokio_crate as tokio;




// refer: arti-client/examples/hook-tcp.rs

use std::{net::SocketAddr, pin::Pin, collections::HashSet, sync::Arc, time::Duration};
use fast_socks5::client::{Socks5Stream, Config as Socks5Config};
use parking_lot::Mutex;
use rand::{distributions::Alphanumeric, Rng};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::Instrument;
use std::future::Future;
use std::io::Result as IoResult;
// use tokio::{
//     net::TcpStream as TokioStream, 
//     // io::{AsyncRead as TokioAsyncRead, AsyncReadExt as TokioAsyncReadExt, AsyncWrite as TokioAsyncWrite, AsyncWriteExt as TokioAsyncWriteExt}
// };
// #[cfg(feature = "tokio")]
// use tokio_util::compat::TokioAsyncReadCompatExt;
use tor_rtcompat::{CompoundRuntime, TcpProvider, Runtime};
use futures::FutureExt;

use crate::box_tcp::{BoxTcpStream, box_tcp_stream, BoxTcpListener};

/// TODO: add doc
#[derive(Debug, Clone)]
pub struct SocksArgs {
    /// TODO: add doc
    pub server: String, 

    /// TODO: add doc
    pub username: Option<String>, 

    /// TODO: add doc
    pub password: Option<String>,

    /// TODO: add doc
    pub max_targets: Option<usize>,
}

/// TODO: add doc
pub type SocksRuntime<R> = CompoundRuntime<R, R, SocksTcpProvider<R>, R, R>;


/// TODO: add doc
pub fn create_runtime(socks_args: Option<SocksArgs>) -> std::io::Result<SocksRuntime<tor_rtcompat::PreferredRuntime>> 
{

    // 不推荐用这种方式创建runtime，因为如果tokio 还没初始化会失败
    let rt = tor_rtcompat::PreferredRuntime::current()?;

    // 推荐用这种方式，但是编译出错
    // TODO: fix compile
    // let rt = create_raw_runtime()?;

    create_with_runtime(socks_args, rt)
}

// /// TODO: add doc
// pub fn create_runtime(socks_args: Option<SocksArgs>) -> std::io::Result< SocksRuntime<impl Runtime+tor_rtcompat::TlsProvider<BoxTcpStream>> > 
// {

//     // 不推荐用这种方式创建runtime，因为如果tokio 还没初始化会失败
//     // let rt = tor_rtcompat::PreferredRuntime::current()?;

//     // 推荐用这种方式，但是编译出错
//     // TODO: fix compile
//     let rt = create_raw_runtime()?;

//     create_with_runtime(socks_args, rt)
// }


// /// TODO: add doc
// pub fn create_socks_runtime(socks_args: Option<SocksArgs>) -> std::io::Result<impl Runtime> {
//     cfg_if::cfg_if! {
//         if #[cfg(all(feature="tokio", feature="native-tls"))] {
//         use tor_rtcompat::tokio::TokioNativeTlsRuntime as ChosenRuntime;
//         } else if #[cfg(all(feature="tokio", feature="rustls"))] {
//             use tor_rtcompat::tokio::TokioRustlsRuntime as ChosenRuntime;
//         } else if #[cfg(all(feature="async-std", feature="native-tls"))] {
//             use tor_rtcompat::async_std::AsyncStdNativeTlsRuntime as ChosenRuntime;
//         } else if #[cfg(all(feature="async-std", feature="rustls"))] {
//             use tor_rtcompat::async_std::AsyncStdRustlsRuntime as ChosenRuntime;
//         } else {
//             compile_error!("You must configure both an async runtime and a TLS stack. See doc/TROUBLESHOOTING.md for more.");
//         }
//     }
//     let rt = ChosenRuntime::create()?;

//     create_with_runtime(socks_args, rt)
// }

/// TODO: add doc
pub fn create_with_runtime<R>(socks_args: Option<SocksArgs>, rt: R) -> std::io::Result<SocksRuntime<R>> 
where
    R: Runtime
{
    let tcp_rt = SocksTcpProvider { socks_args, rt: rt.clone(), targets: Default::default()};

    let rt = CompoundRuntime::new(rt.clone(), rt.clone(), tcp_rt, rt.clone(), rt);

    Ok(rt)
}

// fn create_raw_runtime() -> std::io::Result<impl Runtime+tor_rtcompat::TlsProvider<BoxTcpStream>> {
//     // cfg_if::cfg_if! {
//     //     if #[cfg(all(feature="tokio", feature="native-tls"))] {
//     //     use tor_rtcompat::tokio::TokioNativeTlsRuntime as ChosenRuntime;
//     //     } else if #[cfg(all(feature="tokio", feature="rustls"))] {
//     //         use tor_rtcompat::tokio::TokioRustlsRuntime as ChosenRuntime;
//     //     } else if #[cfg(all(feature="async-std", feature="native-tls"))] {
//     //         use tor_rtcompat::async_std::AsyncStdNativeTlsRuntime as ChosenRuntime;
//     //     } else if #[cfg(all(feature="async-std", feature="rustls"))] {
//     //         use tor_rtcompat::async_std::AsyncStdRustlsRuntime as ChosenRuntime;
//     //     } else {
//     //         compile_error!("You must configure both an async runtime and a TLS stack. See doc/TROUBLESHOOTING.md for more.");
//     //     }
//     // }
//     // ChosenRuntime::create()
//     use tor_rtcompat::tokio::TokioNativeTlsRuntime as ChosenRuntime;
//     ChosenRuntime::create()

// }






/// TODO: add doc
#[derive(Clone)]
pub struct SocksTcpProvider<R> {
    // socks_server: String, // eg. `127.0.0.1:1080`

    // username: Option<String>,

    // password: Option<String>,
    socks_args: Option<SocksArgs>,

    rt: R,

    targets: Arc<Mutex<Targets>>,
}


type SocksTcpStream = BoxTcpStream;

impl<R> TcpProvider for SocksTcpProvider<R>
where 
    R: Runtime,
{
    type TcpStream = SocksTcpStream;
    type TcpListener = BoxTcpListener<R::TcpListener>;

    fn connect<'a, 'b, 'c>(
        &'a self,
        addr: &'b SocketAddr,
    ) -> Pin<Box<dyn Future<Output = IoResult<Self::TcpStream>> + Send + 'c>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        // println!("====== try tcp connecting to {}", addr);
        // let target_addr = addr.ip().to_string();
        // let target_port = addr.port();
        // let r = if let Some(username) = &self.username {
        //     let password = self.password.as_deref().unwrap_or_else(||"").to_owned();
        //     Socks5Stream::connect_with_password(
        //         &self.socks_server,
        //         target_addr,
        //         target_port,
        //         username.clone(),
        //         password,
        //         Socks5Config::default(),
        //     )
        //     .map_ok(|v|box_tcp_stream(v.compat()))
        //     .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        //     .boxed()
        // } else {
        //     Socks5Stream::connect(&self.socks_server, target_addr, target_port, Socks5Config::default())
        //     .map_ok(|v|box_tcp_stream(v.compat()))
        //     .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        //     .boxed()
        // };

        // r

        let txid: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(7)
        .map(char::from)
        .collect();

        let span = tracing::span!(parent:None, tracing::Level::INFO, "", txid = &txid[..]);

        connect_to(
            &self.socks_args, 
            addr, 
            &self.targets
        )
        .instrument(span)
        .boxed()
    }


    fn listen<'a, 'b, 'c>(
        &'a self,
        addr: &'b SocketAddr,
    ) -> Pin<Box<dyn Future<Output = IoResult<Self::TcpListener>> + Send + 'c>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        println!("====== try tcp listening on {}", addr);
        // PendingForever(PhantomData::default()).boxed()
        self.rt
        .listen(addr)
        .map(|l| l.map(|listener| BoxTcpListener::new(listener)))
        .boxed()
    }
}

#[derive(Default)]
struct Targets {
    direct_targets: HashSet<String>,
    socks_targets: HashSet<String>,
    // socks_one: Option<String>,
}

macro_rules! dbgd {
    ($($arg:tt)* ) => (
        tracing::info!($($arg)*) // comment out this line to disable log
    );
}

async fn connect_to(
    socks_args: &Option<SocksArgs>,
    addr: &SocketAddr,
    targets: &Arc<Mutex<Targets>>,
) -> IoResult<SocksTcpStream> {
    let r = do_connect_to(socks_args, addr, targets).await;
    match r {
        Ok(stream) => {
            dbgd!("connect_to result: success");
            Ok(stream)
        },
        Err(e) => {
            dbgd!("connect_to result: fail {:?}", e);
            Err(e)
        },
    }
}

fn check_use_socks<'a>(
    socks_args: &SocksArgs,
    addr: &str,
    targets: &Arc<Mutex<Targets>>,
) -> bool {
    match socks_args.max_targets {
                
        None => return true,

        Some(max) => {
            let targets = targets.lock(); 
            
            if targets.socks_targets.contains(addr) {
                return true;
            }

            if targets.socks_targets.len() < max {
                return true;
            }
            return false;
        },
    }
}


async fn do_connect_to(
    socks_args: &Option<SocksArgs>,
    addr: &SocketAddr,
    targets: &Arc<Mutex<Targets>>,
) -> IoResult<SocksTcpStream> {

    const TIMEOUT: Duration = Duration::from_secs(4);

    if addr.is_ipv6() {
        // tokio::time::sleep(TIMEOUT + Duration::from_secs(2)).await;
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "NOT support Ipv6"))
    }

    if let Some(socks_args) = socks_args {
        let addr0 = addr.to_string(); 
        let use_socks = check_use_socks(socks_args, &addr0, targets);
        if use_socks  {
            let stream = connect_to_with_socks(socks_args, addr).await?;
            targets.lock().socks_targets.insert(addr0);
            return Ok(stream)
        }
    }

    dbgd!("====== try direct tcp connecting to [{}]", addr);
    // let r = TcpStream::connect(addr).await;

    let r = tokio::time::timeout(TIMEOUT, TcpStream::connect(addr)).await;
    let r = match r {
        Ok(r) => r,
        Err(_e) => {
            // dbgd!("====== timeout direct tcp connect to [{}]", addr);
            Err(std::io::Error::new(std::io::ErrorKind::Other, "Timeout"))
        },
    };

    match r {
        Ok(stream) => {
            if targets.lock().direct_targets.insert(addr.to_string()) {
                dbgd!("====== direct tcp connected [{}]", addr);
            }
            return Ok(box_tcp_stream(stream.compat()));
        },
        Err(e) => {
            dbgd!("====== fail to direct tcp connect to [{}], error [{:?}]", addr, e);
            return Err(e);
        },
    }
}

async fn connect_to_with_socks(
    socks_args: &SocksArgs,
    addr: &SocketAddr,
    // targets: &Arc<Mutex<Targets>>,
) -> IoResult<SocksTcpStream> {
    dbgd!("====== try socks tcp connecting to [{}]", addr);

    let target_addr = addr.ip().to_string();
    let target_port = addr.port();
    let r = if let Some(username) = &socks_args.username {
        let password = socks_args.password.as_deref().unwrap_or_else(||"").to_owned();
        Socks5Stream::connect_with_password(
            &socks_args.server,
            target_addr,
            target_port,
            username.to_owned(),
            password,
            Socks5Config::default(),
        ).await
        .map_err(|e| {
            dbgd!("====== fail to socks tcp connect to [{}], error [{:?}]", addr, e);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })
        // .boxed()
    } else {
        Socks5Stream::connect(&socks_args.server, target_addr, target_port, Socks5Config::default()).await
        .map_err(|e| {
            dbgd!("====== fail to socks tcp connect to [{}], error [{:?}]", addr, e);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })
    };

    dbgd!("====== socks tcp connect [{}], result [{:?}]", addr, r.is_ok());

    let stream = r?;
    Ok(box_tcp_stream(stream.compat()))
}




