/// TODO: add doc

// refer: arti-client/examples/hook-tcp.rs

use std::{net::SocketAddr, pin::Pin, task::{Context, Poll}};

use std::future::Future;
use std::io::Result as IoResult;


use tor_rtcompat::TcpListener;
use futures::{FutureExt, Stream, AsyncRead, AsyncWrite};

/// TODO: add doc
pub trait AsyncStreamTrait: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static> AsyncStreamTrait for T {}

/// TODO: add doc
pub type BoxTcpStream = Box<dyn AsyncStreamTrait>;

/// TODO: add doc
pub fn box_tcp_stream<T>(stream: T) -> BoxTcpStream 
where
    T: AsyncStreamTrait
{
    Box::new(stream)
}

/// A wrapper over a `TcpListener`.
pub struct BoxTcpListener<T> {
    inner: T,
}

impl <T> BoxTcpListener<T> {

    /// TODO: add doc
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}


type AcceptResult<T> = IoResult<(T, SocketAddr)>;

impl<T> TcpListener for BoxTcpListener<T>
where
    T: TcpListener,
{
    type TcpStream = BoxTcpStream;
    type Incoming = BoxIncoming<T::Incoming>;

    // This is also an async trait method (see earlier commentary).
    fn accept<'a, 'b>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = AcceptResult<Self::TcpStream>> + Send + 'b>>
    where
        'a: 'b,
        Self: 'b,
    {
        // As with other implementations, we just defer to `self.inner` and wrap the result.
        self.inner
            .accept()
            .inspect(|r| {
                if let Ok((_, addr)) = r {
                    println!("accepted connection from {}", addr)
                }
            })
            .map(|r| {
                r.map(|(stream, addr)| {
                    (
                        // CustomTcpStream {
                        //     inner: stream,
                        //     addr,
                        //     state: TcpState::Open,
                        // },
                        box_tcp_stream(stream),
                        addr,
                    )
                })
            })
            .boxed()
    }

    fn incoming(self) -> Self::Incoming {
        BoxIncoming {
            inner: self.inner.incoming(),
        }
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        self.inner.local_addr()
    }
}

/// TODO: add doc
pub struct BoxIncoming<T> {
    inner: T,
}

impl<T, S> Stream for BoxIncoming<T>
where
    T: Stream<Item = IoResult<(S, SocketAddr)>> + Unpin,
    S: AsyncStreamTrait
{
    type Item = IoResult<(BoxTcpStream, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok((stream, addr)))) => Poll::Ready(Some(Ok((
                // CustomTcpStream {
                //     inner: stream,
                //     addr,
                //     state: TcpState::Open,
                // },
                box_tcp_stream(stream),
                addr,
            )))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
