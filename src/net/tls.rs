use core::future::Future;
use core::pin::Pin;
use core::task::Poll;
use rand_chacha::rand_core::RngCore;

mod sys {
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/wolf_ssl_bindings.rs"));
}

pub fn init() {
    unsafe {
        // sys::wolfSSL_Debugging_ON();
        sys::wolfSSL_SetAllocators(
            Some(wolfssl_malloc),
            Some(wolfssl_free),
            Some(wolfssl_realloc),
        );
        sys::wolfSSL_Init();
        sys::wc_CryptoCb_RegisterDevice(0, Some(wolfssl_crypto_cb), core::ptr::null_mut());
    }
}

pub struct Method(*mut sys::WOLFSSL_METHOD);

impl Method {
    pub fn dtls13_client() -> Self {
        let method = unsafe { sys::wolfDTLSv1_3_client_method() };
        if method == core::ptr::null_mut() {
            panic!("Failed to create DTLS method");
        }
        Self(method)
    }
}

pub struct Context {
    ctx: *mut sys::WOLFSSL_CTX,
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            sys::wolfSSL_CTX_free(self.ctx);
        }
    }
}

impl Context {
    pub fn new(method: Method) -> Self {
        let ctx = unsafe { sys::wolfSSL_CTX_new(method.0) };
        if ctx == core::ptr::null_mut() {
            panic!("Failed to create SSL context");
        }
        unsafe {
            sys::wolfSSL_CTX_SetDevId(ctx, 0);
            let cert_types = [sys::WOLFSSL_CERT_TYPE_RPK];
            sys::wolfSSL_CTX_set_client_cert_type(
                ctx,
                cert_types.as_ptr() as *const core::ffi::c_char,
                1,
            );
            sys::wolfSSL_CTX_set_server_cert_type(
                ctx,
                cert_types.as_ptr() as *const core::ffi::c_char,
                1,
            );
        }
        Self {
            ctx,
        }
    }

    pub fn set_certificate(&mut self, data: &[u8]) -> Result<(), i32> {
        unsafe {
            let ret = sys::wolfSSL_CTX_use_certificate_buffer(
                self.ctx,
                data.as_ptr(),
                data.len() as i32,
                sys::WOLFSSL_FILETYPE_ASN1 as i32,
            );
            if ret != sys::WOLFSSL_SUCCESS as i32 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    pub fn set_private_key(&mut self, data: &[u8]) -> Result<(), i32> {
        unsafe {
            let ret = sys::wolfSSL_CTX_use_PrivateKey_buffer(
                self.ctx,
                data.as_ptr(),
                data.len() as i32,
                sys::WOLFSSL_FILETYPE_ASN1 as i32,
            );
            if ret != sys::WOLFSSL_SUCCESS as i32 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    pub fn set_verify_all(&mut self, cb: fn(i32, X509StoreContext) -> bool) {
        unsafe {
            sys::wolfSSL_CTX_SetCertCbCtx(self.ctx, cb as *mut core::ffi::c_void);
            sys::wolfSSL_CTX_set_verify(self.ctx, sys::WOLFSSL_VERIFY_PEER as i32, Some(verify_cb));
        }
    }

    pub fn connection<'a>(
        &self,
        socket: embassy_net::udp::UdpSocket<'a>,
        peer: embassy_net::IpEndpoint,
    ) -> Connection<'a> {
        let tls = unsafe { sys::wolfSSL_new(self.ctx) };
        if tls == core::ptr::null_mut() {
            panic!("SSL creation failed");
        }
        let mut state = alloc::boxed::Box::new(ConnectionState {
            tls,
            socket,
            peer,
            waker: core::task::Waker::noop().clone(),
        });
        unsafe {
            sys::wolfSSL_SSLSetIOSend(tls, Some(socket_send));
            sys::wolfSSL_SSLSetIORecv(tls, Some(socket_recv));
            sys::wolfSSL_SetIOReadCtx(
                tls,
                alloc::boxed::Box::as_mut(&mut state) as *mut ConnectionState as *mut _,
            );
            sys::wolfSSL_SetIOWriteCtx(
                tls,
                alloc::boxed::Box::as_mut(&mut state) as *mut ConnectionState as *mut _,
            );
            sys::wolfSSL_dtls_set_using_nonblock(tls, 1);
            sys::wolfSSL_dtls_cid_use(tls);
        }
        Connection { state }
    }
}

pub struct X509StoreContext {
    ctx: *mut sys::WOLFSSL_X509_STORE_CTX,
}

impl X509StoreContext {
    pub fn certs(&self) -> alloc::vec::Vec<&[u8]> {
        let store = unsafe { &*self.ctx };
        let mut out = vec![];
        for i in 0..store.totalCerts {
            out.push(unsafe {
                core::slice::from_raw_parts((*store.certs.add(i as usize)).buffer, (*store.certs.add(i as usize)).length as usize)
            });
        }
        out
    }
}

pub struct Connection<'a> {
    state: alloc::boxed::Box<ConnectionState<'a>>,
}

impl<'c> Connection<'c> {
    pub fn connect<'a>(&'a mut self) -> ConnectionConnectFuture<'a, 'c> {
        ConnectionConnectFuture {
            connection: Pin::new(self),
            timeout: None,
        }
    }

    pub fn shutdown<'a>(&'a mut self) -> ConnectionShutdownFuture<'a, 'c> {
        ConnectionShutdownFuture {
            connection: Pin::new(self),
        }
    }

    pub fn read_data<'a>(&'a mut self) -> ConnectionReadFuture<'a, 'c> {
        ConnectionReadFuture {
            connection: Pin::new(self),
        }
    }

    pub fn write_data<'a, 'b>(&'a mut self, data: &'b [u8]) -> ConnectionWriteFuture<'a, 'c, 'b> {
        ConnectionWriteFuture {
            connection: Pin::new(self),
            data,
        }
    }
}

enum PollStatus<T> {
    Ok(T),
    Err(i32),
    Timeout(u64),
}

pub struct ConnectionConnectFuture<'a, 'b> {
    connection: Pin<&'a mut Connection<'b>>,
    timeout: Option<embassy_time::Timer>,
}

impl Future for ConnectionConnectFuture<'_, '_> {
    type Output = Result<(), i32>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Some(timer) = self.timeout.as_mut() {
                match Pin::new(timer).poll(cx) {
                    Poll::Pending => {}
                    Poll::Ready(()) => {
                        debug!("TLS timeout");
                        self.timeout = None;
                        if let Some(err) = self.connection.as_mut().with_context(cx, |s| {
                            let ret = unsafe { sys::wolfSSL_dtls_got_timeout(s.tls) };
                            if ret != sys::WOLFSSL_SUCCESS as i32 {
                                let err = unsafe { sys::wolfSSL_get_error(s.tls, ret) };
                                Some(err)
                            } else {
                                None
                            }
                        }) {
                            return Poll::Ready(Err(err));
                        }
                    }
                }
            }
            match self.connection.as_mut().with_context(cx, |s| {
                let ret = unsafe { sys::wolfSSL_connect(s.tls) };
                if ret == sys::WOLFSSL_SUCCESS as i32 {
                    PollStatus::Ok(())
                } else {
                    let err = unsafe { sys::wolfSSL_get_error(s.tls, ret) };
                    if err == sys::WOLFSSL_ERROR_WANT_READ as i32
                        || err == sys::WOLFSSL_ERROR_WANT_WRITE as i32
                    {
                        let mut timeout =
                            unsafe { sys::wolfSSL_dtls_get_current_timeout(s.tls) } * 1000;
                        if unsafe { sys::wolfSSL_dtls13_use_quick_timeout(s.tls) } != 0 {
                            timeout /= 4;
                        }
                        PollStatus::Timeout(timeout as u64)
                    } else {
                        PollStatus::Err(err)
                    }
                }
            }) {
                PollStatus::Ok(()) => return Poll::Ready(Ok(())),
                PollStatus::Err(e) => return Poll::Ready(Err(e)),
                PollStatus::Timeout(t) => {
                    if self.timeout.is_some() {
                        return Poll::Pending;
                    }
                    debug!("TLS timeout after {:?}", t);
                    let mut timer = embassy_time::Timer::after_millis(t);
                    match Pin::new(&mut timer).poll(cx) {
                        Poll::Pending => {
                            self.timeout = Some(timer);
                            return Poll::Pending;
                        }
                        Poll::Ready(()) => continue,
                    }
                }
            }
        }
    }
}

pub struct ConnectionShutdownFuture<'a, 'b> {
    connection: Pin<&'a mut Connection<'b>>,
}

impl Future for ConnectionShutdownFuture<'_, '_> {
    type Output = Result<(), i32>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> Poll<Self::Output> {
        self.connection.as_mut().with_context(cx, |s| {
            let ret = unsafe { sys::wolfSSL_shutdown(s.tls) };
            if ret == sys::WOLFSSL_SUCCESS as i32
                || ret == sys::_bindgen_ty_17::WOLFSSL_SHUTDOWN_NOT_DONE as i32
            {
                Poll::Ready(Ok(()))
            } else {
                let err = unsafe { sys::wolfSSL_get_error(s.tls, ret) };
                if err == sys::WOLFSSL_ERROR_WANT_READ as i32
                    || err == sys::WOLFSSL_ERROR_WANT_WRITE as i32
                {
                    Poll::Pending
                } else {
                    Poll::Ready(Err(err))
                }
            }
        })
    }
}

pub struct ConnectionReadFuture<'a, 'b> {
    connection: Pin<&'a mut Connection<'b>>,
}

impl Future for ConnectionReadFuture<'_, '_> {
    type Output = Result<alloc::vec::Vec<u8>, i32>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> Poll<Self::Output> {
        self.connection.as_mut().with_context(cx, |s| {
            let mut buf = [0u8; 1500];
            let len = unsafe { sys::wolfSSL_read(s.tls, buf.as_mut_ptr() as *mut _, buf.len() as i32) };
            if len > 0 {
                Poll::Ready(Ok(buf[..len as usize].to_vec()))
            } else {
                let err = unsafe { sys::wolfSSL_get_error(s.tls, len) };
                if err == sys::WOLFSSL_ERROR_WANT_READ as i32
                    || err == sys::WOLFSSL_ERROR_WANT_WRITE as i32
                {
                    Poll::Pending
                } else {
                    Poll::Ready(Err(err))
                }
            }
        })
    }
}

pub struct ConnectionWriteFuture<'a, 'b, 'c> {
    connection: Pin<&'a mut Connection<'b>>,
    data: &'c [u8],
}

impl Future for ConnectionWriteFuture<'_, '_, '_> {
    type Output = Result<(), i32>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> Poll<Self::Output> {
        let data = self.data;
        self.connection.as_mut().with_context(cx, |s| {
            let len = unsafe { sys::wolfSSL_write(s.tls, data.as_ptr() as *const _, data.len() as i32) };
            if len > 0 {
                Poll::Ready(Ok(()))
            } else {
                let err = unsafe { sys::wolfSSL_get_error(s.tls, len) };
                if err == sys::WOLFSSL_ERROR_WANT_READ as i32
                    || err == sys::WOLFSSL_ERROR_WANT_WRITE as i32
                {
                    Poll::Pending
                } else {
                    Poll::Ready(Err(err))
                }
            }
        })
    }
}

struct ConnectionState<'a> {
    tls: *mut sys::WOLFSSL,
    socket: embassy_net::udp::UdpSocket<'a>,
    peer: embassy_net::IpEndpoint,
    waker: core::task::Waker,
}

impl Drop for ConnectionState<'_> {
    fn drop(&mut self) {
        unsafe {
            sys::wolfSSL_free(self.tls);
        }
    }
}

impl Connection<'_> {
    fn with_context<F, R>(
        self: core::pin::Pin<&mut Self>,
        ctx: &mut core::task::Context<'_>,
        f: F,
    ) -> R
    where
        F: FnOnce(&mut ConnectionState) -> R,
    {
        let this = unsafe { self.get_unchecked_mut() };
        this.state.waker = ctx.waker().clone();
        f(&mut this.state)
    }
}

extern "C" fn socket_send(
    _tls: *mut sys::WOLFSSL,
    buf: *mut u8,
    len: i32,
    state: *mut core::ffi::c_void,
) -> i32 {
    let state = unsafe { &mut *(state as *mut ConnectionState) };
    let buf = unsafe { core::slice::from_raw_parts(buf, len as usize) };
    debug!("sending UDP: {:02X?}", buf);
    let mut context = core::task::Context::from_waker(&state.waker);
    match state.socket.poll_send_to(buf, state.peer, &mut context) {
        Poll::Ready(Ok(())) => buf.len() as i32,
        Poll::Ready(Err(c)) => {
            warn!("Send error: {:?}", c);
            match c {
                embassy_net::udp::SendError::NoRoute => {
                    sys::IOerrors::WOLFSSL_CBIO_ERR_GENERAL as i32
                }
                embassy_net::udp::SendError::PacketTooLarge => {
                    sys::IOerrors::WOLFSSL_CBIO_ERR_GENERAL as i32
                }
                embassy_net::udp::SendError::SocketNotBound => {
                    sys::IOerrors::WOLFSSL_CBIO_ERR_CONN_CLOSE as i32
                }
            }
        }
        Poll::Pending => sys::IOerrors::WOLFSSL_CBIO_ERR_WANT_WRITE as i32,
    }
}

extern "C" fn socket_recv(
    _tls: *mut sys::WOLFSSL,
    buf: *mut u8,
    len: i32,
    state: *mut core::ffi::c_void,
) -> i32 {
    let state = unsafe { &mut *(state as *mut ConnectionState) };
    let buf = unsafe { core::slice::from_raw_parts_mut(buf, len as usize) };
    let mut context = core::task::Context::from_waker(&state.waker);
    loop {
        match state.socket.poll_recv_from(buf, &mut context) {
            Poll::Ready(Ok((read, udp_metadata))) => {
                if udp_metadata.endpoint != state.peer {
                    continue;
                }
                debug!("read UDP: {:02X?}", &buf[..read]);
                break read as i32;
            }
            Poll::Ready(Err(c)) => match c {
                embassy_net::udp::RecvError::Truncated => {
                    break sys::IOerrors::WOLFSSL_CBIO_ERR_GENERAL as i32
                }
            },
            Poll::Pending => break sys::IOerrors::WOLFSSL_CBIO_ERR_WANT_READ as i32,
        }
    }
}

extern "C" fn wolfssl_crypto_cb(
    _dev_id: i32,
    crypto_info: *mut sys::wc_CryptoInfo,
    _ctx: *mut core::ffi::c_void,
) -> i32 {
    let crypto_info = unsafe { &mut *crypto_info };
    if crypto_info.algo_type == sys::wc_AlgoType::WC_ALGO_TYPE_RNG as i32 {
        let rng_req = unsafe { crypto_info.__bindgen_anon_1.rng };
        let buf = unsafe { core::slice::from_raw_parts_mut(rng_req.out, rng_req.sz as usize) };
        unsafe {
            embassy_futures::block_on(crate::RAND.lock())
                .assume_init_mut()
                .fill_bytes(buf)
        };
        0
    } else if crypto_info.algo_type == sys::wc_AlgoType::WC_ALGO_TYPE_SEED as i32 {
        let seed_req = unsafe { crypto_info.__bindgen_anon_1.seed };
        let buf = unsafe { core::slice::from_raw_parts_mut(seed_req.seed, seed_req.sz as usize) };
        unsafe {
            embassy_futures::block_on(crate::RAND.lock())
                .assume_init_mut()
                .fill_bytes(buf)
        };
        0
    } else {
        sys::wolfCrypt_ErrorCodes::CRYPTOCB_UNAVAILABLE as i32
    }
}

const LAYOUT_SIZE: usize = size_of::<alloc::alloc::Layout>();

unsafe extern "C" fn wolfssl_malloc(size: usize) -> *mut core::ffi::c_void {
    let layout = alloc::alloc::Layout::from_size_align(LAYOUT_SIZE + size, 4).unwrap();
    let ptr = alloc::alloc::alloc(layout);
    let out_ptr = ptr.add(LAYOUT_SIZE);
    *(ptr as *mut alloc::alloc::Layout) = layout;
    out_ptr as *mut core::ffi::c_void
}

unsafe extern "C" fn wolfssl_free(ptr: *mut core::ffi::c_void) {
    let ptr = ptr as *mut u8;
    let ptr = ptr.sub(LAYOUT_SIZE);
    let layout = *(ptr as *mut alloc::alloc::Layout);
    alloc::alloc::dealloc(ptr, layout);
}

unsafe extern "C" fn wolfssl_realloc(
    ptr: *mut core::ffi::c_void,
    new_size: usize,
) -> *mut core::ffi::c_void {
    let new_layout = alloc::alloc::Layout::from_size_align(LAYOUT_SIZE + new_size, 4).unwrap();
    let ptr = ptr as *mut u8;
    let ptr = ptr.sub(LAYOUT_SIZE);
    let layout = *(ptr as *mut alloc::alloc::Layout);
    let ptr = alloc::alloc::realloc(ptr, layout, LAYOUT_SIZE + new_size);
    let out_ptr = ptr.add(LAYOUT_SIZE);
    *(ptr as *mut alloc::alloc::Layout) = new_layout;
    out_ptr as *mut core::ffi::c_void
}

unsafe extern "C" fn verify_cb(
    pre_verify: i32,
    store: *mut sys::WOLFSSL_X509_STORE_CTX
) -> i32 {;
    let store = &mut*store;
    let cb = core::mem::transmute::<*const (), fn(i32, X509StoreContext) -> bool>(store.userCtx as *const ());
    if cb(pre_verify, X509StoreContext {
        ctx: store
    }) {
        1
    } else {
        0
    }
}

mod ffi {
    #[no_mangle]
    pub extern "C" fn tolower(chr: i32) -> i32 {
        if chr >= 65 && chr <= 90 {
            chr + 32
        } else {
            chr
        }
    }

    #[no_mangle]
    pub extern "C" fn _wolfssl_log(msg: *const u8) {
        let msg = unsafe { core::ffi::CStr::from_ptr(msg) };
        debug!("wolfSSL: {}", msg.to_string_lossy())
    }
}
