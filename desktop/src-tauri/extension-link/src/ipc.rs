//! The local endpoint between the native host and the app, same user only.
//!
//! Unix: a socket in a `0700` folder, the socket itself `0600`; both ends check
//! the other's uid (`getpeereid` / `SO_PEERCRED`). Windows: a named pipe with a
//! DACL for the current user only, `PIPE_REJECT_REMOTE_CLIENTS`, the first
//! instance created with `FILE_FLAG_FIRST_PIPE_INSTANCE` (nobody can squat the
//! name before the app), and both ends compare the other process's token user
//! with their own. The client connects at identification level, so the app
//! cannot impersonate it.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;

fn refused(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.to_string())
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};

    pub fn own_uid() -> u32 {
        // SAFETY: getuid cannot fail.
        unsafe { libc::getuid() }
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
        let mut uid = 0;
        let mut gid = 0;
        // SAFETY: valid fd and out pointers.
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }

    #[cfg(target_os = "linux")]
    pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: valid fd, out buffer of the stated length.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }

    pub struct Stream(UnixStream);

    impl Stream {
        pub fn try_clone(&self) -> io::Result<Stream> {
            Ok(Stream(self.0.try_clone()?))
        }
        pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.0.set_read_timeout(timeout)
        }
        pub fn shutdown(&self) {
            let _ = self.0.shutdown(std::net::Shutdown::Both);
        }
    }

    impl Read for Stream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for Stream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    pub struct Listener {
        inner: UnixListener,
        path: PathBuf,
        inode: u64,
        stopped: Arc<AtomicBool>,
    }

    /// Listen at `path`. A stale socket left by a crash is replaced; a live one
    /// (another CipherMoth already listening) is an error, never taken over.
    pub fn listen(path: &Path) -> io::Result<Listener> {
        let parent = path
            .parent()
            .ok_or_else(|| refused("socket path has no folder"))?;
        crate::identity::private_dir(parent)?;
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if !meta.file_type().is_socket() || meta.uid() != own_uid() {
                return Err(refused("something else is at the socket path"));
            }
            if UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another CipherMoth is listening",
                ));
            }
            std::fs::remove_file(path)?;
        }
        let inner = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let inode = std::fs::symlink_metadata(path)?.ino();
        Ok(Listener {
            inner,
            path: path.to_path_buf(),
            inode,
            stopped: Arc::new(AtomicBool::new(false)),
        })
    }

    impl Listener {
        /// The next client of the same user; `None` once stopped. Clients of
        /// another user are dropped before anything is read from them.
        pub fn accept(&self) -> Option<Stream> {
            loop {
                let (stream, _) = match self.inner.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) if !self.stopped.load(Ordering::SeqCst) => {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    Err(_) => return None,
                };
                if self.stopped.load(Ordering::SeqCst) {
                    return None;
                }
                match peer_uid(&stream) {
                    Ok(uid) if uid == own_uid() => return Some(Stream(stream)),
                    _ => continue,
                }
            }
        }

        pub fn stopper(&self) -> Stopper {
            Stopper {
                path: self.path.clone(),
                inode: self.inode,
                stopped: self.stopped.clone(),
            }
        }
    }

    pub struct Stopper {
        path: PathBuf,
        inode: u64,
        stopped: Arc<AtomicBool>,
    }

    impl Stopper {
        /// Stop accepting and remove the socket (only if it is still ours).
        pub fn stop(&self) {
            if self.stopped.swap(true, Ordering::SeqCst) {
                return;
            }
            let _ = UnixStream::connect(&self.path);
            if std::fs::symlink_metadata(&self.path).is_ok_and(|m| m.ino() == self.inode) {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    /// Connect to the app; the listener must belong to this user.
    pub fn connect(path: &Path) -> io::Result<Stream> {
        let stream = UnixStream::connect(path)?;
        if peer_uid(&stream)? != own_uid() {
            return Err(refused("the endpoint belongs to another user"));
        }
        Ok(Stream(stream))
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GENERIC_READ,
        GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, WaitForSingleObject,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    struct Owned(HANDLE);
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: we own the handle.
                unsafe { CloseHandle(self.0) };
            }
        }
    }
    // SAFETY: kernel handles may be used from any thread.
    unsafe impl Send for Owned {}
    unsafe impl Sync for Owned {}

    /// The token user of `process` (a buffer holding TOKEN_USER and its SID).
    fn token_user(process: HANDLE) -> io::Result<Vec<u8>> {
        let mut token = null_mut();
        // SAFETY: valid process handle, out pointer.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Owned(token);
        let mut size = 0u32;
        // SAFETY: size query with a null buffer.
        unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut size) };
        let mut buf = vec![0u8; size as usize];
        // SAFETY: buffer of the size the system asked for.
        if unsafe {
            GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), size, &mut size)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(buf)
    }

    fn sid_of(buf: &[u8]) -> *mut core::ffi::c_void {
        // SAFETY: buf holds a TOKEN_USER written by GetTokenInformation.
        unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid }
    }

    fn own_user() -> io::Result<Vec<u8>> {
        // SAFETY: the pseudo-handle of this process.
        token_user(unsafe { GetCurrentProcess() })
    }

    pub fn current_user_sid() -> io::Result<String> {
        let user = own_user()?;
        let mut text = null_mut();
        // SAFETY: valid SID; the string is freed with LocalFree.
        if unsafe { ConvertSidToStringSidW(sid_of(&user), &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0;
        // SAFETY: NUL-terminated string from the system.
        while unsafe { *text.add(len) } != 0 {
            len += 1;
        }
        let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        unsafe { LocalFree(text.cast()) };
        Ok(sid)
    }

    fn same_user(pid: u32) -> io::Result<bool> {
        // SAFETY: query-only access to the peer process.
        let process = Owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
        if process.0.is_null() {
            return Err(io::Error::last_os_error());
        }
        let (theirs, ours) = (token_user(process.0)?, own_user()?);
        // SAFETY: two valid SIDs.
        Ok(unsafe { EqualSid(sid_of(&theirs), sid_of(&ours)) } != 0)
    }

    fn event() -> io::Result<Owned> {
        // SAFETY: manual-reset, unnamed event.
        let handle = unsafe { CreateEventW(null(), 1, 0, null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Owned(handle))
    }

    /// Wait for one overlapped operation; on timeout it is cancelled.
    fn finish(
        pipe: HANDLE,
        overlapped: &mut OVERLAPPED,
        started: i32,
        timeout: Option<Duration>,
    ) -> io::Result<usize> {
        // SAFETY: reading the thread's last error right after the call.
        if started == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(io::Error::last_os_error());
        }
        let ms = timeout.map_or(u32::MAX, |t| t.as_millis().min(u32::MAX as u128 - 1) as u32);
        // SAFETY: the event belongs to this overlapped structure.
        let waited = unsafe { WaitForSingleObject(overlapped.hEvent, ms) };
        if waited == WAIT_TIMEOUT {
            // SAFETY: cancel our own request, then wait for it to finish.
            unsafe { CancelIoEx(pipe, overlapped) };
            let mut n = 0;
            unsafe { GetOverlappedResult(pipe, overlapped, &mut n, 1) };
            return Err(io::Error::new(io::ErrorKind::TimedOut, "read timed out"));
        }
        if waited != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let mut n = 0;
        // SAFETY: the operation completed.
        if unsafe { GetOverlappedResult(pipe, overlapped, &mut n, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// An overlapped pipe handle: a read and a write may run at the same time
    /// from two threads (synchronous handles serialize them).
    #[derive(Clone)]
    pub struct Stream {
        pipe: Arc<Owned>,
        server: bool,
        timeout: Arc<std::sync::Mutex<Option<Duration>>>,
    }

    impl Stream {
        pub fn try_clone(&self) -> io::Result<Stream> {
            Ok(self.clone())
        }
        pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            *self.timeout.lock().unwrap() = timeout;
            Ok(())
        }
        pub fn shutdown(&self) {
            // SAFETY: cancels every pending operation on our handle.
            unsafe { CancelIoEx(self.pipe.0, null()) };
            if self.server {
                unsafe { DisconnectNamedPipe(self.pipe.0) };
            }
        }

        /// The pipe's DACL in SDDL (tests check who may open it).
        #[cfg(test)]
        pub fn dacl(&self) -> io::Result<String> {
            use windows_sys::Win32::Security::Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo,
                SE_KERNEL_OBJECT,
            };
            use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
            let mut descriptor = null_mut();
            // SAFETY: our handle; the descriptor is freed with LocalFree.
            let code = unsafe {
                GetSecurityInfo(
                    self.pipe.0,
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut descriptor,
                )
            };
            if code != 0 {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            let descriptor = Descriptor(descriptor);
            let mut text = null_mut();
            let mut len = 0;
            // SAFETY: valid descriptor; the string is freed with LocalFree.
            if unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor.0,
                    SDDL_REVISION_1,
                    DACL_SECURITY_INFORMATION,
                    &mut text,
                    &mut len,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let sddl =
                String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len as usize) });
            unsafe { LocalFree(text.cast()) };
            Ok(sddl.trim_end_matches('\0').to_string())
        }
    }

    impl Read for Stream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let done = event()?;
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            overlapped.hEvent = done.0;
            let len = buf.len().min(u32::MAX as usize) as u32;
            // SAFETY: buf and overlapped outlive the operation (finish waits).
            let started = unsafe {
                ReadFile(
                    self.pipe.0,
                    buf.as_mut_ptr(),
                    len,
                    null_mut(),
                    &mut overlapped,
                )
            };
            let timeout = *self.timeout.lock().unwrap();
            match finish(self.pipe.0, &mut overlapped, started, timeout) {
                // A closed pipe reads as end of stream.
                Err(e) if e.raw_os_error() == Some(109) => Ok(0),
                other => other,
            }
        }
    }

    impl Write for Stream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let done = event()?;
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            overlapped.hEvent = done.0;
            let len = buf.len().min(u32::MAX as usize) as u32;
            // SAFETY: as in read.
            let started =
                unsafe { WriteFile(self.pipe.0, buf.as_ptr(), len, null_mut(), &mut overlapped) };
            finish(self.pipe.0, &mut overlapped, started, None)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// `sddl` as Windows writes it back: a SID that has an alias comes out as
    /// the alias (the built-in Administrator, which GitHub's Windows runners
    /// run as, is "LA"), so tests compare trustees in this form.
    #[cfg(test)]
    pub fn sddl_round_trip(sddl: &str) -> io::Result<String> {
        use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
        use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
        let mut raw = null_mut();
        // SAFETY: NUL-terminated SDDL; the descriptor is freed by Descriptor.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                SDDL_REVISION_1,
                &mut raw,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let descriptor = Descriptor(raw);
        let mut text = null_mut();
        let mut len = 0;
        // SAFETY: valid descriptor; the string is freed with LocalFree.
        if unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                &mut len,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let out =
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len as usize) });
        unsafe { LocalFree(text.cast()) };
        Ok(out.trim_end_matches('\0').to_string())
    }

    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe { LocalFree(self.0) };
        }
    }
    unsafe impl Send for Descriptor {}
    unsafe impl Sync for Descriptor {}

    pub struct Listener {
        name: Vec<u16>,
        descriptor: Descriptor,
        first: AtomicBool,
        stopped: Arc<AtomicBool>,
    }

    /// The pipe's DACL: generic all for the current user, nobody else (no
    /// inherited entries).
    pub fn listen(name: &str) -> io::Result<Listener> {
        let sddl = wide(&format!("D:P(A;;GA;;;{})", current_user_sid()?));
        let mut descriptor = null_mut();
        // SAFETY: valid SDDL string, out pointer.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let listener = Listener {
            name: wide(name),
            descriptor: Descriptor(descriptor),
            first: AtomicBool::new(true),
            stopped: Arc::new(AtomicBool::new(false)),
        };
        Ok(listener)
    }

    impl Listener {
        fn instance(&self) -> io::Result<Owned> {
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.descriptor.0,
                bInheritHandle: 0,
            };
            let first = if self.first.swap(false, Ordering::SeqCst) {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
            // SAFETY: valid name and attributes.
            let pipe = unsafe {
                CreateNamedPipeW(
                    self.name.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | first,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    64 * 1024,
                    64 * 1024,
                    0,
                    &attributes,
                )
            };
            if pipe == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            Ok(Owned(pipe))
        }

        /// Create the first instance now, so a squatter makes this fail at
        /// once (`FILE_FLAG_FIRST_PIPE_INSTANCE`) instead of at the first accept.
        pub fn claim(&self) -> io::Result<Owned2> {
            Ok(Owned2(Some(self.instance()?)))
        }

        pub fn accept_with(&self, waiting: &mut Owned2) -> Option<Stream> {
            loop {
                if self.stopped.load(Ordering::SeqCst) {
                    return None;
                }
                let pipe = match waiting.0.take() {
                    Some(pipe) => pipe,
                    None => match self.instance() {
                        Ok(pipe) => pipe,
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(200));
                            continue;
                        }
                    },
                };
                let done = match event() {
                    Ok(done) => done,
                    Err(_) => return None,
                };
                let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
                overlapped.hEvent = done.0;
                // SAFETY: overlapped connect on our instance.
                let started = unsafe { ConnectNamedPipe(pipe.0, &mut overlapped) };
                let connected = if started == 0 && unsafe { GetLastError() } == ERROR_PIPE_CONNECTED
                {
                    true
                } else {
                    loop {
                        if self.stopped.load(Ordering::SeqCst) {
                            unsafe { CancelIoEx(pipe.0, &overlapped) };
                            let mut n = 0;
                            unsafe { GetOverlappedResult(pipe.0, &overlapped, &mut n, 1) };
                            return None;
                        }
                        match finish_connect(pipe.0, &mut overlapped, started) {
                            Some(result) => break result,
                            None => continue,
                        }
                    }
                };
                if !connected {
                    continue;
                }
                let mut pid = 0;
                // SAFETY: connected pipe, out pointer.
                let ok = unsafe { GetNamedPipeClientProcessId(pipe.0, &mut pid) } != 0;
                if ok && same_user(pid).unwrap_or(false) {
                    return Some(Stream {
                        pipe: Arc::new(pipe),
                        server: true,
                        timeout: Default::default(),
                    });
                }
                unsafe { DisconnectNamedPipe(pipe.0) };
            }
        }

        pub fn stopper(&self) -> Stopper {
            Stopper {
                stopped: self.stopped.clone(),
            }
        }
    }

    /// Waits up to 250 ms; `None` means still waiting (check for stop again).
    fn finish_connect(pipe: HANDLE, overlapped: &mut OVERLAPPED, started: i32) -> Option<bool> {
        if started != 0 {
            return Some(true);
        }
        // SAFETY: as in finish.
        let waited = unsafe { WaitForSingleObject(overlapped.hEvent, 250) };
        if waited == WAIT_TIMEOUT {
            return None;
        }
        let mut n = 0;
        Some(unsafe { GetOverlappedResult(pipe, overlapped, &mut n, 0) } != 0)
    }

    /// The instance a listener holds while it waits for the next client.
    pub struct Owned2(Option<Owned>);

    pub struct Stopper {
        stopped: Arc<AtomicBool>,
    }

    impl Stopper {
        pub fn stop(&self) {
            self.stopped.store(true, Ordering::SeqCst);
        }
    }

    /// Connect to the app; the server process must run as this user.
    pub fn connect(name: &str) -> io::Result<Stream> {
        let name = wide(name);
        // SAFETY: valid name; identification level only.
        let pipe = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                null_mut(),
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let pipe = Owned(pipe);
        let mut pid = 0;
        // SAFETY: connected client handle, out pointer.
        if unsafe { GetNamedPipeServerProcessId(pipe.0, &mut pid) } == 0 || !same_user(pid)? {
            return Err(refused("the endpoint belongs to another user"));
        }
        Ok(Stream {
            pipe: Arc::new(pipe),
            server: false,
            timeout: Default::default(),
        })
    }
}

/// The endpoint for an identity: a socket path or a pipe name.
pub fn endpoint(identity: &crate::identity::Identity) -> io::Result<Endpoint> {
    #[cfg(unix)]
    return identity.socket_path().map(Endpoint);
    #[cfg(windows)]
    return identity.pipe_name().map(Endpoint);
}

#[cfg(unix)]
pub struct Endpoint(pub std::path::PathBuf);
#[cfg(windows)]
pub struct Endpoint(pub String);

impl Endpoint {
    pub fn connect(&self) -> io::Result<Stream> {
        connect(&self.0)
    }
}

/// A listening endpoint and the means to stop it from another thread.
pub struct Server {
    #[cfg(unix)]
    listener: Listener,
    #[cfg(windows)]
    listener: Listener,
    #[cfg(windows)]
    waiting: std::sync::Mutex<Owned2>,
}

impl Server {
    pub fn bind(endpoint: &Endpoint) -> io::Result<Server> {
        #[cfg(unix)]
        return Ok(Server {
            listener: listen(&endpoint.0)?,
        });
        #[cfg(windows)]
        {
            let listener = listen(&endpoint.0)?;
            let waiting = std::sync::Mutex::new(listener.claim()?);
            Ok(Server { listener, waiting })
        }
    }

    pub fn accept(&self) -> Option<Stream> {
        #[cfg(unix)]
        return self.listener.accept();
        #[cfg(windows)]
        return self.listener.accept_with(&mut self.waiting.lock().unwrap());
    }

    pub fn stopper(&self) -> Stopper {
        self.listener.stopper()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn socket_and_folder_are_private_and_a_live_socket_is_never_taken_over() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("run/extension.sock");
        let endpoint = Endpoint(path.clone());
        let server = Server::bind(&endpoint).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            Server::bind(&endpoint).err().unwrap().kind(),
            io::ErrorKind::AddrInUse
        );

        let accepting = std::thread::spawn(move || {
            // The second bind's liveness probe is queued first and sends nothing.
            loop {
                let mut stream = server.accept().unwrap();
                if crate::framing::read_object(&mut stream).is_ok() {
                    crate::framing::write_frame(&mut stream, b"{\"t\":\"hi\"}").unwrap();
                    return server;
                }
            }
        });
        let mut client = endpoint.connect().unwrap();
        crate::framing::write_frame(&mut client, b"{\"t\":\"ping\"}").unwrap();
        assert_eq!(crate::framing::read_object(&mut client).unwrap()["t"], "hi");
        let server = accepting.join().unwrap();
        let stopper = server.stopper();
        stopper.stop();
        assert!(server.accept().is_none());
        assert!(!path.exists(), "the socket is removed when stopped");
        assert!(endpoint.connect().is_err());
    }

    #[test]
    fn stale_sockets_are_replaced_and_strangers_refused() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("run/extension.sock");
        {
            let _stale = Server::bind(&Endpoint(path.clone())).unwrap();
            // Dropped without stop: the file stays, nobody listens.
        }
        assert!(path.exists());
        let server = Server::bind(&Endpoint(path.clone())).unwrap();
        server.stopper().stop();

        let file = root.path().join("run/not-a-socket");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(
            listen(&file).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn a_folder_others_can_enter_is_tightened() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("run");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let server = Server::bind(&Endpoint(dir.join("s"))).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        server.stopper().stop();
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    fn name() -> String {
        let tag = crate::wire::b64(&crate::channel::random::<8>());
        format!(
            r"\\.\pipe\ciphermoth-extension-test-{tag}-{}",
            current_user_sid().unwrap()
        )
    }

    #[test]
    fn only_this_user_may_open_the_pipe_and_nobody_can_squat_it() {
        let endpoint = Endpoint(name());
        let server = Server::bind(&endpoint).unwrap();
        // A second listener on the same name is refused (first instance).
        assert!(Server::bind(&endpoint).is_err());
        let accepting = std::thread::spawn(move || {
            let mut stream = server.accept().unwrap();
            let got = crate::framing::read_object(&mut stream).unwrap();
            crate::framing::write_frame(&mut stream, b"{\"t\":\"hi\"}").unwrap();
            (server, stream, got)
        });
        let mut client = endpoint.connect().unwrap();
        crate::framing::write_frame(&mut client, b"{\"t\":\"ping\"}").unwrap();
        assert_eq!(crate::framing::read_object(&mut client).unwrap()["t"], "hi");
        let (server, stream, got) = accepting.join().unwrap();
        assert_eq!(got["t"], "ping");

        let dacl = stream.dacl().unwrap();
        let sid = current_user_sid().unwrap();
        assert!(
            dacl.starts_with("D:P"),
            "protected, nothing inherited: {dacl}"
        );
        // The one allowed trustee is this user, as Windows writes it (a SID, or
        // "LA" when the tests run as the built-in Administrator).
        let trustee = |sddl: &str| sddl.rsplit(';').next().unwrap_or("").to_string();
        let me = sddl_round_trip(&format!("D:P(A;;GA;;;{sid})")).unwrap();
        assert_eq!(trustee(&dacl), trustee(&me), "{dacl} vs {me}");
        assert!(trustee(&dacl).len() > 1, "{dacl}");
        for other in [";WD)", ";AU)", ";BU)", ";AN)", ";NU)"] {
            assert!(!dacl.contains(other), "{other} in {dacl}");
        }
        assert_eq!(dacl.matches("(A;").count(), 1, "one allow entry: {dacl}");

        server.stopper().stop();
        drop(stream);
    }

    #[test]
    fn reads_and_writes_run_at_the_same_time() {
        let endpoint = Endpoint(name());
        let server = Server::bind(&endpoint).unwrap();
        let accepting = std::thread::spawn(move || (server.accept().unwrap(), server));
        let client = endpoint.connect().unwrap();
        let (served, server) = accepting.join().unwrap();
        // A blocked read must not hold up a write on a clone of the same pipe.
        let mut reader = client.try_clone().unwrap();
        let waiting = std::thread::spawn(move || crate::framing::read_object(&mut reader).unwrap());
        std::thread::sleep(Duration::from_millis(200));
        let mut writer = client.try_clone().unwrap();
        crate::framing::write_frame(&mut writer, b"{\"t\":\"out\"}").unwrap();
        let mut served_reader = served.try_clone().unwrap();
        assert_eq!(
            crate::framing::read_object(&mut served_reader).unwrap()["t"],
            "out"
        );
        let mut served_writer = served.try_clone().unwrap();
        crate::framing::write_frame(&mut served_writer, b"{\"t\":\"back\"}").unwrap();
        assert_eq!(waiting.join().unwrap()["t"], "back");
        // A read timeout ends a read that gets nothing.
        client
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut idle = client.try_clone().unwrap();
        assert!(crate::framing::read_object(&mut idle).is_err());
        server.stopper().stop();
    }
}
