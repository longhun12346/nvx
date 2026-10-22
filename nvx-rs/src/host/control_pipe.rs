//! The launcher's end of the export control channel, as a named pipe server.
//!
//! OpenVMM connects to this pipe as a client when it is started with
//! `--microvm-virtiofs-control name=<pipe>`. A pipe rather than an inherited handle
//! because the launcher cannot hold a handle for the VM's whole life without
//! changing `Instance`'s derives; a name is an ordinary string and each request
//! opens the pipe only for as long as it takes to exchange one frame.
//!
//! Security rests on three layers, none of which is the name: the pipe's default
//! security descriptor limits connects to the creating user, remote clients are
//! rejected by the pipe type, and every request carries a VM generation and a
//! strictly increasing sequence number, so a recorded request replayed later is
//! refused by the receiver.

#![cfg(windows)]

use std::io;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::os::windows::io::RawHandle;

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::ERROR_NO_DATA;
use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_FIRST_PIPE_INSTANCE;
use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
use windows_sys::Win32::System::Pipes::CreateNamedPipeW;
use windows_sys::Win32::System::Pipes::DisconnectNamedPipe;
use windows_sys::Win32::System::Pipes::PIPE_READMODE_BYTE;
use windows_sys::Win32::System::Pipes::PIPE_REJECT_REMOTE_CLIENTS;
use windows_sys::Win32::System::Pipes::PIPE_TYPE_BYTE;
use windows_sys::Win32::System::Pipes::PIPE_WAIT;

/// A pipe server running on its own thread, serving `handle` for each client.
///
/// The launcher needs the name *before* it starts the VMM (the name goes on the
/// command line) but must not block on the client, which is the VMM and has not
/// started yet. So the accept loop runs here, and the caller is handed only the
/// name plus a handle it can wait on or abandon.
pub struct Server {
    name: String,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    /// The pipe name to put on the VMM's command line.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Waits for the accept loop to finish, which happens when it stops accepting.
    pub fn join(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Creates the pipe for `nonce` and serves one connection per request until the
/// VMM stops connecting.
///
/// `handle` receives the connected pipe; it must not block for long, because the
/// next client cannot connect until it returns.
#[cfg(windows)]
pub fn serve<F>(nonce: u64, mut handle: F) -> std::io::Result<Server>
where
    F: FnMut(&mut std::fs::File) + Send + 'static,
{
    let name = crate::host::live_control::pipe_name(nonce);
    // Create the pipe on this thread first, so a creation failure is reported to the
    // caller instead of being lost inside the thread.
    let first = accept_one(&name)?;
    let served_name = name.clone();
    let thread = std::thread::Builder::new()
        .name("nvx-control-pipe".into())
        .spawn(move || {
            let mut connected = Some(first);
            loop {
                let Some(mut current) = connected.take() else {
                    break;
                };
                handle(&mut current.pipe);
                // A fresh instance serves the next client; the previous one is closed
                // when `current` is dropped.
                match accept_next(&served_name) {
                    Ok(next) => connected = Some(next),
                    Err(_) => break,
                }
            }
        })?;
    let server_name = name;
    Ok(Server {
        name: server_name,
        thread: Some(thread),
    })
}
pub struct Connected {
    /// The connected server end, used to exchange frames.
    pub pipe: std::fs::File,
    /// The pipe's full path, as the VMM was told to connect to it.
    pub name: String,
}

fn wide(name: &str) -> Vec<u16> {
    std::os::windows::ffi::OsStrExt::encode_wide(std::ffi::OsStr::new(name))
        .chain([0])
        .collect()
}

/// Creates `name` and waits for the VMM to connect.
///
/// `FILE_FLAG_FIRST_PIPE_INSTANCE` makes a name collision fail loudly instead of
/// silently attaching to another VM's pipe, and the one-instance limit means a
/// second client cannot interleave frames with the first.
pub fn accept_one(name: &str) -> io::Result<Connected> {
    accept(name, true)
}

/// Accepts another client on a pipe whose first instance already exists.
///
/// `FILE_FLAG_FIRST_PIPE_INSTANCE` is only legal on the first instance, so a server
/// that keeps serving has to drop it; the name is already known to be ours.
fn accept_next(name: &str) -> io::Result<Connected> {
    accept(name, false)
}

fn accept(name: &str, first_instance: bool) -> io::Result<Connected> {
    let wide_name = wide(name);
    let mut open_mode = PIPE_ACCESS_DUPLEX;
    if first_instance {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    // SAFETY: the name is NUL-terminated, and a null security descriptor asks for
    // the process default, which admits this user and administrators only.
    let handle = unsafe {
        CreateNamedPipeW(
            wide_name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65_536,
            65_536,
            0,
            std::ptr::null(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the handle is a fresh pipe instance that nothing else owns.
    let mut pipe = std::fs::File::from(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) });
    let server = pipe.as_raw_handle() as HANDLE;
    loop {
        // SAFETY: the handle is this pipe's server end; a null OVERLAPPED waits.
        if unsafe { ConnectNamedPipe(server, std::ptr::null_mut()) } == 0 {
            // SAFETY: GetLastError has no preconditions.
            let error = unsafe { GetLastError() };
            match error {
                // Already connected before the call: that is success.
                ERROR_PIPE_CONNECTED => {}
                // The client gave up before the connection was accepted.
                ERROR_NO_DATA => {
                    // SAFETY: the handle is a pipe server instance.
                    unsafe { DisconnectNamedPipe(server) };
                    continue;
                }
                other => return Err(io::Error::from_raw_os_error(other as i32)),
            }
        }
        break;
    }
    Ok(Connected {
        pipe,
        name: name.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::control::{self, Mode, Operation, Request};
    use std::io::Write;

    fn request() -> Request {
        Request {
            generation: 5,
            sequence: 1,
            session: "s".to_owned(),
            mount_id: "/workspace/mounts/refs".to_owned(),
            child: "mount0".to_owned(),
            operation: Operation::Add,
            mode: Mode::ReadOnly,
            host_path: "C:\\refs".to_owned(),
        }
    }

    #[test]
    fn a_frame_survives_a_real_pipe() {
        let name = crate::host::live_control::pipe_name(0xfeed_face_dead_beef);
        let server = std::thread::spawn({
            let name = name.clone();
            move || {
                let mut connected = accept_one(&name).expect("accept");
                // One request in, one reply out: the shape the VMM serves.
                let mut length = [0u8; 4];
                std::io::Read::read_exact(&mut connected.pipe, &mut length).expect("length");
                let length = u32::from_le_bytes(length) as usize;
                let mut payload = vec![0u8; length];
                std::io::Read::read_exact(&mut connected.pipe, &mut payload).expect("payload");
                let reply = b"ok\n";
                let mut frame = (reply.len() as u32).to_le_bytes().to_vec();
                frame.extend_from_slice(reply);
                connected.pipe.write_all(&frame).expect("reply");
                String::from_utf8(payload).expect("utf-8")
            }
        });

        // The client end, exactly as OpenVMM connects.
        let mut client = None;
        for _ in 0..50 {
            match std::fs::OpenOptions::new().read(true).write(true).open(&name) {
                Ok(file) => {
                    client = Some(file);
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        let mut client = client.expect("the pipe must accept a client");
        control::exchange(&mut client, &request()).expect("exchange");
        client.flush().expect("flush");

        let sent = server.join().expect("server thread");
        assert_eq!(sent, control::encode_request(&request()));
    }
}
