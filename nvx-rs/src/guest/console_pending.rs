//! `nvx-console-pending DEVICE`: prints the number of bytes waiting to be read from a device, such
//! as a console, which the console-snapshot test reads from `/dev/hvc1`.

use std::ffi::CString;
use std::io::{self, Write};
use std::process::ExitCode;

use super::status::{CommandError, run_main};
use super::sys::{self, Errno, Mode, OpenFlags};

/// Runs `nvx-console-pending` with the process's arguments. It exits with 0, 1 when an operation
/// fails, or 2 for a usage error.
pub fn main() -> ExitCode {
    run_main(|args| run(args, &mut sys::Stdout::new(), &mut io::stderr()))
}

/// Opens the requested device, queries and closes it, and prints its pending byte count.
fn run(args: &[CString], out: &mut dyn Write, err: &mut dyn Write) -> Result<(), CommandError> {
    let [_, device] = args else {
        sys::report(err, &[b"usage: nvx-console-pending DEVICE\n"]);
        return Err(CommandError::Usage);
    };
    let fail = |err: &mut dyn Write, operation: &[u8], errno: Errno| {
        let device = device.as_bytes();
        sys::report(
            err,
            &[
                b"nvx-console-pending: ",
                operation,
                b" ",
                device,
                b": ",
                errno.desc().as_bytes(),
                b"\n",
            ],
        );
        CommandError::Operation
    };

    let flags =
        OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC | OpenFlags::O_NOCTTY | OpenFlags::O_NONBLOCK;
    let descriptor =
        sys::open(device, flags, Mode::empty()).map_err(|error| fail(err, b"open", error))?;
    let pending = sys::console_pending(&descriptor).map_err(|error| fail(err, b"ioctl", error))?;
    descriptor
        .close()
        .map_err(|error| fail(err, b"close", error))?;
    if let Err(errno) = sys::print(out, format!("{pending}\n").as_bytes()) {
        let text = errno.desc().as_bytes();
        sys::report(err, &[b"nvx-console-pending: write: ", text, b"\n"]);
        return Err(CommandError::Operation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    use super::*;
    use crate::guest::status::{ExitStatus, command_line};
    use crate::guest::sys::tests::Failing;

    fn console_pending(arguments: &[&[u8]]) -> (u8, Vec<u8>, Vec<u8>) {
        let args = command_line("nvx-console-pending", arguments);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = ExitStatus::from(run(&args, &mut out, &mut err));
        (status as u8, out, err)
    }

    fn message(operation: &str, path: &Path, errno: Errno) -> Vec<u8> {
        let mut message = format!("nvx-console-pending: {operation} ").into_bytes();
        message.extend_from_slice(path.as_os_str().as_bytes());
        message.extend_from_slice(b": ");
        message.extend_from_slice(errno.desc().as_bytes());
        message.push(b'\n');
        message
    }

    #[test]
    fn usage_takes_exactly_one_device() {
        let usage = b"usage: nvx-console-pending DEVICE\n".to_vec();
        for arguments in [&[][..], &[&b"a"[..], b"b"]] {
            assert_eq!(console_pending(arguments), (2, Vec::new(), usage.clone()));
        }
    }

    #[test]
    fn prints_the_bytes_waiting_in_a_fifo() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("console");
        let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            sys::create_fifo(&path, Mode::S_IRUSR | Mode::S_IWUSR),
            Ok(())
        );
        let path = fifo.as_os_str().as_bytes();
        assert_eq!(console_pending(&[path]), (0, b"0\n".to_vec(), Vec::new()));

        // Opening a FIFO's reader without blocking lets the writer open it. The reader stays
        // open until the test ends, so the FIFO keeps the bytes.
        let _reader = fs::File::options()
            .read(true)
            .custom_flags(OpenFlags::O_NONBLOCK.bits())
            .open(&fifo)
            .unwrap();
        fs::write(&fifo, b"twelve bytes").unwrap();
        assert_eq!(console_pending(&[path]), (0, b"12\n".to_vec(), Vec::new()));
    }

    #[test]
    fn prints_the_unread_size_of_a_regular_file() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), b"12345").unwrap();
        let path = file.path().as_os_str().as_bytes();
        assert_eq!(console_pending(&[path]), (0, b"5\n".to_vec(), Vec::new()));
    }

    #[test]
    fn reports_failures_with_the_errno_description() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing");
        assert_eq!(
            console_pending(&[missing.as_os_str().as_bytes()]),
            (1, Vec::new(), message("open", &missing, Errno::ENOENT))
        );
        // A directory opens, but has no FIONREAD.
        assert_eq!(
            console_pending(&[directory.path().as_os_str().as_bytes()]),
            (
                1,
                Vec::new(),
                message("ioctl", directory.path(), Errno::ENOTTY)
            )
        );
    }

    #[test]
    fn reports_a_failed_write() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let args = command_line("nvx-console-pending", &[file.path().as_os_str().as_bytes()]);
        let mut err = Vec::new();
        assert_eq!(
            ExitStatus::from(run(&args, &mut Failing(Errno::EIO), &mut err)),
            ExitStatus::Failure
        );
        let mut expected = b"nvx-console-pending: write: ".to_vec();
        expected.extend_from_slice(Errno::EIO.desc().as_bytes());
        expected.push(b'\n');
        assert_eq!(err, expected);
    }
}
