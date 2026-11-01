//! `nvx-exit [CODE]`: stops the VM with an 8-bit exit code, by writing one byte to OpenVMM's
//! control port 0x604 through `/dev/port`.
//!
//! CODE defaults to 1, and so does anything other than a decimal number from 0 through 255.
//! Further arguments are ignored, and the program prints nothing. It exits with 1 when it cannot
//! write the byte.

use std::ffi::{CStr, CString};
use std::process::ExitCode;

use super::status::{CommandError, run_main};
use super::sys::{self, Mode, OpenFlags, PORT_DEVICE, Port};

/// Runs `nvx-exit` with the process's arguments. It exits with 0 after it writes the byte,
/// unless the VM stops first, or with 1 when it cannot write the byte.
pub fn main() -> ExitCode {
    run_main(|args| run(args, PORT_DEVICE))
}

/// Writes the selected exit code through `port`, which stands for `/dev/port`.
///
/// Any failure to open the device or write the byte is an operation failure, which the program
/// does not report. The descriptor closes when the write returns, whereas the C program left it
/// open until the process exited; neither the output nor the status differs.
fn run(args: &[CString], port: &CStr) -> Result<(), CommandError> {
    let code = exit_code(args.get(1).map(|argument| argument.as_bytes()));
    let written = sys::open(port, OpenFlags::O_WRONLY, Mode::empty())
        .and_then(|descriptor| descriptor.pwrite(&[code], Port::Control.offset()));
    if written == Ok(1) {
        Ok(())
    } else {
        Err(CommandError::Operation)
    }
}

/// Returns the VM exit code that `argument` selects.
///
/// A nonempty decimal number from 0 through 255 is accepted, including leading zeros. A missing
/// or empty argument, a sign, whitespace, any other character, or a larger value selects 1, as in
/// the C program. Rust's `u8::from_str` also accepts a leading `+`, so the program keeps its own
/// parser.
fn exit_code(argument: Option<&[u8]>) -> u8 {
    let Some(argument) = argument else {
        return 1;
    };
    let mut value = 0_u32;
    for &byte in argument {
        if !byte.is_ascii_digit() {
            return 1;
        }
        // The function returns as soon as the value exceeds 255, so this cannot overflow.
        value = value * 10 + u32::from(byte - b'0');
        if value > 255 {
            return 1;
        }
    }
    if argument.is_empty() { 1 } else { value as u8 }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStrExt;

    use super::*;
    use crate::guest::status::{ExitStatus, command_line};

    /// Returns the command line of `nvx-exit` with `arguments`.
    fn args(arguments: &[&[u8]]) -> Vec<CString> {
        command_line("nvx-exit", arguments)
    }

    #[test]
    fn exit_code_takes_a_decimal_number_up_to_255() {
        let cases: &[(&[&[u8]], u8)] = &[
            (&[], 1),
            (&[b""], 1),
            (&[b"0"], 0),
            (&[b"37"], 37),
            (&[b"255"], 255),
            (&[b"256"], 1),
            (&[b"-1"], 1),
            (&[b"+5"], 1),
            (&[b" 7"], 1),
            (&[b"7 "], 1),
            (&[b"12a"], 1),
            (&[b"0x10"], 1),
            (&[b"99999999999999999999"], 1),
            (&[b"4294967296"], 1),
            (&[b"4294967551"], 1),
            (&[b"00000000000000000255"], 255),
            (&[b"010"], 10),
            (&[b"7", b"9"], 7),
        ];
        for &(arguments, expected) in cases {
            let args = args(arguments);
            let code = exit_code(args.get(1).map(|argument| argument.as_bytes()));
            assert_eq!(code, expected, "{arguments:?}");
        }
    }

    #[test]
    fn writes_one_byte_at_the_control_port() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let port = CString::new(file.path().as_os_str().as_bytes()).unwrap();
        let status = ExitStatus::from(run(&args(&[b"37", b"extra"]), &port));
        assert_eq!(status, ExitStatus::Success);
        let control = Port::Control.offset() as usize;
        let mut expected = vec![0; control];
        expected.push(37);
        assert_eq!(fs::read(file.path()).unwrap(), expected);
        assert_eq!(
            ExitStatus::from(run(&args(&[]), &port)),
            ExitStatus::Success
        );
        expected[control] = 1;
        assert_eq!(fs::read(file.path()).unwrap(), expected);
    }

    #[test]
    fn fails_when_it_cannot_open_or_write_the_device() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("port");
        let missing = CString::new(missing.as_os_str().as_bytes()).unwrap();
        for port in [missing.as_c_str(), c"/dev/full"] {
            let status = ExitStatus::from(run(&args(&[b"0"]), port));
            assert_eq!(status, ExitStatus::Failure, "{port:?}");
        }
    }
}
