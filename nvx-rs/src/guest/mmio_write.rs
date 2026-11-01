//! `nvx-mmio-write ADDRESS VALUE`: stores a 32-bit value at a physical address through
//! `/dev/mem`, as `nvx-virtio-restore-probe` does to kick a virtio queue.

use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::process::ExitCode;

use super::parse::parse_u64;
use super::status::{CommandError, run_main};
use super::sys::{self, Errno, Mode, OpenFlags};

/// Runs `nvx-mmio-write` with the process's arguments. It exits with 0, 1 when an operation
/// fails, or 2 for a usage error, and prints nothing on success.
pub fn main() -> ExitCode {
    run_main(|args| run(args, c"/dev/mem", &mut io::stderr()))
}

/// Validates the command, maps one physical page of `memory`, which stands for `/dev/mem`,
/// stores the value, and releases its resources.
fn run(args: &[CString], memory: &CStr, err: &mut dyn Write) -> Result<(), CommandError> {
    let parsed = match args {
        [_, address, value] => parse_u64(address.as_bytes()).zip(parse_u64(value.as_bytes())),
        _ => None,
    };
    let Some((address, value)) = parsed.filter(|&(_, value)| value <= u64::from(u32::MAX)) else {
        sys::report(err, &[b"usage: nvx-mmio-write ADDRESS VALUE\n"]);
        return Err(CommandError::Usage);
    };
    let value = value as u32;

    let Some(page_size) = sys::page_size() else {
        sys::report(err, &[b"invalid page size\n"]);
        return Err(CommandError::Operation);
    };
    let page_size_u64 = page_size as u64;
    let page_base = address & !(page_size_u64 - 1);
    let page_offset = address - page_base;
    if page_offset > page_size_u64.wrapping_sub(4) {
        sys::report(err, &[b"MMIO write crosses a page boundary\n"]);
        return Err(CommandError::Operation);
    }

    let descriptor = sys::open(memory, OpenFlags::O_RDWR | OpenFlags::O_SYNC, Mode::empty())
        .map_err(|error| perror(err, b"open /dev/mem", error))?;
    let length = NonZeroUsize::new(page_size).expect("a valid page size is nonzero");
    let mut mapping = sys::MemoryMapping::shared_read_write(&descriptor, length, page_base)
        .map_err(|error| perror(err, b"mmap /dev/mem", error))?;
    if !mapping.write_u32(page_offset as usize, value) {
        // The boundary validation above proves this unreachable, but preserve a typed failure if
        // the mapping abstraction and validation ever diverge.
        sys::report(err, &[b"MMIO write crosses a page boundary\n"]);
        return Err(CommandError::Operation);
    }
    mapping
        .unmap()
        .map_err(|error| perror(err, b"munmap /dev/mem", error))?;
    descriptor
        .close()
        .map_err(|error| perror(err, b"close /dev/mem", error))?;
    Ok(())
}

/// Reports `errno` as C's `perror(prefix)` does, with `nix`'s description, and returns the
/// operation failure.
fn perror(err: &mut dyn Write, prefix: &[u8], errno: Errno) -> CommandError {
    sys::report(err, &[prefix, b": ", errno.desc().as_bytes(), b"\n"]);
    CommandError::Operation
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use super::*;
    use crate::guest::status::{ExitStatus, command_line};

    fn page_size() -> u64 {
        sys::page_size().expect("tests need a page size") as u64
    }

    fn mmio_write(memory: &Path, arguments: &[&str]) -> (u8, Vec<u8>) {
        let args = command_line("nvx-mmio-write", arguments);
        let memory = CString::new(memory.as_os_str().as_bytes()).unwrap();
        let mut err = Vec::new();
        let status = ExitStatus::from(run(&args, &memory, &mut err));
        (status as u8, err)
    }

    fn perror_text(prefix: &str, errno: Errno) -> Vec<u8> {
        let mut text = format!("{prefix}: ").into_bytes();
        text.extend_from_slice(errno.desc().as_bytes());
        text.push(b'\n');
        text
    }

    #[test]
    fn usage_requires_an_address_and_a_32_bit_value() {
        let directory = tempfile::tempdir().unwrap();
        let memory = directory.path().join("mem");
        let usage = b"usage: nvx-mmio-write ADDRESS VALUE\n".to_vec();
        for arguments in [
            &[][..],
            &["0x1000"],
            &["0x1000", "1", "2"],
            &["", "1"],
            &["0x1000", ""],
            &["0x", "1"],
            &["08", "1"],
            &["010", "1"],
            &["+1", "1"],
            &[" 1", "1"],
            &["1 ", "1"],
            &["0x1g", "1"],
            &["18446744073709551616", "1"],
            &["0x1000", "4294967296"],
            &["0x1000", "-1"],
        ] {
            assert_eq!(
                mmio_write(&memory, arguments),
                (2, usage.clone()),
                "{arguments:?}"
            );
        }
        assert!(!memory.exists());
    }

    #[test]
    fn refuses_a_store_that_crosses_a_page() {
        let directory = tempfile::tempdir().unwrap();
        let memory = directory.path().join("mem");
        let address = format!("{}", page_size() - 3);
        assert_eq!(
            mmio_write(&memory, &[&address, "1"]),
            (1, b"MMIO write crosses a page boundary\n".to_vec())
        );
    }

    #[test]
    fn stores_the_value_in_native_byte_order() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let page = page_size();
        fs::write(file.path(), vec![0; 2 * page as usize]).unwrap();
        for (address, value, offset) in [
            (format!("{:#x}", page + 4), "0xdeadbeef", page as usize + 4),
            (format!("{:#X}", page + 9), "305419896", page as usize + 9),
            (format!("{}", page - 4), "4294967295", page as usize - 4),
        ] {
            assert_eq!(mmio_write(file.path(), &[&address, value]), (0, Vec::new()));
            let stored = parse_u64(value.as_bytes()).unwrap() as u32;
            let contents = fs::read(file.path()).unwrap();
            assert_eq!(&contents[offset..offset + 4], &stored.to_ne_bytes());
        }
    }

    #[test]
    fn reports_failures_as_perror() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            mmio_write(&directory.path().join("missing"), &["0", "0"]),
            (1, perror_text("open /dev/mem", Errno::ENOENT))
        );
        // A FIFO opens for reading and writing, but has no mmap.
        let fifo = directory.path().join("fifo");
        let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            sys::create_fifo(&path, Mode::S_IRUSR | Mode::S_IWUSR),
            Ok(())
        );
        assert_eq!(
            mmio_write(&fifo, &["0", "0"]),
            (1, perror_text("mmap /dev/mem", Errno::ENODEV))
        );
    }
}
