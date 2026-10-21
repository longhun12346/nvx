//! Working-set control of an OpenVMM process. A guest's RAM is ordinary memory of that process,
//! so trimming its working set makes the pages reclaimable by the host. This is a stopgap for a
//! missing balloon device; see `sandbox/doc/nvx_vs_lcow_decision.md`.

use aci_edge_sandboxes::nvx::host::platform::process_start_time;

#[derive(Debug, Clone, Copy)]
pub struct VmmMemory {
    pid: u32,
    start_time: u64,
}

impl VmmMemory {
    pub fn new(pid: u32, start_time: u64) -> Self {
        Self { pid, start_time }
    }

    /// Working set in bytes.
    pub fn working_set(&self) -> Result<u64, String> {
        self.with_process(|process| imp::working_set(process))
    }

    /// Trims the working set; returns it before and after, in bytes.
    pub fn trim(&self) -> Result<(u64, u64), String> {
        self.with_process(|process| {
            let before = imp::working_set(process)?;
            imp::empty_working_set(process)?;
            Ok((before, imp::working_set(process)?))
        })
    }

    fn with_process<T>(
        &self,
        action: impl FnOnce(&imp::Process) -> Result<T, String>,
    ) -> Result<T, String> {
        // A recycled process ID must never be trimmed.
        match process_start_time(self.pid) {
            Ok(Some(started)) if started == self.start_time => {}
            Ok(_) => return Err("the VMM process is gone".into()),
            Err(error) => return Err(error.to_string()),
        }
        action(&imp::Process::open(self.pid)?)
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;

    #[repr(C)]
    struct Counters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        rest: [usize; 6],
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn K32EmptyWorkingSet(process: *mut c_void) -> i32;
        fn K32GetProcessMemoryInfo(process: *mut c_void, counters: *mut Counters, cb: u32) -> i32;
    }

    const PROCESS_SET_QUOTA: u32 = 0x0100;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

    pub struct Process(*mut c_void);

    impl Process {
        pub fn open(pid: u32) -> Result<Self, String> {
            // SAFETY: plain Win32 call; the handle is closed in `Drop`.
            let handle =
                unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION, 0, pid) };
            if handle.is_null() {
                Err(format!(
                    "cannot open process {pid}: {}",
                    std::io::Error::last_os_error()
                ))
            } else {
                Ok(Self(handle))
            }
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            // SAFETY: the handle came from `OpenProcess` and is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    pub fn working_set(process: &Process) -> Result<u64, String> {
        let mut counters = Counters {
            cb: size_of::<Counters>() as u32,
            page_fault_count: 0,
            peak_working_set_size: 0,
            working_set_size: 0,
            rest: [0; 6],
        };
        // SAFETY: `counters` is a correctly sized, writable PROCESS_MEMORY_COUNTERS.
        if unsafe { K32GetProcessMemoryInfo(process.0, &mut counters, counters.cb) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(counters.working_set_size as u64)
    }

    pub fn empty_working_set(process: &Process) -> Result<(), String> {
        // SAFETY: the handle is valid and has PROCESS_SET_QUOTA.
        if unsafe { K32EmptyWorkingSet(process.0) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    pub struct Process;

    impl Process {
        pub fn open(_pid: u32) -> Result<Self, String> {
            Err("working-set control is only implemented on Windows".into())
        }
    }

    pub fn working_set(_process: &Process) -> Result<u64, String> {
        Err("unsupported".into())
    }

    pub fn empty_working_set(_process: &Process) -> Result<(), String> {
        Err("unsupported".into())
    }
}
