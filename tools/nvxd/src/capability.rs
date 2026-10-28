//! Whether this machine can boot the microVM at all, found out by booting a small one once and
//! remembered across runs.
//!
//! Static checks (the hypervisor platform is installed, the files exist) cannot see the failures
//! that matter in practice: a platform build that terminates the VMM, a guest CPU model the
//! hypervisor refuses. A real boot can. The verdict is keyed by a fingerprint of everything that
//! could change it, so a repeat start on the same machine costs one file read.

use serde_json::Value;
use serde_json::json;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Condvar;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// A machine that booted the probe VM stays capable until its fingerprint changes.
const CAPABLE_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
/// A machine that did not is tried again soon: the cause may be transient, such as memory
/// pressure at that moment.
const INCAPABLE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Debug)]
pub enum Verdict {
    Capable,
    Incapable { code: String, message: String },
}

#[derive(Clone)]
enum State {
    Idle,
    Running,
    Done(Verdict, SystemTime),
}

pub struct Capability {
    cache: Option<PathBuf>,
    fingerprint: String,
    state: Mutex<State>,
    changed: Condvar,
}

impl Capability {
    pub fn new(cache: Option<PathBuf>, fingerprint: String) -> Self {
        Self {
            cache,
            fingerprint,
            state: Mutex::new(State::Idle),
            changed: Condvar::new(),
        }
    }

    /// Returns the verdict, running `check` (a real boot) if there is none yet. While another
    /// thread is checking, waits for it: at most `wait`, or without limit for `None`. Returns
    /// `None` if the wait ran out.
    pub fn resolve(
        &self,
        wait: Option<Duration>,
        check: &dyn Fn() -> Result<(), (String, String)>,
    ) -> Option<Verdict> {
        let deadline = wait.map(|wait| Instant::now() + wait);
        let mut state = self.state.lock().unwrap();
        loop {
            match &*state {
                State::Done(verdict, at) => {
                    let expired = matches!(verdict, Verdict::Incapable { .. })
                        && at.elapsed().is_ok_and(|age| age >= INCAPABLE_TTL);
                    if !expired {
                        return Some(verdict.clone());
                    }
                    *state = State::Idle;
                }
                State::Running => {
                    state = match deadline {
                        None => self.changed.wait(state).unwrap(),
                        Some(deadline) => {
                            let left = deadline.saturating_duration_since(Instant::now());
                            if left.is_zero() {
                                return None;
                            }
                            self.changed.wait_timeout(state, left).unwrap().0
                        }
                    };
                }
                State::Idle => {
                    *state = State::Running;
                    drop(state);
                    let verdict = self.cached().unwrap_or_else(|| {
                        let verdict = match check() {
                            Ok(()) => Verdict::Capable,
                            Err((code, message)) => Verdict::Incapable { code, message },
                        };
                        self.store(&verdict);
                        verdict
                    });
                    let mut state = self.state.lock().unwrap();
                    *state = State::Done(verdict.clone(), SystemTime::now());
                    self.changed.notify_all();
                    return Some(verdict);
                }
            }
        }
    }

    fn cached(&self) -> Option<Verdict> {
        let text = std::fs::read_to_string(self.cache.as_ref()?).ok()?;
        let entry: Value = serde_json::from_str(&text).ok()?;
        if entry.get("fingerprint")?.as_str()? != self.fingerprint {
            return None;
        }
        let at = UNIX_EPOCH + Duration::from_secs(entry.get("at")?.as_u64()?);
        let age = SystemTime::now().duration_since(at).ok()?;
        if entry.get("capable")?.as_bool()? {
            (age < CAPABLE_TTL).then_some(Verdict::Capable)
        } else {
            (age < INCAPABLE_TTL).then(|| Verdict::Incapable {
                code: entry["code"].as_str().unwrap_or("").to_owned(),
                message: entry["message"].as_str().unwrap_or("").to_owned(),
            })
        }
    }

    fn store(&self, verdict: &Verdict) {
        let Some(path) = &self.cache else { return };
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |age| age.as_secs());
        let entry = match verdict {
            Verdict::Capable => json!({"fingerprint": self.fingerprint, "at": at, "capable": true}),
            Verdict::Incapable { code, message } => json!({
                "fingerprint": self.fingerprint, "at": at, "capable": false,
                "code": code, "message": message,
            }),
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Written beside the target and renamed, so a reader never sees half a file.
        let temporary = path.with_extension(format!("tmp{}", std::process::id()));
        if std::fs::write(&temporary, entry.to_string()).is_ok()
            && std::fs::rename(&temporary, path).is_err()
        {
            let _ = std::fs::remove_file(&temporary);
        }
    }
}

/// What a file looked like: size and modification time, which change whenever it is replaced.
fn stamp(path: &Path) -> String {
    match std::fs::metadata(path) {
        Ok(metadata) => {
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |age| age.as_secs());
            format!("{}:{}:{}", path.display(), metadata.len(), modified)
        }
        Err(_) => format!("{}:missing", path.display()),
    }
}

/// Everything that decides whether a VM can boot here: the files that boot it, the platform
/// libraries it runs on, the CPU, and the settings that shape the VM. The first artifact must be
/// the VMM, whose directory may hold the helper executable that its behaviour depends on.
pub fn fingerprint(artifacts: &[&Path], settings: &str) -> String {
    let mut parts: Vec<String> = artifacts.iter().map(|path| stamp(path)).collect();
    if let Some(directory) = artifacts.first().and_then(|path| path.parent()) {
        parts.push(stamp(&directory.join("whp-legacy-cpuid-probe.exe")));
    }
    let system = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    for library in ["WinHvPlatform.dll", "ntdll.dll"] {
        parts.push(stamp(&system.join("System32").join(library)));
    }
    parts.push(cpu_brand());
    parts.push(settings.to_owned());
    parts.push(env!("CARGO_PKG_VERSION").to_owned());
    parts.join("|")
}

#[cfg(target_arch = "x86_64")]
fn cpu_brand() -> String {
    use std::arch::x86_64::__cpuid;
    if __cpuid(0x8000_0000).eax < 0x8000_0004 {
        return "cpu:unknown".to_owned();
    }
    let mut bytes = Vec::with_capacity(48);
    for leaf in 0x8000_0002..=0x8000_0004 {
        let registers = __cpuid(leaf);
        for value in [registers.eax, registers.ebx, registers.ecx, registers.edx] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    let brand = String::from_utf8_lossy(&bytes);
    format!("cpu:{}", brand.trim_end_matches('\0').trim())
}

#[cfg(not(target_arch = "x86_64"))]
fn cpu_brand() -> String {
    "cpu:unknown".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    fn temporary(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("nvxd-capability-{}-{name}.json", std::process::id()))
    }

    fn counted(runs: &AtomicUsize) -> impl Fn() -> Result<(), (String, String)> + '_ {
        move || {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn a_verdict_is_remembered_across_instances() {
        let path = temporary("remembered");
        let _ = std::fs::remove_file(&path);
        let runs = AtomicUsize::new(0);
        let first = Capability::new(Some(path.clone()), "machine-a".into());
        assert!(matches!(first.resolve(None, &counted(&runs)), Some(Verdict::Capable)));
        let second = Capability::new(Some(path.clone()), "machine-a".into());
        assert!(matches!(second.resolve(None, &counted(&runs)), Some(Verdict::Capable)));
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_different_fingerprint_checks_again() {
        let path = temporary("fingerprint");
        let _ = std::fs::remove_file(&path);
        let runs = AtomicUsize::new(0);
        Capability::new(Some(path.clone()), "machine-a".into()).resolve(None, &counted(&runs));
        Capability::new(Some(path.clone()), "machine-b".into()).resolve(None, &counted(&runs));
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_failure_keeps_its_code_and_is_remembered() {
        let path = temporary("failure");
        let _ = std::fs::remove_file(&path);
        let failing = || Err(("E_BACKEND_START_VMM_EXIT".to_owned(), "vmm exited".to_owned()));
        let first = Capability::new(Some(path.clone()), "m".into());
        let Some(Verdict::Incapable { code, message }) = first.resolve(None, &failing) else {
            panic!("expected a failure");
        };
        assert_eq!((code.as_str(), message.as_str()), ("E_BACKEND_START_VMM_EXIT", "vmm exited"));
        let unreachable = || -> Result<(), (String, String)> { panic!("should use the cache") };
        let second = Capability::new(Some(path.clone()), "m".into());
        assert!(matches!(
            second.resolve(None, &unreachable),
            Some(Verdict::Incapable { .. })
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn waiting_for_a_running_check_gives_up_after_the_wait() {
        let capability = Arc::new(Capability::new(None, "m".into()));
        let (started, running) = std::sync::mpsc::channel::<()>();
        let (go, wait_for_go) = std::sync::mpsc::channel::<()>();
        let runner = {
            let capability = Arc::clone(&capability);
            std::thread::spawn(move || {
                capability.resolve(None, &|| {
                    started.send(()).unwrap();
                    wait_for_go.recv().unwrap();
                    Ok(())
                })
            })
        };
        running.recv().unwrap();
        let never = || -> Result<(), (String, String)> { panic!("a second check must not start") };
        assert!(capability.resolve(Some(Duration::from_millis(30)), &never).is_none());
        go.send(()).unwrap();
        assert!(matches!(runner.join().unwrap(), Some(Verdict::Capable)));
        assert!(matches!(
            capability.resolve(Some(Duration::ZERO), &never),
            Some(Verdict::Capable)
        ));
    }
}
