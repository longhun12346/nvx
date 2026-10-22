//! Persistent per-sandbox state of the OpenVMM backend.
//!
//! ```text
//! <state_root>/
//!   .locks/<token>.lock       serializes lifecycle transitions of one sandbox
//!   <token>/
//!     sandbox.json            provisioned configuration
//!     launch.json             endpoint and available process identity of a start in progress
//!     runtime.json            OpenVMM process identity and endpoint (running only)
//!     control.capability      launch capability (running only)
//!     control.sock            Linux control endpoint (running only)
//!     openvmm.log             OpenVMM output of the latest start
//!     outcome.json            OpenVMM outcome report of the latest run
//! ```
//!
//! Each sandbox's directory is the directory of its VM [`Instance`], which keeps every file but
//! `sandbox.json`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use nvx::host::filesystem::ExportPlan;
use nvx::host::instance::{self, Instance, LockGuard};
use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorCode, Result};
use crate::id::SandboxId;
use crate::model::{HostLoopbackForward, NetworkPolicy};

/// Version of the state files written by this crate, which records the instance's export plan.
pub(crate) const STATE_FORMAT: u32 = instance::STATE_FORMAT;
/// Backend key recorded in every sandbox.
pub(crate) const BACKEND_KEY: &str = "openvmm";

const RECORD_NAME: &str = "sandbox.json";
const LOCKS_NAME: &str = ".locks";

/// Provisioned configuration of one sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SandboxRecord {
    pub(crate) format: u32,
    pub(crate) backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) network: Option<NetworkPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) filesystem: Option<ExportPlan>,
    /// Host loopback ports that OpenVMM forwards to guest ports. A record without forwards keeps
    /// the form of earlier records, and earlier versions of this crate refuse one with forwards.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) host_loopback_forwards: Vec<HostLoopbackForward>,
    pub(crate) memory_mib: u32,
    pub(crate) workload_uid: u32,
    pub(crate) workload_gid: u32,
    /// Whether the guest creates an account for the workload identity if its image lacks a usable
    /// one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) create_workload_account: bool,
    pub(crate) hostname: String,
}

/// Directory tree that holds every sandbox of one backend instance.
#[derive(Debug)]
pub(crate) struct StateStore {
    root: PathBuf,
}

fn io_error(context: String) -> impl FnOnce(io::Error) -> Error {
    move |error| Error::backend_error(context).with_source(error)
}

fn not_provisioned(sandbox_id: &SandboxId) -> Error {
    Error::stale_id(format!("sandbox {sandbox_id} is not provisioned"))
}

impl StateStore {
    /// Opens `root`, creating it and restricting it to the current user if needed.
    pub(crate) fn open(root: &Path) -> io::Result<Self> {
        if let Some(parent) = root.parent() {
            fs::create_dir_all(parent)?;
        }
        instance::create_private_dir(root)?;
        instance::create_private_dir(&root.join(LOCKS_NAME))?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub(crate) fn dir(&self, sandbox_id: &SandboxId) -> PathBuf {
        self.root.join(sandbox_id.token())
    }

    /// Returns the VM instance of a sandbox, which messages call by the sandbox's ID.
    pub(crate) fn instance(&self, sandbox_id: &SandboxId) -> Instance {
        Instance::new(self.dir(sandbox_id), sandbox_id.to_string())
    }

    fn lock_path(&self, sandbox_id: &SandboxId) -> PathBuf {
        self.root
            .join(LOCKS_NAME)
            .join(format!("{}.lock", sandbox_id.token()))
    }

    /// Takes the exclusive lifecycle lock of a sandbox and loads its configuration.
    ///
    /// An ID without state fails with [`ErrorCode::StaleId`] and leaves no lock file behind, also
    /// when its state disappears while this call waits for the lock, as it does when a
    /// concurrent deprovision removes it. A stale ID never becomes valid again, so no other call
    /// can still need the removed lock file.
    pub(crate) fn lock_and_load(
        &self,
        sandbox_id: &SandboxId,
    ) -> Result<(LockGuard, SandboxRecord)> {
        if matches!(self.dir(sandbox_id).try_exists(), Ok(false)) {
            return Err(not_provisioned(sandbox_id));
        }
        let guard = instance::lock(&self.lock_path(sandbox_id))?;
        match self.load(sandbox_id) {
            Ok(record) => Ok((guard, record)),
            Err(error) if error.code() == ErrorCode::StaleId => {
                drop(guard);
                self.remove_lock(sandbox_id);
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    /// Removes the lock file of a deprovisioned sandbox.
    pub(crate) fn remove_lock(&self, sandbox_id: &SandboxId) {
        let _ = fs::remove_file(self.lock_path(sandbox_id));
    }

    /// Creates the state directory of a new sandbox.
    pub(crate) fn create(&self, sandbox_id: &SandboxId, record: &SandboxRecord) -> Result<()> {
        let dir = self.dir(sandbox_id);
        fs::create_dir(&dir).map_err(io_error(format!(
            "cannot create sandbox state {}",
            dir.display()
        )))?;
        let created = instance::create_private_dir(&dir)
            .map_err(io_error(format!(
                "cannot restrict sandbox state {}",
                dir.display()
            )))
            .and_then(|()| Ok(instance::write_json(&dir.join(RECORD_NAME), record)?));
        if created.is_err() {
            let _ = fs::remove_dir_all(&dir);
        }
        created
    }

    /// Loads the configuration of a provisioned sandbox.
    pub(crate) fn load(&self, sandbox_id: &SandboxId) -> Result<SandboxRecord> {
        let path = self.dir(sandbox_id).join(RECORD_NAME);
        // Records of other formats have other fields, so their format is checked first.
        let record: serde_json::Value = match instance::read_json(&path)? {
            Some(record) => record,
            None => return Err(not_provisioned(sandbox_id)),
        };
        if record.get("format").and_then(serde_json::Value::as_u64) != Some(STATE_FORMAT.into())
            || record.get("backend").and_then(serde_json::Value::as_str) != Some(BACKEND_KEY)
        {
            return Err(Error::backend_error(format!(
                "sandbox state {} has an unsupported format",
                path.display()
            )));
        }
        serde_json::from_value(record).map_err(|error| {
            Error::backend_error(format!("sandbox state {} is malformed", path.display()))
                .with_source(error)
        })
    }

    /// Deletes the state of a stopped sandbox.
    ///
    /// Unknown files abort the removal before anything is deleted. The configuration is removed
    /// last, so an interrupted removal leaves a sandbox that can be deprovisioned again.
    pub(crate) fn remove(&self, sandbox_id: &SandboxId) -> Result<()> {
        let dir = self.dir(sandbox_id);
        let entries = fs::read_dir(&dir).map_err(io_error(format!(
            "cannot list sandbox state {}",
            dir.display()
        )))?;
        let mut owned = Vec::new();
        for entry in entries {
            let entry = entry.map_err(io_error(format!(
                "cannot list sandbox state {}",
                dir.display()
            )))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let temporary = name.starts_with('.') && name.ends_with(".tmp");
            if instance::FILE_NAMES.contains(&name.as_ref()) || temporary {
                owned.push(entry.path());
            } else if name != RECORD_NAME {
                return Err(Error::backend_error(format!(
                    "sandbox state {} contains the unexpected entry {name:?}; remove it and retry",
                    dir.display()
                )));
            }
        }
        for path in owned {
            instance::remove_if_present(&path)?;
        }
        instance::remove_if_present(&dir.join(RECORD_NAME))?;
        fs::remove_dir(&dir).map_err(io_error(format!(
            "cannot remove sandbox state {}",
            dir.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use nvx::host::instance::{LaunchRecord, ProcessIdentity, RuntimeRecord};
    use nvx::protocol::CAPABILITY_LEN;

    use super::*;
    use crate::ErrorCode;

    fn record() -> SandboxRecord {
        SandboxRecord {
            format: STATE_FORMAT,
            backend: BACKEND_KEY.to_owned(),
            network: None,
            filesystem: None,
            host_loopback_forwards: Vec::new(),
            memory_mib: 256,
            workload_uid: 65534,
            workload_gid: 65534,
            create_workload_account: false,
            hostname: "nvx-sandbox".to_owned(),
        }
    }

    #[test]
    fn records_round_trip_and_unknown_ids_are_stale() {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::open(&root.path().join("sandboxes")).unwrap();
        let id = SandboxId::generate().unwrap();
        assert_eq!(store.load(&id).unwrap_err().code(), ErrorCode::StaleId);
        store.create(&id, &record()).unwrap();
        assert_eq!(store.load(&id).unwrap(), record());
        assert!(store.instance(&id).runtime().unwrap().is_none());
    }

    #[test]
    fn runtime_files_are_cleared_and_state_removed() {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::open(root.path()).unwrap();
        let id = SandboxId::generate().unwrap();
        store.create(&id, &record()).unwrap();
        let instance = store.instance(&id);
        assert!(instance.launch().unwrap().is_none());
        let launch = LaunchRecord {
            format: STATE_FORMAT,
            endpoint: "endpoint".to_owned(),
            process: None,
        };
        instance.write_launch(&launch).unwrap();
        assert_eq!(instance.launch().unwrap(), Some(launch.clone()));
        let identified = LaunchRecord {
            process: Some(ProcessIdentity {
                pid: 1,
                start_time: 2,
            }),
            ..launch.clone()
        };
        instance.write_launch(&identified).unwrap();
        assert_eq!(instance.launch().unwrap(), Some(identified));
        instance.remove_launch();
        assert!(instance.launch().unwrap().is_none());
        instance.write_launch(&launch).unwrap();
        let runtime = RuntimeRecord {
            format: STATE_FORMAT,
            pid: 1,
            start_time: 2,
            endpoint: "endpoint".to_owned(),
            export_pipe: None,
        };
        instance.write_runtime(&runtime).unwrap();
        instance.write_capability(&[9; CAPABILITY_LEN]).unwrap();
        assert_eq!(instance.runtime().unwrap(), Some(runtime));
        assert_eq!(instance.read_capability().unwrap(), [9; CAPABILITY_LEN]);
        instance.clear_runtime().unwrap();
        assert!(instance.runtime().unwrap().is_none());
        assert!(instance.launch().unwrap().is_none());
        assert!(instance.read_capability().is_err());
        drop(instance.create_log().unwrap());
        store.remove(&id).unwrap();
        assert!(!store.dir(&id).exists());
    }

    #[test]
    fn removal_preserves_unknown_files_and_the_sandbox() {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::open(root.path()).unwrap();
        let id = SandboxId::generate().unwrap();
        store.create(&id, &record()).unwrap();
        fs::write(store.dir(&id).join("keep.txt"), b"user data").unwrap();
        assert!(store.remove(&id).is_err());
        assert!(store.dir(&id).join("keep.txt").exists());
        assert_eq!(store.load(&id).unwrap(), record());
    }

    #[test]
    fn records_of_other_formats_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::open(root.path()).unwrap();
        let id = SandboxId::generate().unwrap();
        store.create(&id, &record()).unwrap();
        fs::write(store.dir(&id).join(RECORD_NAME), b"{ truncated").unwrap();
        assert_eq!(store.load(&id).unwrap_err().code(), ErrorCode::BackendError);
        let unsupported = |record: &serde_json::Value| {
            fs::write(
                store.dir(&id).join(RECORD_NAME),
                serde_json::to_vec(record).unwrap(),
            )
            .unwrap();
            let error = store.load(&id).unwrap_err();
            assert_eq!(error.code(), ErrorCode::BackendError);
            assert!(error.message().contains("unsupported format"), "{error}");
        };
        let mut legacy = serde_json::to_value(record()).unwrap();
        legacy["format"] = 1.into();
        unsupported(&legacy);
        // Version 2 exported one directory and listed its bind mounts on the kernel command
        // line.
        legacy["format"] = 2.into();
        legacy["filesystem"] = serde_json::json!({
            "root": "/host/work",
            "writable": false,
            "denied": [],
            "deniedIdentities": [],
            "binds": [{ "source": "", "target": "/host/work", "readOnly": true }],
        });
        unsupported(&legacy);
    }

    #[test]
    fn records_of_the_current_format_keep_loading() {
        // A record that the crate wrote before NVX moved to `nvx-rs`, with a file and a
        // directory child, pinned identities, and every optional field.
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::open(root.path()).unwrap();
        let id = SandboxId::generate().unwrap();
        store.create(&id, &record()).unwrap();
        let written = serde_json::json!({
            "format": 3,
            "backend": "openvmm",
            "network": {
                "egress": {
                    "default": "deny",
                    "allow": [{ "to": [{ "cidr": "10.0.0.0/8", "except": ["10.1.0.0/16"] }],
                                "ports": [{ "protocol": "tcp", "port": 443 }] }]
                },
                "ingress": { "default": "deny", "hostLoopback": "deny" }
            },
            "filesystem": {
                "children": [
                    { "root": "/host/work/config.json", "file": true, "writable": false,
                      "hidden": false, "denied": [], "deniedIdentities": [], "allowed": [],
                      "write": [] },
                    { "root": "/host/work/out", "writable": true, "hidden": false,
                      "denied": ["/host/work/out/secret"],
                      "deniedIdentities": [{ "device": 1, "index": 2 }], "allowed": [],
                      "write": [] }
                ],
                "binds": [
                    { "child": 0, "source": "", "target": "/host/work/config.json",
                      "readOnly": true },
                    { "child": 1, "source": "", "target": "/host/work/out", "readOnly": false,
                      "identity": { "device": 1, "index": 3 } }
                ]
            },
            "memoryMib": 512,
            "workloadUid": 1000,
            "workloadGid": 1000,
            "createWorkloadAccount": true,
            "hostname": "nvx-sandbox"
        });
        fs::write(
            store.dir(&id).join(RECORD_NAME),
            serde_json::to_vec(&written).unwrap(),
        )
        .unwrap();
        let loaded = store.load(&id).unwrap();
        let plan = loaded.filesystem.as_ref().unwrap();
        assert!(plan.children[0].file && plan.children[1].writable);
        assert_eq!(plan.binds[1].identity.unwrap().index, 3);
        assert!(loaded.create_workload_account);
        // Writing the record again reproduces it field for field.
        assert_eq!(serde_json::to_value(&loaded).unwrap(), written);
    }

    #[test]
    fn locks_are_exclusive_per_sandbox() {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::open(root.path()).unwrap();
        let id = SandboxId::generate().unwrap();
        store.create(&id, &record()).unwrap();
        let (guard, loaded) = store.lock_and_load(&id).unwrap();
        assert_eq!(loaded, record());
        let path = store.lock_path(&id);
        let contender = OpenOptions::new().write(true).open(&path).unwrap();
        assert!(contender.try_lock().is_err());
        drop(guard);
        contender.try_lock().unwrap();
    }

    fn lock_files(root: &Path) -> usize {
        fs::read_dir(root.join(LOCKS_NAME)).unwrap().count()
    }

    #[test]
    fn stale_ids_leave_no_lock_files() {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::open(root.path()).unwrap();
        let never_provisioned = SandboxId::generate().unwrap();
        // An interrupted removal can leave an empty directory, which is stale too.
        let emptied = SandboxId::generate().unwrap();
        fs::create_dir(store.dir(&emptied)).unwrap();
        for id in [&never_provisioned, &emptied] {
            let error = store.lock_and_load(id).unwrap_err();
            assert_eq!(error.code(), ErrorCode::StaleId, "{error}");
        }
        assert_eq!(lock_files(root.path()), 0);

        let id = SandboxId::generate().unwrap();
        store.create(&id, &record()).unwrap();
        drop(store.lock_and_load(&id).unwrap());
        assert_eq!(lock_files(root.path()), 1);
    }

    #[test]
    fn state_removed_while_waiting_for_the_lock_leaves_no_lock_file() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::open(root.path()).unwrap());
        let id = SandboxId::generate().unwrap();
        store.create(&id, &record()).unwrap();
        let (guard, _) = store.lock_and_load(&id).unwrap();
        let waiter = thread::spawn({
            let (store, id) = (Arc::clone(&store), id.clone());
            move || store.lock_and_load(&id).map(drop)
        });
        // Let the waiter block on the lock, then deprovision as the backend does. A waiter that
        // starts late finds no state and must leave no lock file either.
        thread::sleep(Duration::from_millis(100));
        store.remove(&id).unwrap();
        drop(guard);
        store.remove_lock(&id);
        let error = waiter.join().unwrap().unwrap_err();
        assert_eq!(error.code(), ErrorCode::StaleId, "{error}");
        assert_eq!(lock_files(root.path()), 0);
    }
}
