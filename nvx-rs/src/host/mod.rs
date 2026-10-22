//! The host side of NVX.
//!
//! - [`artifacts`] locates the OpenVMM executable and the guest kernel and initramfs.
//! - [`launch`] builds OpenVMM's command line from a [`LaunchSpec`](launch::LaunchSpec): the
//!   managed lifecycle, the workload identity, the kernel command line, and the network and
//!   filesystem options.
//! - [`network`] lowers egress rules into OpenVMM's rules, and [`filesystem`] plans the export of
//!   host paths through OpenVMM's aggregate virtio-fs device.
//! - [`instance`] supervises one VM instance in a directory of its own: it starts OpenVMM and
//!   waits until the guest is ready, reconciles recorded state with the host, runs workloads,
//!   and stops the VM. [`report`] reads OpenVMM's outcome report.
//! - [`session`] speaks the authenticated control protocol, [`process`] launches and terminates
//!   OpenVMM processes, and [`platform`] holds the primitives of Linux and Windows hosts. Other
//!   hosts compile but report NVX as unavailable.

pub mod artifacts;
pub mod control;
pub mod filesystem;
pub mod instance;
pub mod launch;
pub mod live_control;
pub mod network;
pub mod platform;
pub mod poc_live;
pub mod process;
pub mod report;
pub mod session;
