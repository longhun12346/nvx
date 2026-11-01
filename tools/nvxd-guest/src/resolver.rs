//! The guest's DNS servers in the assembled root.
//!
//! NVX's `/init` writes the servers OpenVMM names on the kernel command line (`virtnet_dns=`) to
//! the initramfs's `/etc/resolv.conf`, but the workload runs in the root that the agent assembles
//! over the distro layer, which holds a resolver file of its own (often a link to a stub that
//! does not exist here). Without this step a guest with a network resolves no names.

use std::fs;
use std::io;
use std::path::Path;

/// The servers that a kernel command line names with `virtnet_dns=a,b`, in order.
pub fn servers(command_line: &str) -> Vec<String> {
    command_line
        .split_whitespace()
        .find_map(|word| word.strip_prefix("virtnet_dns="))
        .map(|list| {
            list.split(',')
                .filter(|server| !server.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Writes `nameserver` lines for the command line's servers to `etc/resolv.conf` of `root`,
/// replacing a file or a link there. Does nothing for a command line without servers.
pub fn write(root: &Path, command_line: &str) -> io::Result<()> {
    let servers = servers(command_line);
    if servers.is_empty() {
        return Ok(());
    }
    let etc = root.join("etc");
    fs::create_dir_all(&etc)?;
    let path = etc.join("resolv.conf");
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut text = String::new();
    for server in servers {
        text.push_str("nameserver ");
        text.push_str(&server);
        text.push('\n');
    }
    fs::write(path, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servers_come_from_the_command_line_in_order() {
        let line = "console=hvc0 virtnet_ip=10.0.0.2 virtnet_dns=10.0.0.1,fd00::a00:1 quiet";
        assert_eq!(servers(line), ["10.0.0.1", "fd00::a00:1"]);
        assert!(servers("console=hvc0 quiet").is_empty());
        assert!(servers("virtnet_dns=").is_empty());
    }

    #[test]
    fn a_link_to_a_missing_stub_is_replaced() {
        let dir = std::env::temp_dir().join(format!("nvxd-resolver-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(dir.join("etc/resolv.conf"), "nameserver 1.1.1.1\n").unwrap();
        write(&dir, "virtnet_dns=10.0.0.1").unwrap();
        assert_eq!(fs::read_to_string(dir.join("etc/resolv.conf")).unwrap(), "nameserver 10.0.0.1\n");
        write(&dir, "no servers here").unwrap();
        assert_eq!(fs::read_to_string(dir.join("etc/resolv.conf")).unwrap(), "nameserver 10.0.0.1\n");
        let _ = fs::remove_dir_all(&dir);
    }
}
