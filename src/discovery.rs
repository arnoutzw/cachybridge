//! Link-local discovery for the short-lived initial pairing listener.
//!
//! Discovery deliberately advertises only a display name and pairing port. The
//! five-character code and all long-term secrets remain inside the PAKE/Noise
//! channel. Multicast stays on the local network (TTL 1).

use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 99);
const PORT: u16 = 45_234;
const PREFIX: &str = "CachyBridgeDiscovery/1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredClient {
    pub endpoint: SocketAddr,
    pub name: String,
}

pub struct Advertiser {
    stopped: Arc<AtomicBool>,
    mdns: Option<Child>,
}

impl Advertiser {
    pub fn start(pairing_port: u16, name: String) -> io::Result<Self> {
        let payload = encode_advertisement(pairing_port, &name)?;
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.set_multicast_ttl_v4(1)?;
        socket.set_multicast_loop_v4(true)?;
        socket.set_broadcast(true)?;
        let stopped = Arc::new(AtomicBool::new(false));
        let thread_stopped = Arc::clone(&stopped);
        thread::spawn(move || {
            while !thread_stopped.load(Ordering::Relaxed) {
                let _ = socket.send_to(&payload, (GROUP, PORT));
                // Some consumer Wi-Fi networks suppress multicast. A limited
                // broadcast fallback keeps discovery working within the same
                // subnet; it carries the same non-secret announcement.
                let _ = socket.send_to(&payload, (Ipv4Addr::BROADCAST, PORT));
                for _ in 0..10 {
                    if thread_stopped.load(Ordering::Relaxed) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
        });
        // Avahi/mDNS is the primary discovery path on CachyOS/KDE. The UDP
        // announcement above remains a same-subnet fallback for installations
        // where Avahi is disabled.
        let service_name = format!("CachyBridge {name}");
        let service_port = pairing_port.to_string();
        let mdns = Command::new("avahi-publish-service")
            .args([
                "-s",
                service_name.as_str(),
                "_cachybridge._tcp",
                service_port.as_str(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok();
        Ok(Self { stopped, mdns })
    }
}

impl Drop for Advertiser {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        if let Some(child) = self.mdns.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub fn discover(timeout: Duration) -> io::Result<Vec<DiscoveredClient>> {
    let mut discovered = discover_mdns();
    discovered.extend(discover_udp(timeout)?);
    let mut unique = BTreeMap::new();
    for client in discovered {
        unique.insert(client.endpoint, client);
    }
    Ok(unique.into_values().collect())
}

fn discover_udp(timeout: Duration) -> io::Result<Vec<DiscoveredClient>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, PORT))?;
    socket.join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    let deadline = Instant::now() + timeout;
    let mut clients = BTreeMap::new();
    while Instant::now() < deadline {
        let mut buffer = [0_u8; 256];
        match socket.recv_from(&mut buffer) {
            Ok((len, source)) => {
                if let Some((port, name)) = decode_advertisement(&buffer[..len]) {
                    let endpoint = SocketAddr::new(source.ip(), port);
                    clients.insert(endpoint, DiscoveredClient { endpoint, name });
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(clients.into_values().collect())
}

fn discover_mdns() -> Vec<DiscoveredClient> {
    let output = match Command::new("avahi-browse")
        .args(["-rtp", "_cachybridge._tcp"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => output.stdout,
        _ => return Vec::new(),
    };
    parse_mdns_output(&output)
}

fn parse_mdns_output(output: &[u8]) -> Vec<DiscoveredClient> {
    String::from_utf8_lossy(output)
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split(';').collect();
            if fields.len() < 10 || fields[0] != "=" || fields[4] != "_cachybridge._tcp" {
                return None;
            }
            let ip = fields[7].parse::<IpAddr>().ok()?;
            if ip.is_loopback()
                || matches!(ip, IpAddr::V6(address) if address.is_unicast_link_local())
            {
                return None;
            }
            let port = fields[8].parse::<u16>().ok()?;
            if port == 0 {
                return None;
            }
            Some(DiscoveredClient {
                endpoint: SocketAddr::new(ip, port),
                name: fields[3].replace("\\032", " "),
            })
        })
        .collect()
}

fn encode_advertisement(pairing_port: u16, name: &str) -> io::Result<Vec<u8>> {
    if pairing_port == 0 || name.is_empty() || name.len() > 80 || name.contains(['\n', '\r', '\t'])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid discovery advertisement",
        ));
    }
    Ok(format!("{PREFIX}\t{pairing_port}\t{name}").into_bytes())
}

fn decode_advertisement(bytes: &[u8]) -> Option<(u16, String)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut fields = text.split('\t');
    if fields.next()? != PREFIX {
        return None;
    }
    let port = fields.next()?.parse::<u16>().ok()?;
    let name = fields.next()?;
    if port == 0 || name.is_empty() || name.len() > 80 || fields.next().is_some() {
        return None;
    }
    Some((port, name.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_payload_never_contains_pairing_secrets() {
        let payload = encode_advertisement(45_232, "Client iMac").unwrap();
        assert_eq!(
            decode_advertisement(&payload),
            Some((45_232, "Client iMac".into()))
        );
        assert!(!String::from_utf8(payload).unwrap().contains("PSK"));
    }

    #[test]
    fn parses_avahi_machine_readable_records() {
        let output = b"=;wlan0;IPv4;CachyBridge\\032Client;_cachybridge._tcp;local;client.local;192.168.2.24;45232;\n";
        assert_eq!(
            parse_mdns_output(output),
            vec![DiscoveredClient {
                endpoint: "192.168.2.24:45232".parse().unwrap(),
                name: "CachyBridge Client".into(),
            }]
        );
    }
}
