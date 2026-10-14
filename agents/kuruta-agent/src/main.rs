//! Kuruta's cross-platform process-start sensor.

use std::collections::{HashSet, VecDeque};
use std::env;
use std::thread;
use std::time::Duration;

use chrono::Utc;
use reqwest::blocking::Client;
use serde::Serialize;
use serde_json::json;
use sysinfo::{Pid, System};
use url::{Host, Url};
use uuid::Uuid;

const MAX_PENDING_EVENTS: usize = 500;
const DEFAULT_INTERVAL_SECONDS: u64 = 5;

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
compile_error!("Kuruta currently supports Windows and Linux only.");

#[cfg(target_os = "windows")]
const PLATFORM: &str = "windows";
#[cfg(target_os = "linux")]
const PLATFORM: &str = "linux";

#[derive(Serialize)]
struct HostIdentity {
    id: String,
    hostname: String,
    platform: &'static str,
}

#[derive(Serialize)]
struct EventRecord {
    schema_version: u8,
    event_id: String,
    timestamp: String,
    host: HostIdentity,
    source: &'static str,
    event_type: &'static str,
    severity: &'static str,
    data: serde_json::Value,
}

fn required_hostname() -> Result<String, Box<dyn std::error::Error>> {
    System::host_name().ok_or_else(|| "Operating system did not provide a hostname".into())
}

fn configured_interval() -> Result<Duration, Box<dyn std::error::Error>> {
    let seconds = match env::var("KURUTA_INTERVAL_SECONDS") {
        Ok(value) => value.parse::<u64>()?,
        Err(env::VarError::NotPresent) => DEFAULT_INTERVAL_SECONDS,
        Err(error) => return Err(error.into()),
    };
    if seconds == 0 {
        return Err("KURUTA_INTERVAL_SECONDS must be greater than zero".into());
    }
    Ok(Duration::from_secs(seconds))
}

fn configured_endpoint() -> Result<Url, Box<dyn std::error::Error>> {
    let endpoint = match env::var("KURUTA_BACKEND_URL") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => {
            "http://127.0.0.1:8765/api/v1/events".to_owned()
        }
        Err(error) => return Err(error.into()),
    };
    let endpoint = Url::parse(&endpoint)?;
    let loopback_host = match endpoint.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    if endpoint.scheme() != "http"
        || !loopback_host
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
    {
        return Err(
            "MVP only permits unauthenticated HTTP endpoints on localhost".into(),
        );
    }
    Ok(endpoint)
}

fn current_process_ids(system: &System) -> HashSet<Pid> {
    system.processes().keys().copied().collect()
}

fn make_process_event(hostname: &str, pid: Pid, name: &str) -> EventRecord {
    EventRecord {
        schema_version: 1,
        event_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        host: HostIdentity {
            id: format!("{PLATFORM}:{hostname}"),
            hostname: hostname.to_owned(),
            platform: PLATFORM,
        },
        source: "host",
        event_type: "process.started",
        severity: "info",
        data: json!({
            "pid": pid.as_u32(),
            "name": name,
        }),
    }
}

fn post_pending_events(client: &Client, endpoint: &Url, pending: &mut VecDeque<EventRecord>) {
    while let Some(event) = pending.front() {
        let result = client.post(endpoint.as_str()).json(event).send();
        match result {
            Ok(response) if response.status().is_success() => {
                pending.pop_front();
            }
            Ok(response) => {
                eprintln!(
                    "Kuruta: backend returned {}; retaining event for retry",
                    response.status()
                );
                break;
            }
            Err(error) => {
                eprintln!("Kuruta: could not deliver event; retaining it for retry: {error}");
                break;
            }
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let hostname = required_hostname()?;
    let interval = configured_interval()?;
    let endpoint = configured_endpoint()?;
    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
    let mut system = System::new_all();
    let mut known_processes = current_process_ids(&system);
    let mut pending_events = VecDeque::new();

    eprintln!("Kuruta agent started for {PLATFORM}; sending events to the local backend");

    loop {
        thread::sleep(interval);
        system.refresh_all();
        let running_processes = current_process_ids(&system);
        known_processes.retain(|pid| running_processes.contains(pid));

        for (pid, process) in system.processes() {
            if known_processes.insert(*pid) {
                let name = process.name().to_string_lossy().into_owned();
                let event = make_process_event(&hostname, *pid, &name);
                if pending_events.len() == MAX_PENDING_EVENTS {
                    pending_events.pop_front();
                    eprintln!("Kuruta: pending event queue full; dropped the oldest event");
                }
                pending_events.push_back(event);
            }
        }

        post_pending_events(&client, &endpoint, &mut pending_events);
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Kuruta agent failed: {error}");
        std::process::exit(1);
    }
}
