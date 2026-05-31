use crate::scanner::{PortState, ScanResult};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_info: ScanInfo,
    pub results: Vec<ScanResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanInfo {
    pub target: String,
    pub timestamp: String,
    pub total_ports_scanned: usize,
    pub open_ports: usize,
    pub closed_ports: usize,
    pub filtered_ports: usize,
    pub unfiltered_ports: usize,
    pub open_filtered_ports: usize,
}

pub fn format_text_report(results: &[ScanResult], target: &str) -> String {
    let mut output = String::new();
    let now: DateTime<Local> = Local::now();

    output.push_str(&format!("╔══════════════════════════════════════════════════════════════╗\n"));
    output.push_str(&format!("║  cli-nmap scan report for {:<34}║\n", target));
    output.push_str(&format!("║  Scan started at {:<43}║\n", now.format("%Y-%m-%d %H:%M:%S")));
    output.push_str(&format!("╠══════════════════════════════════════════════════════════════╣\n"));
    output.push_str(&format!("║ {:<6} {:<6} {:<12} {:<20} {:<20} ║\n", "PORT", "PROTO", "STATE", "SERVICE", "VERSION"));
    output.push_str(&format!("╠══════════════════════════════════════════════════════════════╣\n"));

    for result in results {
        let state_str = match result.state {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open|filtered",
            PortState::Unfiltered => "unfiltered",
        };

        output.push_str(&format!(
            "║ {:<6} {:<6} {:<12} {:<20} {:<20} ║\n",
            result.port,
            result.protocol,
            state_str,
            result.service,
            result.version,
        ));

        if !result.banner.is_empty() {
            let banner_preview: String = result.banner.chars().take(60).collect();
            let banner_display = banner_preview.replace('\n', " ").replace('\r', "");
            output.push_str(&format!("║        Banner: {:<51}║\n", banner_display));
        }
    }

    let open_count = results.iter().filter(|r| r.state == PortState::Open).count();
    let closed_count = results.iter().filter(|r| r.state == PortState::Closed).count();
    let filtered_count = results.iter().filter(|r| r.state == PortState::Filtered).count();
    let open_filtered_count = results.iter().filter(|r| r.state == PortState::OpenFiltered).count();
    let unfiltered_count = results.iter().filter(|r| r.state == PortState::Unfiltered).count();

    output.push_str(&format!("╠══════════════════════════════════════════════════════════════╣\n"));
    output.push_str(&format!("║  Total: {} ports | Open: {} | Closed: {} | Filtered: {} | Open|Filtered: {}",
        results.len(), open_count, closed_count, filtered_count, open_filtered_count));
    let stats_line_len = format!("  Total: {} ports | Open: {} | Closed: {} | Filtered: {} | Open|Filtered: {}",
        results.len(), open_count, closed_count, filtered_count, open_filtered_count).len();
    let padding = 60i32.saturating_sub(stats_line_len as i32);
    output.push_str(&" ".repeat(padding.max(0) as usize));
    output.push_str("║\n");
    if unfiltered_count > 0 {
        output.push_str(&format!("║  Unfiltered: {}                                               ║\n", unfiltered_count));
    }
    output.push_str(&format!("╚══════════════════════════════════════════════════════════════╝\n"));

    output
}

pub fn format_json_report(results: &[ScanResult], target: &str) -> String {
    let open_count = results.iter().filter(|r| r.state == PortState::Open).count();
    let closed_count = results.iter().filter(|r| r.state == PortState::Closed).count();
    let filtered_count = results.iter().filter(|r| r.state == PortState::Filtered).count();
    let open_filtered_count = results.iter().filter(|r| r.state == PortState::OpenFiltered).count();
    let unfiltered_count = results.iter().filter(|r| r.state == PortState::Unfiltered).count();

    let now: DateTime<Local> = Local::now();

    let report = ScanReport {
        scan_info: ScanInfo {
            target: target.to_string(),
            timestamp: now.format("%Y-%m-%d %H:%M:%S").to_string(),
            total_ports_scanned: results.len(),
            open_ports: open_count,
            closed_ports: closed_count,
            filtered_ports: filtered_count,
            unfiltered_ports: unfiltered_count,
            open_filtered_ports: open_filtered_count,
        },
        results: results.to_vec(),
    };

    serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}

pub fn write_output(content: &str, file_path: Option<&str>) -> std::io::Result<()> {
    match file_path {
        Some(path) => {
            let mut file = File::create(path)?;
            file.write_all(content.as_bytes())?;
            println!("Results written to: {}", path);
            Ok(())
        }
        None => {
            println!("{}", content);
            Ok(())
        }
    }
}
