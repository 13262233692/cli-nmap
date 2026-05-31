mod cli;
mod fingerprint;
mod output;
mod packet;
mod proxy;
mod scanner;

use cli::Cli;

fn main() {
    let cli = Cli::parse_args();

    eprintln!("cli-nmap: Starting scan on target '{}' ...", cli.target);
    eprintln!("  Port range : {}", cli.ports);
    eprintln!("  Scan type  : {}", cli.scan_type);
    eprintln!("  Threads    : {}", cli.threads);
    eprintln!("  Timeout    : {}ms", cli.timeout);
    eprintln!("  Output     : {}", cli.output);
    if cli.stealth {
        eprintln!("  Stealth    : enabled");
    }
    if cli.ttl != 64 {
        eprintln!("  TTL        : {}", cli.ttl);
    }
    if cli.mtu.is_some() {
        eprintln!("  MTU frag   : {} bytes", cli.mtu.unwrap());
    }
    if cli.zombie.is_some() {
        eprintln!("  Zombie     : {}:{}", cli.zombie.as_ref().unwrap(), cli.zombie_port.unwrap_or(80));
    }
    if cli.decoys.is_some() {
        eprintln!("  Decoys     : {}", cli.decoys.as_ref().unwrap());
    }
    if cli.proxy_file.is_some() {
        eprintln!("  Proxy file : {}", cli.proxy_file.as_ref().unwrap());
    }
    if cli.randomize_ports {
        eprintln!("  Randomize  : ports");
    }

    let engine = scanner::ScanEngine::new(&cli);
    let results = engine.run();

    if results.is_empty() {
        eprintln!("cli-nmap: No open ports found.");
    } else {
        eprintln!("cli-nmap: Scan complete. Found {} result(s).", results.len());
    }

    let content = match cli.output.as_str() {
        "json" => output::format_json_report(&results, &cli.target),
        _ => output::format_text_report(&results, &cli.target),
    };

    if let Err(e) = output::write_output(&content, cli.file.as_deref()) {
        eprintln!("Error writing output: {}", e);
    }
}
