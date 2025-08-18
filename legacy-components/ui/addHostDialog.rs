// Models

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlanMode {
    Easy,
    Hard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimingProfile {
    T0Paranoid,
    T1Sneaky,
    T2Polite,
    T3Normal,
    T4Aggressive,
    T5Insane,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortScanStyle {
    TcpConnect, // -sT
    Obfuscated, // custom: data-length, retries, randomize-hosts
    Fin,        // -sF
    Null,       // -sN
    Xmas,       // -sX
    TcpPing,    // host discovery via TCP ping
    UdpPing,    // host discovery via UDP
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostDiscovery {
    Disabled,  // -Pn
    Default,   // ICMP + TCP ACK (approx)
    Icmp,      // -PE
    TcpSyn,    // -PS
    TcpAck,    // -PA
    Timestamp, // -PP
    Netmask,   // -PM
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EasyOptions {
    pub run_discovery: bool,   // default true
    pub run_staged_scan: bool, // default true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardOptions {
    pub port_scan_style: PortScanStyle,
    pub host_discovery: HostDiscovery,
    pub fragment: bool,
    pub custom_args: Vec<String>, // free-form flags
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanRequest {
    pub targets: Vec<String>, // supports CIDR, ranges, hosts
    pub mode: PlanMode,
    pub timing: TimingProfile,     // T0..T5
    pub easy: Option<EasyOptions>, // required if mode=Easy
    pub hard: Option<HardOptions>, // required if mode=Hard
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSpec {
    pub program: String,            // "nmap" or "masscan"
    pub args: Vec<String>,          // resolved CLI flags
    pub cwd: Option<String>,        // optional
    pub env: Vec<(String, String)>, // optional
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanResolved {
    pub commands: Vec<CommandSpec>, // execute in order
    pub description: String,
}

// Flag mappers for nmap and masscan

fn timing_to_nmap(t: &TimingProfile) -> &'static str {
    match t {
        TimingProfile::T0Paranoid => "-T0",
        TimingProfile::T1Sneaky => "-T1",
        TimingProfile::T2Polite => "-T2",
        TimingProfile::T3Normal => "-T3",
        TimingProfile::T4Aggressive => "-T4",
        TimingProfile::T5Insane => "-T5",
    }
}

// Host discovery flags for nmap
fn host_discovery_flags(h: &HostDiscovery) -> Vec<&'static str> {
    match h {
        HostDiscovery::Disabled => vec!["-Pn"],
        HostDiscovery::Default => vec!["-PE", "-PA"], // ICMP Echo + TCP ACK (approximate default)
        HostDiscovery::Icmp => vec!["-PE"],
        HostDiscovery::TcpSyn => vec!["-PS"],
        HostDiscovery::TcpAck => vec!["-PA"],
        HostDiscovery::Timestamp => vec!["-PP"],
        HostDiscovery::Netmask => vec!["-PM"],
    }
}

// Scan style maps for nmap
fn port_scan_style_flags(p: &PortScanStyle) -> Vec<&'static str> {
    match p {
        PortScanStyle::TcpConnect => vec!["-sT"],
        PortScanStyle::Obfuscated => vec![], // handled separately
        PortScanStyle::Fin => vec!["-sF"],
        PortScanStyle::Null => vec!["-sN"],
        PortScanStyle::Xmas => vec!["-sX"],
        PortScanStyle::TcpPing => vec![], // discovery-only; handled in discovery step
        PortScanStyle::UdpPing => vec![], // discovery-only
    }
}

// Plans

pub fn resolve_plan(req: PlanRequest) -> PlanResolved {
    let mut commands: Vec<CommandSpec> = Vec::new();
    let timing = timing_to_nmap(&req.timing).to_string();

    let join_targets = |v: &Vec<String>| v.clone(); // pass as individual args

    match req.mode {
        PlanMode::Easy => {
            let opts = req.easy.unwrap_or(EasyOptions {
                run_discovery: true,
                run_staged_scan: true,
            });

            // Optional: initial fast sweep with masscan to accelerate
            // Keep disabled by default; uncomment to include.
            // commands.push(CommandSpec {
            //     program: "masscan".into(),
            //     args: vec![
            //         "--rate", "10000".into(),
            //         "-p", "1-1000".into(),
            //     ]
            //     .into_iter()
            //     .chain(join_targets(&req.targets).into_iter())
            //     .collect(),
            //     cwd: None,
            //     env: vec![],
            // });

            if opts.run_discovery {
                // nmap host discovery only
                let mut args: Vec<String> = vec![timing.clone()];
                // Default discovery: ICMP + TCP ACK
                args.extend(["-PE", "-PA"].iter().map(|s| s.to_string()));
                // No port scan, just ping sweep
                args.push("-sn".to_string());
                args.extend(join_targets(&req.targets));
                commands.push(CommandSpec {
                    program: "nmap".into(),
                    args,
                    cwd: None,
                    env: vec![],
                });
            }

            if opts.run_staged_scan {
                // Stage 1: top ports fast TCP
                {
                    let mut args: Vec<String> = vec![
                        timing.clone(),
                        "-sS".into(),
                        "--top-ports".into(),
                        "1000".into(),
                        "-n".into(),
                        "-v".into(),
                    ];
                    // Disable host discovery so we reuse targets or pipe discovered hosts externally
                    args.push("-Pn".into());
                    args.extend(join_targets(&req.targets));
                    commands.push(CommandSpec {
                        program: "nmap".into(),
                        args,
                        cwd: None,
                        env: vec![],
                    });
                }
                // Stage 2: service detection on discovered open ports (rerun broadly if you don't parse)
                {
                    let mut args: Vec<String> = vec![
                        timing.clone(),
                        "-sS".into(),
                        "-sV".into(),
                        "-O".into(),
                        "-n".into(),
                        "-v".into(),
                    ];
                    args.push("-Pn".into());
                    args.extend(join_targets(&req.targets));
                    commands.push(CommandSpec {
                        program: "nmap".into(),
                        args,
                        cwd: None,
                        env: vec![],
                    });
                }
                // Stage 3: targeted NSE scripts (optional – keep modest by default)
                {
                    let mut args: Vec<String> = vec![
                        timing.clone(),
                        "-sS".into(),
                        "--script".into(),
                        "default,vuln,safe".into(),
                        "-n".into(),
                        "-v".into(),
                    ];
                    args.push("-Pn".into());
                    args.extend(join_targets(&req.targets));
                    commands.push(CommandSpec {
                        program: "nmap".into(),
                        args,
                        cwd: None,
                        env: vec![],
                    });
                }
            }
        }

        PlanMode::Hard => {
            let opts = req.hard.unwrap_or(HardOptions {
                port_scan_style: PortScanStyle::Obfuscated,
                host_discovery: HostDiscovery::Disabled,
                fragment: true,
                custom_args: vec![],
            });

            // Host discovery phase if enabled
            if !matches!(opts.host_discovery, HostDiscovery::Disabled) {
                let mut args: Vec<String> = vec![timing.clone()];
                args.extend(
                    host_discovery_flags(&opts.host_discovery)
                        .into_iter()
                        .map(|s| s.to_string()),
                );
                args.push("-sn".to_string());
                args.extend(join_targets(&req.targets));
                commands.push(CommandSpec {
                    program: "nmap".into(),
                    args,
                    cwd: None,
                    env: vec![],
                });
            }

            // Main scan
            let mut args: Vec<String> = vec![timing.clone()];

            // Fragmentation
            if opts.fragment {
                args.push("-f".into());
            }

            // Scan style
            let style = &opts.port_scan_style;
            args.extend(
                port_scan_style_flags(style)
                    .into_iter()
                    .map(|s| s.to_string()),
            );

            // Obfuscation preset
            if matches!(style, PortScanStyle::Obfuscated) {
                // Conservative obfuscation: small payload, fewer retries, randomized hosts
                args.extend(
                    [
                        "--data-length",
                        "5",
                        "--max-retries",
                        "2",
                        "--randomize-hosts",
                    ]
                    .into_iter()
                    .map(|s| s.to_string()),
                );
                // Use -sS for speed but you can switch to -sT if raw sockets restricted
                args.push("-sS".into());
            }

            // If style implies discovery-only, map to actual scan modes
            if matches!(style, PortScanStyle::TcpPing | PortScanStyle::UdpPing) {
                // Treat as discovery followed by TCP/UDP scan
                // You can split it, but here we run a TCP SYN scan after discovery hint.
                args.push("-sS".into());
            }

            // Keep DNS off for speed unless you want names
            args.push("-n".into());
            args.push("-v".into());

            // If discovery disabled, tell nmap to skip ping
            if matches!(opts.host_discovery, HostDiscovery::Disabled) {
                args.push("-Pn".into());
            } else {
                // otherwise, you can also carry discovery flags into main scan if desired
                // args.extend(host_discovery_flags(&opts.host_discovery).into_iter().map(|s| s.to_string()));
            }

            // Custom args
            args.extend(opts.custom_args.clone());

            // Targets
            args.extend(join_targets(&req.targets));

            commands.push(CommandSpec {
                program: "nmap".into(),
                args,
                cwd: None,
                env: vec![],
            });

            // Optional: augment with masscan for large ranges then nmap follow-up
            // commands.push(CommandSpec {
            //     program: "masscan".into(),
            //     args: vec!["-p", "1-65535", "--rate", "50000"]
            //         .into_iter()
            //         .map(|s| s.to_string())
            //         .chain(join_targets(&req.targets).into_iter())
            //         .collect(),
            //     cwd: None,
            //     env: vec![],
            // });
        }
    }

    PlanResolved {
        description: "Resolved scanning plan".into(),
        commands,
    }
}
// A single tauri command to resolve a plan

#[tauri::command]
pub fn build_plan(req: PlanRequest) -> Result<PlanResolved, String> {
    // TODO: validate targets and options as needed
    Ok(resolve_plan(req))
}

// Backend command to execute a plan

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub program: String,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[tauri::command]
pub fn execute_plan(plan: PlanResolved) -> Result<Vec<ExecResult>, String> {
    let mut results = Vec::new();
    for cmd in plan.commands {
        let mut child = Command::new(&cmd.program)
            .args(&cmd.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {} failed: {}", cmd.program, e))?;

        let output = child
            .wait_with_output()
            .map_err(|e| format!("wait {} failed: {}", cmd.program, e))?;

        results.push(ExecResult {
            program: cmd.program,
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(results)
}
