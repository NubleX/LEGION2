use anyhow::Result;
use regex::Regex;
use serde::Serialize;
use std::{env, fs, path::PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Serialize)]
struct Entry {
  path: String,
  name: String,
  script_type: String,
  shebang: Option<String>,
  python_imports: Vec<String>,
  arg_flags: Vec<String>,
  external_tools: Vec<String>,
  possible_outputs: Vec<String>,
  os_specific: Vec<String>,
  size_bytes: u64,
  migration_strategy: String,
}

fn detect_shebang(code: &str) -> Option<String> {
  code.lines().next().and_then(|l| {
    l.trim_start().strip_prefix("#!").map(|s| s.trim().to_string())
  })
}

fn detect_script_type(path: &PathBuf, code: &str) -> String {
  let she = detect_shebang(code).unwrap_or_default().to_lowercase();
  let ext = path
    .extension()
    .unwrap_or_default()
    .to_string_lossy()
    .to_lowercase();
  if she.contains("python") || ext == "py" {
    "python".into()
  } else if she.contains("bash") || she.contains("sh") || ext == "sh" {
    "bash".into()
  } else if she.contains("powershell") || ext == "ps1" {
    "powershell".into()
  } else if ext == "bat" || ext == "cmd" {
    "batch".into()
  } else {
    "unknown".into()
  }
}

fn extract_python_imports(code: &str) -> Vec<String> {
  let re =
    Regex::new(r#"^\s*(?:from\s+([\w\.]+)\s+import|import\s+([\w\.]+))"#).unwrap();
  let mut out = vec![];
  for line in code.lines() {
    if let Some(c) = re.captures(line) {
      let pkg = c.get(1).or_else(|| c.get(2)).map(|m| m.as_str()).unwrap();
      let base = pkg.split('.').next().unwrap_or(pkg).to_string();
      if !out.contains(&base) {
        out.push(base);
      }
    }
  }
  out
}

fn extract_argparse_flags(code: &str) -> Vec<String> {
  let re = Regex::new(r#"add_argument\(\s*['"](-{1,2}[\w\-]+)['"]"#).unwrap();
  let mut out = vec![];
  for cap in re.captures_iter(code) {
    let f = cap.get(1).unwrap().as_str().to_string();
    if !out.contains(&f) {
      out.push(f);
    }
  }
  out
}

fn guess_external_tools(code: &str) -> Vec<String> {
  let known = [
    "masscan", "nmap", "hydra", "curl", "wget", "nikto", "amass", "sublist3r",
    "dnsrecon", "whatweb", "ffuf", "dirb", "gobuster", "openssl", "ssh", "ping",
    "traceroute", "powershell",
  ];
  let token = Regex::new(r#"\b([\w\-\_\.]+)\b"#).unwrap();
  let mut out = vec![];
  for cap in token.captures_iter(code) {
    let t = cap.get(1).unwrap().as_str().to_lowercase();
    if known.contains(&t.as_str()) && !out.contains(&t) {
      out.push(t);
    }
  }
  out
}

fn outputs_guess(code: &str) -> Vec<String> {
  let l = code.to_lowercase();
  let mut out = vec![];
  if l.contains("json") {
    out.push("json".into());
  }
  if l.contains("xml") {
    out.push("xml".into());
  }
  if l.contains("csv") {
    out.push("csv".into());
  }
  out.push("stdout".into());
  out.sort();
  out.dedup();
  out
}

fn migration_strategy(stype: &str, tools: &[String], imports: &[String]) -> String {
  if stype == "python" {
    let toolset: Vec<_> = tools.iter().map(|s| s.as_str()).collect();
    let imps: Vec<_> = imports.iter().map(|s| s.as_str()).collect();
    if toolset.is_empty() && (imps.contains(&"requests") || imps.contains(&"json")) {
      "rewrite_rust".into()
    } else {
      "rewrite_rust".into()
    }
  } else if ["bash", "powershell", "batch"].contains(&stype) {
    "rewrite_rust".into()
  } else {
    "inspect_manual".into()
  }
}

fn main() -> Result<()> {
  let root = env::args().nth(1).unwrap_or(".".into());
  let out_dir = env::args().nth(2).unwrap_or("tools/analysis".into());
  let legacy_dirs = vec!["legacy-python", "legacy-scripts"];
  fs::create_dir_all(&out_dir)?;

  let mut entries: Vec<Entry> = vec![];

  for d in legacy_dirs {
    let dir = PathBuf::from(&root).join(d);
    if !dir.exists() {
      continue;
    }
    for e in WalkDir::new(&dir).into_iter().filter_map(|e| e.ok()) {
      let p = e.path();
      if !p.is_file() {
        continue;
      }
      let ext = p
        .extension()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
      if !["py", "sh", "ps1", "bat", "cmd"].contains(&ext.as_str()) {
        continue;
      }
      let code = fs::read_to_string(p).unwrap_or_default();
      let stype = detect_script_type(&p.to_path_buf(), &code);
      let shebang = detect_shebang(&code);
      let python_imports = if stype == "python" {
        extract_python_imports(&code)
      } else {
        vec![]
      };
      let arg_flags = if stype == "python" {
        extract_argparse_flags(&code)
      } else {
        vec![]
      };
      let external_tools = guess_external_tools(&code);
      let possible_outputs = outputs_guess(&code);
      let mut os_specific = vec![];
      if stype == "bash" {
        os_specific.push("posix".into());
      }
      if stype == "powershell" || stype == "batch" {
        os_specific.push("windows".into());
      }
      let size_bytes = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
      let migration_strategy =
        migration_strategy(&stype, &external_tools, &python_imports);
      let rel = p
        .strip_prefix(&root)
        .unwrap_or(p)
        .to_string_lossy()
        .to_string();

      entries.push(Entry {
        path: rel,
        name: p.file_name().unwrap().to_string_lossy().to_string(),
        script_type: stype,
        shebang,
        python_imports,
        arg_flags,
        external_tools,
        possible_outputs,
        os_specific,
        size_bytes,
        migration_strategy,
      });
    }
  }

  let summary = serde_json::json!({
    "count": entries.len(),
    "by_script_type": {
      "python": entries.iter().filter(|e| e.script_type == "python").count(),
      "bash": entries.iter().filter(|e| e.script_type == "bash").count(),
      "powershell": entries.iter().filter(|e| e.script_type == "powershell").count(),
      "batch": entries.iter().filter(|e| e.script_type == "batch").count(),
      "unknown": entries.iter().filter(|e| e.script_type == "unknown").count(),
    },
  });

  let report = serde_json::json!({
    "root": root,
    "entries": entries,
    "summary": summary
  });

  let json_path = PathBuf::from(&out_dir).join("legacy_report.json");
  fs::write(&json_path, serde_json::to_string_pretty(&report)?)?;

  println!("Wrote: {}", json_path.display());
  Ok(())
}