# Run the agent
# From repo root:

# 1) Analyze legacy code
python3 tools/analyze_legacy.py --root . \
  --legacy-dirs legacy-python legacy-scripts \
  --out tools/analysis

# 2) Generate Tauri wrappers
python3 tools/generate_tauri_wrappers.py \
  --report tools/analysis/legacy_report.json \
  --out tools/generated

# 3) Copy generated files into the app
cp tools/generated/legacy_wrappers.rs src-tauri/src/legacy_wrappers.rs
# Open src-tauri/src/main.rs and register commands from REGISTER_CMDS.txt
# Copy tools/generated/legacy_bindings.ts into src/lib/legacy.ts (or your preferred path)

# 4) Build/run Tauri
pnpm tauri dev  # or yarn/npm, per your setup