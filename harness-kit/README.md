# Harness kit (rsync onto a new Mac)

Prefer `../install/install-all.sh` from the clone root.

```bash
export DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
export PENTEST_LAB="${PENTEST_LAB:-$DSH_HOME/pentest-lab}"
export KIT_ROOT="$(cd .. && pwd)"
rsync -a "$KIT_ROOT/harness-kit/plugins/" "$DSH_HOME/plugins/"
mkdir -p "$PENTEST_LAB/jobs"
cp "$KIT_ROOT/harness-kit/pentest-lab/"*.py "$PENTEST_LAB/"
chmod +x "$PENTEST_LAB/subenum.py" "$PENTEST_LAB/connect_probe.py" "$PENTEST_LAB/org_ranges.py"
cd "$DSH_HOME/profiles/web" && npm install
python3 "$PENTEST_LAB/subenum.py" example.com
```
