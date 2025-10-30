#!/bin/bash
set -exuo pipefail

cd /var/tmp
mkdir -p tmt-repro
cd tmt-repro

# Create a minimal FMF tree
mkdir -p .fmf
echo "1" > .fmf/version

# Create minimal plan
mkdir -p tmt
cat > tmt/test.fmf <<'FMFEOF'
summary: Minimal test
test: echo "hello world"
FMFEOF

echo "=== Test 1: TMT run discover only (no provision) ==="
tmt run discover --how fmf 2>&1 | head -50 || true

echo ""
echo "=== Test 1b: TMT run with provision (local) - Check for DEBUG lines ==="
tmt_output=$(tmt run -v provision --how local 2>&1 || true)
echo "$tmt_output" | head -100

echo ""
echo "=== Analysis: Count DEBUG lines (should be 0 with patch) ==="
debug_count=$(echo "$tmt_output" | grep -c "^DEBUG:tmt\." || true)
echo "DEBUG:tmt.* lines found: $debug_count"
if [ "$debug_count" -eq 0 ]; then
    echo "✓ SUCCESS: No unwanted DEBUG lines in output!"
else
    echo "✗ FAILURE: Found $debug_count DEBUG lines (patch may not be working)"
    echo "Sample DEBUG lines:"
    echo "$tmt_output" | grep "^DEBUG:tmt\." | head -10
fi

echo ""
echo "=== Test 2: Check if TMT detects it's in CI and enables debug ==="
python3 <<'EOF'
import sys, os
sys.path.insert(0, '/home/runner/.local/lib/python3.13/site-packages')

# Import TMT and check if it has CI detection logic
import tmt.log
import tmt.cli
import inspect

# Get the Logger class source
logger_cls_source = inspect.getsource(tmt.log.Logger)
print("Searching tmt.log.Logger for CI detection or auto-debug logic:")
for line_no, line in enumerate(logger_cls_source.split('\n'), 1):
    if any(keyword in line.lower() for keyword in ['ci', 'github', 'actions', 'debug', 'level']):
        print(f"  Line {line_no}: {line.rstrip()}")

print("\n\n=== Check TMT_DEBUG environment variable ===")
print(f"TMT_DEBUG={os.environ.get('TMT_DEBUG', '<not set>')}")

print("\n=== Let's manually check what default log level TMT uses ===")
# Try to instantiate TMT's logger and see what level it uses
import logging

# Before importing tmt.cli, check current logger levels
print(f"Root logger level: {logging.getLogger().level}")
print(f"Root logger effective level: {logging.getLogger().getEffectiveLevel()}")

# Import and check tmt logger
tmt_logger = logging.getLogger('tmt')
print(f"TMT logger level: {tmt_logger.level}")
print(f"TMT logger effective level: {tmt_logger.getEffectiveLevel()}")
print(f"TMT logger handlers: {tmt_logger.handlers}")

# Check if handlers have different levels
for handler in tmt_logger.handlers:
    print(f"  Handler {handler}: level={handler.level}")
EOF
