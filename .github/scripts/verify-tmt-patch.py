#!/usr/bin/env python3
"""Verify that TMT has the DebugLevelFilter patch applied."""

import sys
sys.path.insert(0, "/home/runner/.local/lib/python3.13/site-packages")

import tmt.log
import inspect

# Check if the patch is applied by looking at DebugLevelFilter
source = inspect.getsource(tmt.log.DebugLevelFilter.filter)
if "return False" in source and "Filter out DEBUG messages" in source:
    print("✓ PATCH CONFIRMED: DebugLevelFilter has the fix applied")
    sys.exit(0)
else:
    print("✗ WARNING: Patch may not be applied correctly")
    print("Source code:")
    print(source)
    sys.exit(1)
