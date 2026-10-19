#!/bin/bash
# The oracle runs patchgate with a scripted model.
set -euo pipefail

exec python3 /opt/patchgate/harbor/scenarios.py solve merge-order-conflict /scenarios/merge-order-conflict
