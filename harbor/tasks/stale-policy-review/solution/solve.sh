#!/bin/bash
set -euo pipefail
exec patchgate-eval solve stale-policy-review /scenarios/stale-policy-review
