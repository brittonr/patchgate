#!/bin/bash
set -euo pipefail
exec patchgate-eval solve stale-main-review /scenarios/stale-main-review
