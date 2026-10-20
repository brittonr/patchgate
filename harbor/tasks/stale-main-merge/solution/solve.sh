#!/bin/bash
set -euo pipefail
exec patchgate-eval solve stale-main-merge /scenarios/stale-main-merge
