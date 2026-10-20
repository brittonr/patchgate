#!/bin/bash
set -euo pipefail
exec patchgate-eval check stale-main-merge /scenarios/stale-main-merge
