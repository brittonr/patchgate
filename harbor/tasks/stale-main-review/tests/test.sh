#!/bin/bash
set -euo pipefail
exec patchgate-eval check stale-main-review /scenarios/stale-main-review
