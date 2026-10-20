#!/bin/bash
set -euo pipefail
exec patchgate-eval check stale-policy-review /scenarios/stale-policy-review
