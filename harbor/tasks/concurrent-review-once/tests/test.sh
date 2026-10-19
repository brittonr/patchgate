#!/bin/bash
set -euo pipefail
exec patchgate-eval check concurrent-review-once /scenarios/concurrent-review-once
