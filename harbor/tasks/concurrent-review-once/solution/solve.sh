#!/bin/bash
set -euo pipefail
exec patchgate-eval solve concurrent-review-once /scenarios/concurrent-review-once
