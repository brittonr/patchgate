#!/bin/bash
set -euo pipefail

exec patchgate-eval solve apply-race-review /scenarios/apply-race-review
