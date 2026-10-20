#!/bin/bash
set -euo pipefail

exec patchgate-eval check apply-race-review /scenarios/apply-race-review
