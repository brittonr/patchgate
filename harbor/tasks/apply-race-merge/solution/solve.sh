#!/bin/bash
set -euo pipefail

exec patchgate-eval solve apply-race-merge /scenarios/apply-race-merge
