#!/bin/bash
set -euo pipefail

exec patchgate-eval check apply-race-merge /scenarios/apply-race-merge
