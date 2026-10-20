#!/bin/bash
set -euo pipefail

exec patchgate-eval solve apply-race-human /scenarios/apply-race-human
