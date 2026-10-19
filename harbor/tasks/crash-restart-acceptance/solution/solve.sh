#!/bin/bash
set -euo pipefail

exec patchgate-eval solve crash-restart-acceptance /scenarios/crash-restart-acceptance
