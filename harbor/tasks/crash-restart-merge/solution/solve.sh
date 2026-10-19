#!/bin/bash
set -euo pipefail

exec patchgate-eval solve crash-restart-merge /scenarios/crash-restart-merge
