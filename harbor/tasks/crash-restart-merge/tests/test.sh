#!/bin/bash
set -euo pipefail

exec patchgate-eval check crash-restart-merge /scenarios/crash-restart-merge
