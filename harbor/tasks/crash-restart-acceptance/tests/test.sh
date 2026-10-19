#!/bin/bash
set -euo pipefail

exec patchgate-eval check crash-restart-acceptance /scenarios/crash-restart-acceptance
