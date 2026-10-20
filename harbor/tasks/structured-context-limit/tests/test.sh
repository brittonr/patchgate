#!/bin/bash
set -euo pipefail
exec patchgate-eval check structured-context-limit /scenarios/structured-context-limit
