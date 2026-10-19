#!/bin/bash
set -euo pipefail
exec patchgate-eval check hostile-message-injection /scenarios/hostile-message-injection
