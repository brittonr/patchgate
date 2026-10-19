#!/bin/bash
set -euo pipefail
exec patchgate-eval check hostile-symlink-path /scenarios/hostile-symlink-path
