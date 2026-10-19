#!/bin/bash
set -euo pipefail
exec patchgate-eval solve hostile-symlink-path /scenarios/hostile-symlink-path
