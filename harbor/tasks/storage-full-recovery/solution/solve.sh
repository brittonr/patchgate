#!/bin/bash
set -euo pipefail

exec patchgate-eval solve storage-full-recovery /scenarios/storage-full-recovery
