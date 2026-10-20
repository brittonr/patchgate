#!/bin/bash
set -euo pipefail

exec patchgate-eval check storage-sync-recovery /scenarios/storage-sync-recovery
