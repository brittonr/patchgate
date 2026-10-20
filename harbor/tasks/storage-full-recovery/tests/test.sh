#!/bin/bash
set -euo pipefail

exec patchgate-eval check storage-full-recovery /scenarios/storage-full-recovery
