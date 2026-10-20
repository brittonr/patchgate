#!/bin/bash
set -euo pipefail

exec patchgate-eval solve storage-short-write-recovery /scenarios/storage-short-write-recovery
