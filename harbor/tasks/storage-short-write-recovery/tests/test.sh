#!/bin/bash
set -euo pipefail

exec patchgate-eval check storage-short-write-recovery /scenarios/storage-short-write-recovery
