#!/bin/bash
set -euo pipefail
exec patchgate-eval check rust-merge-errors-order /scenarios/rust-merge-errors-order
