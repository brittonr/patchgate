#!/bin/bash
set -euo pipefail
exec patchgate-eval check rust-merge-build /scenarios/rust-merge-build
