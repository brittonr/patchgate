#!/bin/bash
set -euo pipefail
exec patchgate-eval check rust-merge-behavior /scenarios/rust-merge-behavior
