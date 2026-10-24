#!/bin/bash
set -euo pipefail
exec patchgate-eval check rust-model-rules /scenarios/rust-model-rules
