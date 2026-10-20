#!/bin/bash
set -euo pipefail
exec patchgate-eval solve dependency-graph-removed /scenarios/dependency-graph-removed
