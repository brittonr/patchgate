#!/bin/bash
set -euo pipefail
exec patchgate-eval check dependency-graph-removed /scenarios/dependency-graph-removed
