#!/bin/bash
set -euo pipefail
exec patchgate-eval solve dependency-graph-rejected /scenarios/dependency-graph-rejected
