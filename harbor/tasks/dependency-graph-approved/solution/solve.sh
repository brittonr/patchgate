#!/bin/bash
set -euo pipefail
exec patchgate-eval solve dependency-graph-approved /scenarios/dependency-graph-approved
