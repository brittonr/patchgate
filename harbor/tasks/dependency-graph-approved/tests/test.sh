#!/bin/bash
set -euo pipefail
exec patchgate-eval check dependency-graph-approved /scenarios/dependency-graph-approved
