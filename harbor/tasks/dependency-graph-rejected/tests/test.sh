#!/bin/bash
set -euo pipefail
exec patchgate-eval check dependency-graph-rejected /scenarios/dependency-graph-rejected
