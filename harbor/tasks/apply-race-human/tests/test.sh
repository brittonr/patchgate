#!/bin/bash
set -euo pipefail

exec patchgate-eval check apply-race-human /scenarios/apply-race-human
