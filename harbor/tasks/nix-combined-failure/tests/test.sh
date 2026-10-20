#!/bin/bash
set -euo pipefail

exec patchgate-eval check nix-combined-failure /scenarios/nix-combined-failure
