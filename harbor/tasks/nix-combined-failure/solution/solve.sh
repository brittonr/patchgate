#!/bin/bash
set -euo pipefail

exec patchgate-eval solve nix-combined-failure /scenarios/nix-combined-failure
