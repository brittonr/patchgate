#!/bin/bash
set -euo pipefail

exec patchgate-eval solve nix-acceptance /scenarios/nix-acceptance
