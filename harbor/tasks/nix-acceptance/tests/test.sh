#!/bin/bash
set -euo pipefail

exec patchgate-eval check nix-acceptance /scenarios/nix-acceptance
