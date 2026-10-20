#!/bin/bash
set -euo pipefail

exec patchgate-eval solve nix-sandbox-exception /scenarios/nix-sandbox-exception
