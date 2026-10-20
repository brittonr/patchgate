#!/bin/bash
set -euo pipefail

exec patchgate-eval solve nix-timeout /scenarios/nix-timeout
