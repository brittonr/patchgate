#!/bin/bash
set -euo pipefail

exec patchgate-eval check nix-timeout /scenarios/nix-timeout
