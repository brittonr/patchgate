#!/bin/bash
set -euo pipefail

exec patchgate-eval solve nix-hostile-input /scenarios/nix-hostile-input
