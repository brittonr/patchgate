#!/bin/bash
set -euo pipefail

exec patchgate-eval solve nix-hostile-definition /scenarios/nix-hostile-definition
