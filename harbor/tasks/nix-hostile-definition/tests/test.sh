#!/bin/bash
set -euo pipefail

exec patchgate-eval check nix-hostile-definition /scenarios/nix-hostile-definition
