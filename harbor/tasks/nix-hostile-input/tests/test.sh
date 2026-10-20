#!/bin/bash
set -euo pipefail

exec patchgate-eval check nix-hostile-input /scenarios/nix-hostile-input
