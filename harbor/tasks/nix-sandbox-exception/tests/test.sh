#!/bin/bash
set -euo pipefail

exec patchgate-eval check nix-sandbox-exception /scenarios/nix-sandbox-exception
