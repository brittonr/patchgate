#!/bin/bash
set -euo pipefail

exec patchgate-eval check nix-failed-build /scenarios/nix-failed-build
