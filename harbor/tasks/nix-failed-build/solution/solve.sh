#!/bin/bash
set -euo pipefail

exec patchgate-eval solve nix-failed-build /scenarios/nix-failed-build
