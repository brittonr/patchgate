#!/bin/bash
set -euo pipefail

exec patchgate-eval check nix-main-changed /scenarios/nix-main-changed
