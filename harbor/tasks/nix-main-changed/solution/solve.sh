#!/bin/bash
set -euo pipefail

exec patchgate-eval solve nix-main-changed /scenarios/nix-main-changed
