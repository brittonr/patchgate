#!/bin/bash
set -euo pipefail

exec patchgate-eval solve nix-interrupt /scenarios/nix-interrupt
