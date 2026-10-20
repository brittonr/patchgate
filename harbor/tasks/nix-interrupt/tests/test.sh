#!/bin/bash
set -euo pipefail

exec patchgate-eval check nix-interrupt /scenarios/nix-interrupt
