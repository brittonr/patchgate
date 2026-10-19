#!/bin/bash
# Reward 1 only if the repository has the state that instruction.md asks for.
exec python3 /opt/patchgate/harbor/scenarios.py check rename-onto-protected-path /scenarios/rename-onto-protected-path
