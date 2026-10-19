# The bubblewrap backend builds this file. The Docker backend uses the image patchgate-harbor:dev instead.
# Both come from harbor/environment.nix.
(import ../../../environment.nix { }).default
