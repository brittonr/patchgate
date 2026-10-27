{ pkgs }:

pkgs.pijul.overrideAttrs (old: {
  # Pijul omits the zero size field in empty-directory archive headers.
  # Rust tar readers reject those headers after a rename leaves an empty directory.
  postPatch = (old.postPatch or "") + ''
    archive=$(find "$cargoDepsCopy" -path '*/pijul-core-*/src/output/archive.rs')
    test -f "$archive"
    patch -d "$(dirname "$archive")" < ${./pijul-archive.patch}
    # Compare channel states inside the native write transaction.
    patch -p1 < ${./pijul-apply.patch}
    patch -p1 < ${./pijul-unrecord.patch}
  # <!-- ste-disable-next-line semicolon -->
  '';
})
