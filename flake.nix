{
  description = "Development environment for shrike";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, rust-overlay, ... }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

          # cargo-fuzz needs nightly (libFuzzer instrumentation and sanitizers).
          # Without rustup there is no `cargo +nightly`, so `cargo-nightly` runs
          # cargo with this toolchain first on PATH. flake.lock pins which
          # nightly this is.
          nightlyToolchain = pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.minimal);
          cargoNightly = pkgs.writeShellScriptBin "cargo-nightly" ''
            export PATH=${nightlyToolchain}/bin:$PATH
            exec cargo "$@"
          '';
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              rustToolchain
              cargoNightly
              cargo-fuzz
              git
              just
              nodejs
              binaryen
              gzip
              wasm-bindgen-cli
              wasm-pack
            ] ++ lib.optionals stdenv.hostPlatform.isLinux [
              openssl
              pkg-config
            ];
          };
        }
      );
    };
}
