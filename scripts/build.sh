#!/bin/bash
set -e

# Add cargo to PATH
export PATH="$HOME/.cargo/bin:$PATH"

echo "Building eBPF component..."
cd bpfhook-ebpf
cargo +nightly build --target=bpfel-unknown-none -Z build-std=core --release
cd ..

echo "Building userspace component..."
cd bpfhook-userspace
cargo build --release
cd ..

echo "Build complete!"