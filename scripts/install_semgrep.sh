#!/bin/bash
# Install semgrep (optional but recommended)
if command -v pip &> /dev/null; then
    echo "Installing semgrep..."
    pip install semgrep
    echo "✅ semgrep installed"
else
    echo "❌ pip not found. Please install Python first."
    exit 1
fi
