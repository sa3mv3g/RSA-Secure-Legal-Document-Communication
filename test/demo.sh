#!/bin/bash

echo "Starting RSA Secure Document Demo..."
echo "-----------------------------------"
echo "This script simulates a user interacting with the application."
echo "Steps:"
echo "1. Generate Keys"
echo "2. Encrypt a contract text"
echo "3. Sign the contract"
echo "4. Decrypt the ciphertext"
echo "5. Verify the signature"
echo "-----------------------------------"

# The following block pipes inputs to the Python application.
# We include empty lines to handle the "Press Enter to continue..." prompts.

# Resolve path to main.py relative to this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
uv run "$SCRIPT_DIR/../main.py" <<EOF
1

2
I agree to the terms and conditions of this contract.

3

4

5

6
EOF

echo "-----------------------------------"
echo "Demo Completed."
