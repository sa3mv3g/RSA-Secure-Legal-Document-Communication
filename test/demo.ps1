Write-Output "Starting RSA Secure Document Demo..."
Write-Output "-----------------------------------"
Write-Output "This script simulates a user interacting with the application."

# Define the input stream
# 1. Option 1 (Gen Keys)
# 2. Enter (Continue)
# 3. Option 2 (Encrypt)
# 4. Message text
# 5. Enter (Continue)
# 6. Option 3 (Sign)
# 7. Enter (Continue)
# 8. Option 4 (Decrypt)
# 9. Enter (Continue)
# 10. Option 5 (Verify)
# 11. Enter (Continue)
# 12. Option 6 (Exit)

$inputString = @"
1

2
I agree to the terms and conditions of this contract.

3

4

5

6
"@

# Run the command and pipe the input
# Resolve path to main.py relative to this script (one level up)
$mainPath = Join-Path $PSScriptRoot "../main.py"
$inputString | py -m uv run $mainPath

Write-Output "-----------------------------------"
Write-Output "Demo Completed."
