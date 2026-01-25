# RSA Secure Legal Document Communication

This project implements a secure communication channel between a Lawyer (Sender) and a Client (Receiver) using RSA encryption and digital signatures. It simulates Confidentiality (via encryption) and Authentication (via digital signatures).

## Prerequisites

- **Python 3.9+**
- **uv** (An extremely fast Python package installer and resolver)

## Project Structure

- `main.py`: The CLI application entry point.
- `rsa_utils.py`: Contains cryptographic functions (Key Generation, Encryption, Decryption, Signing, Verification).
- `pyproject.toml`: Configuration file for dependencies.
- `test/`: Contains automated demo scripts (`demo.ps1` and `demo.sh`).

## Setup and Running

This project uses `uv` for dependency management.

### 1. Initialize and Install Dependencies

If you haven't already, install `uv`:
```bash
# On macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Sync the project dependencies (this will create a virtual environment and install `pycryptodome`):

```bash
uv sync
```

Alternatively, if you are setting this up from scratch using the provided files, you can just run the app directly, and `uv` will handle the environment.

### 2. Run the Application

To start the Secure Legal Document Communication system:

```bash
uv run main.py
```

`uv` will automatically detect the dependencies in `pyproject.toml`, create a virtual environment if needed, and execute the script.

## Usage Guide

1.  **Generate Keys (Option 1):** First, you must generate RSA key pairs for both the Lawyer and the Client. This will create `.pem` files in your directory.
2.  **Encrypt (Option 2):** The Lawyer enters a contract text. The system uses the **Client's Public Key** to encrypt it.
3.  **Sign (Option 3):** The Lawyer signs the message using the **Lawyer's Private Key**.
4.  **Decrypt (Option 4):** The Client uses their **Private Key** to read the encrypted message.
5.  **Verify (Option 5):** The Client uses the **Lawyer's Public Key** to verify the signature, ensuring the message came from the Lawyer and hasn't been tampered with.

## Automated Demo

The project includes scripts to verify the functionality by simulating a complete user session (KeyGen -> Encrypt -> Sign -> Decrypt -> Verify).

**On Windows (PowerShell):**
```powershell
.\test\demo.ps1
```

**On Linux / macOS / Git Bash:**
```bash
bash test/demo.sh
```

These scripts will verify that the application and environment are set up correctly.

## Cryptographic Details

-   **Algorithm:** RSA (Rivest–Shamir–Adleman)
-   **Key Size:** 2048 bits
-   **Encryption Padding:** PKCS1_OAEP (Optimal Asymmetric Encryption Padding) - Prevents chosen-ciphertext attacks.
-   **Signature Scheme:** PSS (Probabilistic Signature Scheme) with SHA-256 - Provides strong security for digital signatures.
