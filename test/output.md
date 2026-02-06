```bash
============================================================
       RSA Secure Legal Document Communication System
============================================================

--- Step 1: Generate Keys ---
Generating 2048-bit RSA keys...
Key saved to lawyer_private.pem
Key saved to lawyer_public.pem
Key saved to client_private.pem
Key saved to client_public.pem
Setup Complete!

--- Step 2: Encrypt Document ---
Enter the legal document text to send: Test legal document
Encryption Successful!
Ciphertext (Hex): 2b8b4ee4a13c001c46ddfb2765d88979ed174698b4ae6f6e07d7d614186d...[truncated]
(This ciphertext can only be decrypted by the Client's Private Key)

--- Step 3: Sign Document ---
Signing Successful!
Digital Signature (Hex): 5151baf5139d57cc11dd54c712e8f687221a93d34f8b66cd240917d54659...[truncated]
(This signature proves the Lawyer sent the message)

--- Step 4: Decrypt Document ---
Decryption Successful!
--------------------
Original Message: Test legal document
--------------------

--- Step 5: Verify Signature ---
Verifying signature for message: 'Test legal document '
Verification Result:
[VALID] SIGNATURE: The message is authentic and from the Lawyer.

Exiting...
```