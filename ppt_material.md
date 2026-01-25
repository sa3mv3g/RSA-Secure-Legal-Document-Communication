Here is a complete breakdown of the content for your PowerPoint presentation. I have structured it to cover the **problem**, the **math/logic**, and the **code**, which is exactly what professors look for.

You can copy and paste these sections directly into your slides.

---

### **Slide 1: Title Slide**

* **Title:** Secure Legal Document Communication System
* **Subtitle:** Implementation of RSA Encryption & Digital Signatures
* **Course:** Cryptography & Network Security
* **Group Members:** [Name 1], [Name 2], [Name 3], [Name 4]

---

### **Slide 2: The Problem Scenario**

* **The Scenario:** A Lawyer needs to send a sensitive contract to a Client over an insecure network (like the internet).
* **The Risks:**
1. **Eavesdropping:** Hackers reading the contract.
2. **Tampering:** Hackers changing the settlement amount.
3. **Impersonation:** Someone pretending to be the lawyer.


* **The Solution:** We implemented a system providing:
* **Confidentiality:** Only the client can read it.
* **Authentication:** The client knows *for sure* it came from the lawyer.



---

### **Slide 3: Algorithm Selection (Why RSA?)**

* **Algorithm:** RSA (Rivest–Shamir–Adleman)
* **Type:** Asymmetric Cryptography (Public-Key Cryptography).
* **Why we chose it:**
* Unlike AES (Symmetric), RSA uses **two separate keys**.
* This allows the Lawyer and Client to communicate securely without ever having to meet in person to exchange a secret password.


* **Key Size:** 2048-bits (Industry Standard for security).

---

### **Slide 4: System Architecture (How it Works)**

*(You can draw a simple diagram on the whiteboard for this)*

* **Step 1: Key Generation**
* Lawyer generates `(Public_L, Private_L)`
* Client generates `(Public_C, Private_C)`


* **Step 2: Confidentiality (Encryption)**
* Lawyer uses **Client's Public Key** to lock the message.
* *Result:* Only Client's Private Key can unlock it.


* **Step 3: Authentication (Signing)**
* Lawyer uses **Lawyer's Private Key** to "sign" the hash of the message.
* *Result:* Client uses Lawyer's Public Key to verify the signature.



---

### **Slide 5: Technical Stack**

* **Language:** Python 3.9+
* **Core Library:** `PyCryptodome`
* Chosen for its robust implementation of math primitives compared to the standard `ssl` module.


* **Dependency Management:** `uv` (by Astral)
* We used `uv` instead of standard `pip` for 10-100x faster environment setup and reproducible builds.
* Ensures the project runs identically on every group member's machine.



---

### **Slide 6: Implementation Details - Encryption**

* **Method:** `PKCS1_OAEP` (Optimal Asymmetric Encryption Padding).
* **Why OAEP?**
* Raw RSA is unsafe (encrypting "Hello" twice produces the same ciphertext).
* OAEP adds randomness (padding) before encryption.
* Prevents **Chosen-Ciphertext Attacks**.


* **Code Snippet:**
```python
cipher = PKCS1_OAEP.new(recipient_key)
ciphertext = cipher.encrypt(message)

```



---

### **Slide 7: Implementation Details - Digital Signatures**

* **Hashing:** `SHA-256`
* Creates a unique "fingerprint" of the document.


* **Signature Scheme:** `PSS` (Probabilistic Signature Scheme).
* **Why PSS?**
* More secure than older PKCS#1 v1.5 padding.
* Ensures the signature cannot be forged even if the attacker studies many previous signatures.


* **Code Snippet:**
```python
h = SHA256.new(message)
signer = pss.new(sender_key)
signature = signer.sign(h)

```



---

### **Slide 8: Project Structure**

* **`rsa_utils.py`**: The "Engine." Contains pure cryptographic functions (KeyGen, Encrypt, Sign).
* **`main.py`**: The "Driver." Handles user input and workflow logic.
* **`pyproject.toml`**: The Configuration. Defines dependencies for `uv` to install.

---

### **Slide 9: Conclusion & Future Scope**

* **Summary:** We successfully built a secure CLI tool that ensures confidentiality and authenticity for legal documents.
* **Key Learnings:**
* Difference between Symmetric vs Asymmetric.
* Importance of Padding (OAEP/PSS) in real-world crypto.
* Modern Python tooling (`uv`).


* **Future Scope:**
* Add a Graphical User Interface (GUI) using Tkinter or React.
* Implement Hybrid Encryption (RSA + AES) for faster processing of very large files.



---

### **Speaker Notes (Q&A Prep)**

* **If they ask "Why `uv`?":** "It's a modern replacement for pip/poetry written in Rust. It manages our virtual environment automatically so we don't have dependency conflicts."
* **If they ask "Why 2048 bits?":** "1024-bit RSA is considered broken or weak by modern standards. 2048 is the current NIST recommendation for secure data."
* **If they ask "What is OAEP?":** "It stands for Optimal Asymmetric Encryption Padding. It adds random data to the message so that patterns in the original text don't show up in the encrypted text."