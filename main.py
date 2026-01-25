import os
import sys
from rsa_utils import (
    generate_keys,
    save_key_to_file,
    encrypt_message,
    decrypt_message,
    sign_message,
    verify_signature
)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    print("="*60)
    print("RSA Secure Legal Document Communication System".center(60))
    print("="*60)

def main():
    # Session state
    current_message = None
    current_ciphertext = None
    current_signature = None
    
    # File paths
    lawyer_priv = "lawyer_private.pem"
    lawyer_pub = "lawyer_public.pem"
    client_priv = "client_private.pem"
    client_pub = "client_public.pem"

    while True:
        print_header()
        print("\nSelect an operation:")
        print("1. [Setup] Generate Keys for Lawyer and Client")
        print("2. [Sender] Encrypt Document (Confidentiality)")
        print("3. [Sender] Sign Document (Authentication)")
        print("4. [Receiver] Decrypt Document")
        print("5. [Receiver] Verify Signature")
        print("6. Exit")
        
        choice = input("\nEnter choice (1-6): ").strip()
        
        try:
            if choice == '1':
                print("\n--- Generating Keys ---")
                # Lawyer keys
                l_priv, l_pub = generate_keys()
                save_key_to_file(l_priv, lawyer_priv)
                save_key_to_file(l_pub, lawyer_pub)
                print(f"Lawyer keys saved to {lawyer_priv}, {lawyer_pub}")
                
                # Client keys
                c_priv, c_pub = generate_keys()
                save_key_to_file(c_priv, client_priv)
                save_key_to_file(c_pub, client_pub)
                print(f"Client keys saved to {client_priv}, {client_pub}")
                
                print("\nSetup Complete!")

            elif choice == '2':
                print("\n--- Encrypt Document ---")
                if not os.path.exists(client_pub):
                    print("Error: Client Public Key not found. Please run Option 1 first.")
                else:
                    msg = input("Enter the legal document text to send: ")
                    current_message = msg # Store original for signature check later if needed
                    
                    # Encrypt using Client's Public Key
                    current_ciphertext = encrypt_message(client_pub, msg)
                    
                    print("\nEncryption Successful!")
                    print(f"Ciphertext (Hex): {current_ciphertext.hex()[:60]}...[truncated]")
                    print("(This ciphertext can only be decrypted by the Client's Private Key)")

            elif choice == '3':
                print("\n--- Sign Document ---")
                if not os.path.exists(lawyer_priv):
                    print("Error: Lawyer Private Key not found. Please run Option 1 first.")
                elif not current_message:
                    print("Error: No message content defined. Please run Option 2 (Encrypt) first to define the message, or type it now.")
                    confirm = input("Do you want to sign the message used in Option 2? (y/n): ")
                    if confirm.lower() != 'y':
                        current_message = input("Enter the message to sign: ")
                
                if current_message:
                    # Sign using Lawyer's Private Key
                    current_signature = sign_message(lawyer_priv, current_message)
                    print("\nSigning Successful!")
                    print(f"Digital Signature (Hex): {current_signature.hex()[:60]}...[truncated]")
                    print("(This signature proves the Lawyer sent the message)")

            elif choice == '4':
                print("\n--- Decrypt Document ---")
                if not os.path.exists(client_priv):
                    print("Error: Client Private Key not found. Please run Option 1 first.")
                elif current_ciphertext is None:
                    print("Error: No ciphertext in memory. Please run Option 2 first.")
                else:
                    try:
                        decrypted_msg = decrypt_message(client_priv, current_ciphertext)
                        current_message = decrypted_msg # Update memory for verification step
                        print("\nDecryption Successful!")
                        print("-" * 20)
                        print(f"Original Message: {decrypted_msg}")
                        print("-" * 20)
                    except ValueError:
                        print("\nError: Decryption failed. Incorrect key or corrupted ciphertext.")

            elif choice == '5':
                print("\n--- Verify Signature ---")
                if not os.path.exists(lawyer_pub):
                    print("Error: Lawyer Public Key not found. Please run Option 1 first.")
                elif current_signature is None:
                    print("Error: No signature in memory. Please run Option 3 first.")
                else:
                    # We need the message to verify the signature against. 
                    # In a real scenario, the receiver decrypts the message first, then verifies.
                    
                    msg_to_verify = None
                    if current_message:
                         print(f"Verifying signature for message: '{current_message}'")
                         msg_to_verify = current_message
                    else:
                        msg_to_verify = input("Enter the message content to verify against: ")

                    is_valid = verify_signature(lawyer_pub, msg_to_verify, current_signature)
                    
                    print("\nVerification Result:")
                    if is_valid:
                        print("[VALID] SIGNATURE: The message is authentic and from the Lawyer.")
                    else:
                        print("[INVALID] SIGNATURE: The message may have been tampered with or is from an unknown sender.")

            elif choice == '6':
                print("Exiting...")
                sys.exit(0)
            
            else:
                print("Invalid option. Please try again.")

        except Exception as e:
            print(f"\nAn unexpected error occurred: {e}")
        
        input("\nPress Enter to continue...")
        print("\n" * 2)

if __name__ == "__main__":
    main()
