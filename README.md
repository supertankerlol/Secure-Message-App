# Secure Messaging Application

A fully end-to-end encrypted messaging system implemented in Python, featuring:

- AES-256-GCM message encryption  
- RSA-2048-OAEP key exchange  
- RSA-PSS digital signatures  
- PBKDF2-HMAC-SHA256 password-based private key encryption  
- bcrypt password hashing  
- Custom HMAC-SHA256 implementation  
- GUI (Tkinter) & CLI interface  
- Local JSON-based message and user storage  

This project demonstrates **practical applied cryptography**, hybrid encryption, secure key management, and GUI-based message handling.


## Project Structure


## Features

### Security  
- AES-256-GCM authenticated encryption  
- RSA-2048 keypair per user  
- RSA-OAEP secure AES key exchange  
- RSA-PSS signatures for message authenticity  
- Custom HMAC-SHA256 for message integrity  
- Private keys encrypted using PBKDF2 + AES-GCM  
- bcrypt password hashing  

### Two Interfaces  
- **CLI interface**  
- **Tkinter GUI version**  

### Persistent Storage  
- Local storage using JSON files  
- Works without external services

  
# Installation Instructions

### 1. Clone the repository

```bash
git clone https://github.com/<yourname>/<repo>.git
cd SecureMessageApp

