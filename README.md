# Crypto Manager: Secure 🔒 Credential and File Sharing System

**Crypto Manager** is a Python application built with **Tkinter** that allows users to securely manage credentials and share files. The app uses robust cryptographic methods to ensure the security and confidentiality of user data and files.

## Features

- **Secure Credential Storage**:  
  User credentials are stored in a JSON file with hashed passwords (bcrypt) and unique salts for each user.

- **File Encryption & Sharing**:  
  - Uses **AES-GCM** mixed with **RSA-128** for file encryption to provide data confidentiality and integrity.  
  - Stores encryption metadata in a JSON file to manage user access.
  - A Custom Certificate system makes sure each User has their own certificate and private keys for added security.

- **Master Key Security**:  
  A master key ensures all sensitive operations are protected.

- **User-Friendly Interface**:  
  - Register new users with securely hashed credentials.  
  - Upload and share `.txt` files between users.  
  - Navigate user folders with a graphical interface.  

- **Custom User Folders**:  
  - Each user has a personal folder within a main directory (`Users`).  
  - View and access shared folders in the interface.  

## Installation

Follow these steps to set up the project locally.

1. Clone the repository:

    ```bash
    git clone https://github.com/Guillermo-villar/Crypto-safe-Fileshare-App.git
    cd crypto-manager
    ```

2. Create and activate a virtual environment:

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Linux/Mac
    venv\Scripts\activate     # On Windows
    ```

3. Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Launch the application:

    ```bash
    python app.py
    ```

2. Use the graphical interface to:  
   - Register new users with securely hashed credentials.  
   - Login and access the secure file-sharing system.  
   - Upload, encrypt, and share files with other users.  

## Dependencies

- Tkinter (for the GUI)
- bcrypt (for password hashing)
- cryptography (for file encryption with AES-GCM)
- Python 3.10 or higher is recommended.

## Contributing

We welcome contributions! Follow these steps:  
1. Fork the repository.  
2. Create a new branch (`git checkout -b feature/new-feature`).  
3. Commit your changes and push the branch.  
4. Open a pull request.  

## License

This project is licensed under the MIT License. Developed by Guillermo Villar, Jonhatan and George Hallak.

---

**Crypto Manager** ensures your data is secure, encrypted, and easy to share. Feel free to share your feedback and suggestions!
