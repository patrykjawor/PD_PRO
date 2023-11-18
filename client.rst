====================================
Python GUI Application Documentation
====================================

Introduction
------------

This documentation provides an overview of a Python application built using the `tkinter` library and other modules. The application implements a client-side interface for a file storage system with user authentication and encryption features.

Features
--------

The Python application includes the following features:

- User registration and login: Users can register with a username, email, and password, and subsequently log in using their credentials.

- Two-factor authentication (2FA): After successful login, users are prompted to authorize their access using a one-time password (OTP) received via email.

- File management: Users can upload and download files to/from the file storage system.

- File encryption: The application encrypts uploaded files using the `cryptography` module and a generated encryption key.

- File integrity check: The application calculates the SHA256 hash of uploaded files for integrity verification.

Dependencies
------------

The application relies on the following Python modules:

- `tkinter`: A standard GUI library for creating graphical user interfaces.

- `requests`: A module for making HTTP requests and handling responses.

- `hashlib`: A module for working with cryptographic hash functions.

- `os.path`: A module for manipulating file paths.

- `tkinter.messagebox`: A module for displaying message boxes in the GUI.

- `tkinter.filedialog`: A module for opening file dialogs in the GUI.

- `cryptography.fernet`: A module for symmetric encryption using the Fernet algorithm.

- `os`: A module for interacting with the operating system.

- `pickle`: A module for serializing and deserializing Python objects.

- `ttkthemes`: A module for applying themes to the `tkinter` GUI.

Usage
-----

To run the application, execute the main Python script. The application will launch a GUI interface with options to register, log in, and perform file operations.

For user registration, enter a username, email, and password. Click the "Register" button to send the registration request to the server.

For user login, enter a username or email and password. Click the "Login" button to send the login request to the server. If successful, the application will prompt for the OTP code received via email.

After successful login, the application displays a list of files available for the logged-in user. Users can upload and download files using the corresponding buttons. The application encrypts uploaded files and verifies their integrity during download using the SHA256 hash.

To log out, click the "Logout" button.

Limitations
-----------

The application has the following limitations:

- The application requires a CA certificate file (`ca.crt`) for SSL/TLS verification.

- The application generates and stores an encryption key in a file (`key_file.key`) on the local machine. The key is required for encrypting and decrypting files.

- The application uses the `ttkthemes` module to apply a specific theme ("arc") to the GUI. Ensure the module is installed for proper visual styling.

Conclusion
----------

The Python application provides a user-friendly interface for a file storage system with user authentication, encryption, and integrity checks. The provided code can be further extended and integrated with server-side components to create a complete file storage solution.

For more details on the application's code and implementation, refer to the provided source code.