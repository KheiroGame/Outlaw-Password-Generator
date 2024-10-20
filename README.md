
---

# Outlaw Password Generator

**Outlaw Password Manager** is a secure password management tool that allows users to generate, encrypt, save, and manage their passwords, all protected by a master password. The project supports both English and French languages and includes several key features designed for ease of use and security.

## Key Features:
- **Master Password Protection**: Protect all your passwords using a master password. The master password is hashed using SHA-256, and the passwords are encrypted with Fernet encryption.
- **Password Generation**: Generate strong random passwords with customizable options such as including symbols and setting password length.
- **Encrypted Local Storage**: All passwords are securely stored locally in an encrypted file (`passwords.enc`). There is **no internet connection required**, ensuring that your passwords are never uploaded or sent to any server, providing **maximum security** and privacy.
- **Multi-language Support**: Switch between English and French with a single button click. The tool dynamically updates its interface to match the selected language.
- **Copy Passwords**: Copy generated or stored passwords directly to your clipboard for easy use.
- **Subscription Management**: Keep track of whether the stored passwords are for services with active subscriptions.
- **Password Display Toggle**: Show or hide the stored passwords with a toggle button, ensuring privacy when needed.
- **Delete Passwords**: Securely delete passwords with master password verification.
- **Customizable UI**: The tool offers fullscreen and windowed modes, and the GUI can be resized or centered on the screen.

## How It Works:
1. **Master Password**: Upon first use, the user is prompted to create a master password. This password will be used to derive an encryption key for securely storing and retrieving passwords.
2. **Password Management**: Users can generate passwords for various applications, encrypt them, and save them to a file. These saved passwords can be listed, displayed, copied, or deleted, with master password verification required for deletion.
3. **No Internet Connection Needed**: The application operates entirely offline, meaning no passwords or sensitive information are ever uploaded to any server. All passwords are securely stored **locally** on your device.
4. **Language Support**: The tool supports both French and English, with an easy toggle button that switches between languages and updates all interface labels.

## Ready to Use:
The application is provided as a standalone `.exe` file. No additional installation or setup is required—just open the executable and start managing your passwords securely.


---

