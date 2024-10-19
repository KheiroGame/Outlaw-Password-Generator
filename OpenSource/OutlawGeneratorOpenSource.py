import os
import random
import string
import hashlib
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode

# Génération du mot de passe aléatoire
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Génération d'une clé de chiffrement à partir du mot de passe maître
def derive_key_from_master_password(master_password):
    digest = hashlib.sha256(master_password.encode()).digest()
    return urlsafe_b64encode(digest)

# Chiffrement du texte
def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

# Déchiffrement du texte
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

# Enregistrement des informations dans un fichier crypté
def save_password(application, username, password, key, lang):
    filename = "passwords.enc"
    encrypted_data = encrypt_message(f"Application: {application} - Username: {username} - Password: {password}", key)
    with open(filename, "ab") as file:
        file.write(encrypted_data + b'\n')
    if lang == 'fr':
        print(f"Mot de passe sauvegardé pour {application} avec le nom d'utilisateur {username} dans {filename}.")
    else:
        print(f"Password saved for {application} with username {username} in {filename}.")

# Lecture et déchiffrement du fichier de sauvegarde
def load_passwords(key, lang):
    filename = "passwords.enc"
    if not os.path.exists(filename):
        if lang == 'fr':
            print("Aucun mot de passe sauvegardé.")
        else:
            print("No passwords saved.")
        return
    with open(filename, "rb") as file:
        encrypted_data = file.readlines()
    for line in encrypted_data:
        try:
            decrypted_message = decrypt_message(line.strip(), key)
            print(decrypted_message)
        except:
            if lang == 'fr':
                print("Impossible de déchiffrer certaines données.")
            else:
                print("Unable to decrypt some data.")

# Détection de la langue ou demande lors du premier lancement
def get_language():
    settings_file = "settings.txt"
    if os.path.exists(settings_file):
        with open(settings_file, "r") as file:
            return file.read().strip()
    else:
        lang = input("Choose your language / Choisissez votre langue (en/fr) : ").lower()
        if lang not in ['en', 'fr']:
            lang = 'en'  # Langue par défaut si saisie incorrecte
        with open(settings_file, "w") as file:
            file.write(lang)
        return lang

if __name__ == "__main__":
    lang = get_language()

    if lang == 'fr':
        print("Bienvenue dans le générateur de mot de passe sécurisé !")
    else:
        print("Welcome to the secure password generator!")

    # Demander le mot de passe maître à chaque lancement pour générer la clé de chiffrement
    if lang == 'fr':
        master_password = input("Entrez/Créé votre mot de passe maître : ")
    else:
        master_password = input("Enter/Create your master password: ")
        
    key = derive_key_from_master_password(master_password)

    # Options du menu
    while True:
        if lang == 'fr':
            print("\nOptions :")
            print("1. Générer un nouveau mot de passe")
            print("2. Afficher tous les mots de passe")
            print("3. Quitter")
            choix = input("Choisissez une option : ")
        else:
            print("\nOptions:")
            print("1. Generate a new password")
            print("2. Display all passwords")
            print("3. Quit")
            choix = input("Choose an option: ")

        if choix == "1":
            if lang == 'fr':
                application = input("Entrez le nom de l'application : ")
                username = input("Entrez le nom d'utilisateur : ")
            else:
                application = input("Enter the application name: ")
                username = input("Enter the username: ")
                
            password = generate_password()
            if lang == 'fr':
                print(f"Mot de passe généré pour {application} : {password}")
            else:
                print(f"Password generated for {application}: {password}")
                
            save_password(application, username, password, key, lang)

        elif choix == "2":
            load_passwords(key, lang)

        elif choix == "3":
            if lang == 'fr':
                print("Fermeture du générateur.")
            else:
                print("Exiting the generator.")
            break

        else:
            if lang == 'fr':
                print("Choix invalide. Veuillez réessayer.")
            else:
                print("Invalid choice. Please try again.")
