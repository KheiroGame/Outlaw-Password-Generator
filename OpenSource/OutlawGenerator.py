import os
import random
import string
import hashlib
from cryptography.fernet import Fernet, InvalidToken  # Ajout d'InvalidToken ici
from base64 import urlsafe_b64encode
import tkinter as tk
from tkinter import messagebox

# Dictionnaire de traduction
translations = {
    'fr': {
        'title': "Outlaw Gestionnaire de Mot de Passe",
        'generate_password': "Générer le mot de passe",
        'app_name': "Nom de l'application:",
        'username': "Nom d'utilisateur:",
        'subscription_active': "Abonnement actif",
        'include_symbols': "Inclure des symboles",
        'length': "Longueur:",
        'save_success': "Mot de passe sauvegardé pour",
        'error': "Erreur",
        'fill_fields': "Veuillez remplir tous les champs.",
        'quit': "Voulez-vous vraiment quitter?",
        'confirm': "Confirmer",
        'confirm_delete': "Entrez le mot de passe maître pour confirmer :",
        'delete': "Supprimer",
        'show': "Afficher",
        'hide': "Masquer",
        'copy': "Copier",
        'close': "Quitter",
        'password_copied': "Mot de passe copié dans le presse-papiers.",
        'confirm_password': "Confirmer",
        'validation_error': "Mot de passe maître incorrect.",
        'language_button': "English",
        'master_password_error': "Attention, le mot de passe que vous avez tenté de générer sera impossible à lire. Veuillez vérifier votre mot de passe maître avant de réessayer.",
        'create_master_password': "Créer votre mot de passe maître:"
    },
    'en': {
        'title': "Outlaw Password Manager",
        'generate_password': "Generate Password",
        'app_name': "Application Name:",
        'username': "Username:",
        'subscription_active': "Active Subscription",
        'include_symbols': "Include Symbols",
        'length': "Length:",
        'save_success': "Password saved for",
        'error': "Error",
        'fill_fields': "Please fill all fields.",
        'quit': "Do you really want to quit?",
        'confirm': "Confirm",
        'confirm_delete': "Enter master password to confirm:",
        'delete': "Delete",
        'show': "Show",
        'hide': "Hide",
        'copy': "Copy",
        'close': "Close",
        'password_copied': "Password copied to clipboard.",
        'confirm_password': "Confirm",
        'validation_error': "Incorrect master password.",
        'language_button': "Français",
        'master_password_error': "Warning, the password you attempted to generate will be unreadable. Please check your master password and try again.",
        'create_master_password': "Create your master password:"
    }
}

# Variable pour stocker la langue actuelle
current_language = 'en'

# Fonction pour mettre à jour les textes
def update_language():
    title_label.config(text=translations[current_language]['title'])
    generate_button.config(text=translations[current_language]['generate_password'])
    app_label.config(text=translations[current_language]['app_name'])
    user_label.config(text=translations[current_language]['username'])
    subscription_check.config(text=translations[current_language]['subscription_active'])
    symbol_check.config(text=translations[current_language]['include_symbols'])
    length_label.config(text=translations[current_language]['length'])
    language_button.config(text=translations[current_language]['language_button'])

# Fonction pour basculer entre les langues
def toggle_language():
    global current_language
    current_language = 'en' if current_language == 'fr' else 'fr'
    update_language()  # Met à jour les textes après changement de langue

# Fonction pour centrer une fenêtre sur l'écran
def center_window(window, width=800, height=600):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    window.geometry(f"{width}x{height}+{x}+{y}")

# Fonction pour générer le mot de passe en fonction des options sélectionnées
def generate_password(length=16, use_symbols=True):
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += string.punctuation  # Ajouter des symboles si la case est cochée
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

# Fonction pour enregistrer le mot de passe généré et l'état de l'abonnement
def save_password(application, username, password, is_active):
    encrypted_username = encrypt_message(username, key)
    encrypted_password = encrypt_message(password, key)

    with open("passwords.enc", "a") as file:
        file.write(f"{application}||{encrypted_username.decode()}||{encrypted_password.decode()}||{is_active}\n")
    
    messagebox.showinfo(translations[current_language]['save_success'], 
                        f"{translations[current_language]['save_success']} {application} et l'utilisateur {username}.")
    update_password_list()

# Fonction pour générer et enregistrer le mot de passe
def generate_and_save_password():
    application = app_entry.get()
    username = user_entry.get()

    if not application or not username:
        messagebox.showwarning(translations[current_language]['error'], translations[current_language]['fill_fields'])
        return

    # Récupérer les paramètres sélectionnés
    use_symbols = symbol_var.get() == 1  # Vérifier si la case des symboles est cochée
    length = 16 if length_var.get() == 1 else 12  # Longueur 12 ou 16 caractères

    password = generate_password(length=length, use_symbols=use_symbols)
    
    # Récupérer l'état de la case à cocher de l'abonnement
    is_active = 1 if subscription_var.get() == 1 else 0
    
    try:
        # Sauvegarde du mot de passe généré
        print("Tentative de sauvegarde du mot de passe")
        save_password(application, username, password, is_active)
        print("Mot de passe sauvegardé avec succès")
    except InvalidToken:
        print("Erreur InvalidToken détectée")
        messagebox.showerror(translations[current_language]['error'], 
                             translations[current_language]['master_password_error'])
        return

# Fonction pour lister les mots de passe enregistrés
def list_applications():
    if not os.path.exists("passwords.enc"):
        return []

    applications = []
    with open("passwords.enc", "r") as file:
        lines = file.readlines()
        for line in lines:
            parts = line.strip().split("||")
            if len(parts) == 3:
                app_name, encrypted_username, encrypted_password = parts
                is_active = "0"  # Par défaut, inactif si non précisé
            elif len(parts) == 4:
                app_name, encrypted_username, encrypted_password, is_active = parts
            else:
                print(f"Ligne mal formatée : {line}")
                continue
            applications.append((app_name, encrypted_username, encrypted_password, is_active))
    
    return applications

# Fonction pour afficher/masquer le mot de passe
def toggle_display(app_frame, app_choice, username_choice, button):
    if button.cget("text") == translations[current_language]['show']:
        with open("passwords.enc", "r") as file:
            lines = file.readlines()
            for line in lines:
                parts = line.strip().split("||")
                if len(parts) == 3:
                    app_name, encrypted_username, encrypted_password = parts
                elif len(parts) == 4:
                    app_name, encrypted_username, encrypted_password, is_active = parts
                else:
                    continue

                if app_name == app_choice and encrypted_username == username_choice:
                    username = decrypt_message(encrypted_username.encode(), key)
                    password = decrypt_message(encrypted_password.encode(), key)

                    # Afficher les valeurs déchiffrées
                    button.username_label.config(text=username)
                    button.password_label.config(text=password)
                    button.config(text=translations[current_language]['hide'])

                    # Stocker le mot de passe déchiffré dans l'objet app_frame pour le copier plus tard
                    app_frame.real_password = password

                    # Met à jour le bouton copier pour copier le mot de passe déchiffré
                    app_frame.copy_button.config(command=lambda: copy_to_clipboard(app_frame.real_password, main_window))
    else:
        button.username_label.config(text="****")
        button.password_label.config(text="****")
        button.config(text=translations[current_language]['show'])
        # Toujours utiliser le mot de passe réel, même s'il est masqué
        app_frame.copy_button.config(command=lambda: copy_to_clipboard(app_frame.real_password, main_window))

# Fonction pour copier le mot de passe dans le presse-papiers
def copy_to_clipboard(password, window):
    window.clipboard_clear()
    window.clipboard_append(password)
    messagebox.showinfo(translations[current_language]['copy'], translations[current_language]['password_copied'])

# Fonction pour demander la confirmation avec le mot de passe maître avant suppression
def confirm_delete_password(app_name, encrypted_username):
    def check_master_password():
        entered_password = password_entry.get()

        # Hacher le mot de passe saisi et vérifier s'il correspond au mot de passe maître stocké
        hashed_input = hashlib.sha256(entered_password.encode()).hexdigest()
        
        if key.decode() == urlsafe_b64encode(hashlib.sha256(entered_password.encode()).digest()).decode():
            # Mot de passe correct, on supprime
            delete_password(app_name, encrypted_username)
            master_prompt.destroy()
        else:
            messagebox.showerror(translations[current_language]['error'], translations[current_language]['validation_error'])
            master_prompt.destroy()

    # Fenêtre pour demander le mot de passe maître
    master_prompt = tk.Toplevel(main_window)
    master_prompt.title(translations[current_language]['confirm'])
    center_window(master_prompt, 300, 150)

    prompt_label = tk.Label(master_prompt, text=translations[current_language]['confirm_delete'])
    prompt_label.pack(pady=10)

    password_entry = tk.Entry(master_prompt, show="*", width=30)
    password_entry.pack(pady=5)

    confirm_button = tk.Button(master_prompt, text=translations[current_language]['confirm'], command=check_master_password)
    confirm_button.pack(pady=10)

# Fonction pour supprimer un mot de passe
def delete_password(app_name, encrypted_username):
    with open("passwords.enc", "r") as file:
        lines = file.readlines()

    with open("passwords.enc", "w") as file:
        for line in lines:
            parts = line.strip().split("||")
            if len(parts) == 3:
                stored_app_name, stored_encrypted_username, stored_encrypted_password = parts
            elif len(parts) == 4:
                stored_app_name, stored_encrypted_username, stored_encrypted_password, stored_is_active = parts

            # Si l'application et le nom d'utilisateur ne correspondent pas, on garde la ligne
            if stored_app_name == app_name and stored_encrypted_username == encrypted_username:
                continue  # Ne pas réécrire cette ligne pour la supprimer

            # Réécrire les lignes non supprimées
            file.write(line + "\n")

    update_password_list()  # Mettre à jour la liste après suppression

# Fonction pour mettre à jour la liste des mots de passe affichés
def update_password_list():
    for widget in password_frame.winfo_children():
        widget.destroy()

    apps = list_applications()
    if apps:
        for app_name, encrypted_username, encrypted_password, is_active in apps:
            app_frame = tk.Frame(password_frame, bg="white", bd=1, relief="solid")
            app_frame.pack(fill="x", padx=5, pady=5)

            delete_button = tk.Button(app_frame, text=translations[current_language]['delete'], 
                                      command=lambda a=app_name, u=encrypted_username: confirm_delete_password(a, u))
            delete_button.grid(row=0, column=0, sticky="nsew")

            app_label = tk.Label(app_frame, text=app_name, width=20, relief="solid", borderwidth=1)
            app_label.grid(row=0, column=1, sticky="nsew")

            username_label = tk.Label(app_frame, text="****", width=20, relief="solid", borderwidth=1)
            username_label.grid(row=0, column=2, sticky="nsew")
            password_label = tk.Label(app_frame, text="****", width=20, relief="solid", borderwidth=1)
            password_label.grid(row=0, column=3, sticky="nsew")

            try:
                # Tentative de déchiffrement des données
                real_username = decrypt_message(encrypted_username.encode(), key)
                real_password = decrypt_message(encrypted_password.encode(), key)
                app_frame.real_password = real_password  # Stocker le mot de passe déchiffré
            except InvalidToken:
                # Si le mot de passe maître est incorrect, afficher un message d'erreur
                messagebox.showerror(translations[current_language]['error'],
                                     translations[current_language]['master_password_error'])
                return

            view_button = tk.Button(app_frame, text=translations[current_language]['show'])
            view_button.username_label = username_label
            view_button.password_label = password_label
            view_button.config(command=lambda a=app_name, u=encrypted_username, f=app_frame, b=view_button: toggle_display(f, a, u, b))
            view_button.grid(row=0, column=4, sticky="nsew")

            copy_button = tk.Button(app_frame, text=translations[current_language]['copy'], 
                                    command=lambda: copy_to_clipboard(app_frame.real_password, main_window))
            copy_button.grid(row=0, column=5, sticky="nsew")

            app_frame.copy_button = copy_button

            subscription_var = tk.IntVar(value=int(is_active))

            subscription_check = tk.Checkbutton(app_frame, text=translations[current_language]['subscription_active'], 
                                                variable=subscription_var, 
                                                command=lambda a=app_name, u=encrypted_username, v=subscription_var: update_subscription_status(a, u, v.get()))
            subscription_check.grid(row=0, column=6, sticky="nsew")


# Fonction pour mettre à jour l'état de l'abonnement
def update_subscription_status(app_name, encrypted_username, is_active):
    with open("passwords.enc", "r") as file:
        lines = file.readlines()

    with open("passwords.enc", "w") as file:
        for line in lines:
            parts = line.strip().split("||")
            if len(parts) == 3:
                stored_app_name, stored_encrypted_username, stored_encrypted_password = parts
                stored_is_active = "0"
            elif len(parts) == 4:
                stored_app_name, stored_encrypted_username, stored_encrypted_password, stored_is_active = parts

            if stored_app_name == app_name and stored_encrypted_username == encrypted_username:
                stored_is_active = str(is_active)

            file.write(f"{stored_app_name}||{stored_encrypted_username}||{stored_encrypted_password}||{stored_is_active}\n")

# Fonction pour gérer la fermeture de l'application
def on_closing():
    if messagebox.askokcancel(translations[current_language]['close'], translations[current_language]['quit']):
        master_window.destroy()  # Fermer la fenêtre principale
        main_window.quit()       # Quitter Tkinter
        main_window.destroy()    # Détruire toute fenêtre restante
        os._exit(0)              # Quitter l'application sans erreur

# Sauvegarde du mot de passe maître
def save_master_password(master_password):
    # Hacher le mot de passe maître, mais ne plus l'enregistrer dans un fichier
    hashed_password = hashlib.sha256(master_password.encode()).hexdigest()
    return hashed_password

# Variable pour indiquer si le mot de passe maître est valide
master_password_valid = False

# Vérification du mot de passe maître
def verify_master_password():
    global key
    global master_password_valid
    master_password_input = master_entry.get()

    if not os.path.exists("passwords.enc"):  # Si c'est la première exécution et qu'on crée un mot de passe maître
        confirm_password = confirm_master_entry.get()  # Vérifier la confirmation uniquement si le champ existe

        if master_password_input == confirm_password:
            key = derive_key_from_master_password(master_password_input)
            master_password_valid = True  # Le mot de passe est correct
            messagebox.showinfo("Succès", translations[current_language]['confirm_password'])
            master_window.destroy()
            open_main_window()
        else:
            master_password_valid = False  # Mauvais mot de passe maître
            messagebox.showerror(translations[current_language]['error'], translations[current_language]['validation_error'])
    else:  # Si le fichier existe déjà, on vérifie simplement le mot de passe saisi
        key = derive_key_from_master_password(master_password_input)
        try:
            # Test pour voir si la clé fonctionne en essayant de déchiffrer un ancien mot de passe (facultatif, à adapter)
            if list_applications():  # Teste s'il y a des mots de passe à déchiffrer
                decrypt_message(list_applications()[0][1].encode(), key)
            master_password_valid = True
            master_window.destroy()
            open_main_window()
        except InvalidToken:
            master_password_valid = False  # Mauvais mot de passe maître
            messagebox.showerror(translations[current_language]['error'], translations[current_language]['validation_error'])


# Fonction pour activer ou désactiver le plein écran
def toggle_fullscreen(event=None):
    main_window.attributes("-fullscreen", True)

# Fonction pour quitter le plein écran
def end_fullscreen(event=None):
    main_window.attributes("-fullscreen", False)

# Ouvrir la fenêtre principale et configurer le redimensionnement automatique
def open_main_window():
    global main_window
    global password_frame
    global subscription_var
    global symbol_var
    global length_var
    global title_label
    global generate_button
    global app_label
    global user_label
    global symbol_check
    global length_label
    global language_button
    global subscription_check

    main_window = tk.Tk()
    main_window.title(translations[current_language]['title'])
    center_window(main_window, 800, 600)  # Centrer la fenêtre principale

    # Rendre la fenêtre redimensionnable
    main_window.grid_rowconfigure(0, weight=1)
    main_window.grid_columnconfigure(0, weight=1)

    title_label = tk.Label(main_window, text=translations[current_language]['title'], font=("Arial", 16))
    title_label.pack(pady=10)

    # Cadre pour les options de génération
    options_frame = tk.Frame(main_window)
    options_frame.pack(pady=10)

    # Ajouter le bouton de changement de langue
    language_button = tk.Button(main_window, text=translations[current_language]['language_button'], command=toggle_language)
    language_button.place(x=10, y=10)  # Position dans le coin supérieur gauche

    # Case à cocher pour les symboles
    symbol_var = tk.IntVar(value=1)
    symbol_check = tk.Checkbutton(options_frame, text=translations[current_language]['include_symbols'], variable=symbol_var)
    symbol_check.pack(side="left", padx=10)

    # Radio pour la longueur du mot de passe
    length_var = tk.IntVar(value=1)
    length_label = tk.Label(options_frame, text=translations[current_language]['length'])
    length_label.pack(side="left", padx=10)
    length_radio_16 = tk.Radiobutton(options_frame, text="16", variable=length_var, value=1)
    length_radio_12 = tk.Radiobutton(options_frame, text="12", variable=length_var, value=0)
    length_radio_16.pack(side="left", padx=5)
    length_radio_12.pack(side="left", padx=5)

    # Saisie du nom de l'application
    app_label = tk.Label(main_window, text=translations[current_language]['app_name'])
    app_label.pack(pady=5)
    global app_entry
    app_entry = tk.Entry(main_window, width=40)
    app_entry.pack(pady=5)

    user_label = tk.Label(main_window, text=translations[current_language]['username'])
    user_label.pack(pady=5)
    global user_entry
    user_entry = tk.Entry(main_window, width=40)
    user_entry.pack(pady=5)

    # Checkbox pour l'abonnement
    subscription_var = tk.IntVar()
    subscription_check = tk.Checkbutton(main_window, text=translations[current_language]['subscription_active'], variable=subscription_var)
    subscription_check.pack(pady=5)

    # Bouton pour générer et sauvegarder le mot de passe
    generate_button = tk.Button(main_window, text=translations[current_language]['generate_password'], command=generate_and_save_password)
    generate_button.pack(pady=10)

    # Cadre pour afficher les mots de passe enregistrés
    password_frame = tk.Frame(main_window, bg="white", relief="sunken", borderwidth=1)
    password_frame.pack(fill="both", expand=True, padx=10, pady=10)

    update_password_list()  # Mettre à jour la liste des mots de passe

    # Ajouter les fonctionnalités de plein écran
    main_window.bind("<F11>", toggle_fullscreen)
    main_window.bind("<Escape>", end_fullscreen)

    # Appeler update_language après la création de tous les widgets
    update_language()

    main_window.mainloop()

# Fenêtre pour entrer ou créer le mot de passe maître
def show_master_password_window():
    global master_window, master_entry, confirm_master_entry

    master_window = tk.Tk()
    master_window.title(translations[current_language]['confirm_password'])
    center_window(master_window, 350, 250)  # Centrer la fenêtre de connexion

    # Gérer la fermeture correcte
    master_window.protocol("WM_DELETE_WINDOW", on_closing)

    try:
        # Si le fichier passwords.enc existe déjà (donc vérifier le mot de passe maître)
        if os.path.exists("passwords.enc"):
            # Création du label pour entrer le mot de passe maître
            master_label = tk.Label(master_window, text=translations[current_language]['confirm_password'])
            master_label.pack(pady=10)

            # Champ pour entrer le mot de passe maître
            master_entry = tk.Entry(master_window, show="*", width=30)
            master_entry.pack(pady=10)

            # Bouton pour confirmer le mot de passe
            master_button = tk.Button(master_window, text=translations[current_language]['confirm'], command=verify_master_password)
            master_button.pack(pady=10)
        else:
            # Si aucun fichier de mots de passe n'existe, création d'un nouveau mot de passe maître
            create_label_text = translations[current_language]['create_master_password']
            confirm_label_text = translations[current_language]['confirm_password']

            # Label pour indiquer la création du mot de passe maître
            master_label = tk.Label(master_window, text=create_label_text)
            master_label.pack(pady=10)

            # Champ pour entrer le nouveau mot de passe maître
            master_entry = tk.Entry(master_window, show="*", width=30)
            master_entry.pack(pady=10)

            # Label pour la confirmation du mot de passe maître
            confirm_master_label = tk.Label(master_window, text=confirm_label_text)
            confirm_master_label.pack(pady=10)

            # Champ pour confirmer le nouveau mot de passe maître
            confirm_master_entry = tk.Entry(master_window, show="*", width=30)
            confirm_master_entry.pack(pady=10)

            # Avertissement à l'utilisateur sur la mémorisation du mot de passe
            warning_text = (
                "Attention : mémorisez bien votre mot de passe !\n"
                "Sinon, les mots de passe générés seront irrécupérables."
                if current_language == 'fr' else
                "Warning: Remember your password carefully!\n"
                "Otherwise, the generated passwords will be unrecoverable."
            )
            warning_label = tk.Label(master_window, text=warning_text, fg="red")
            warning_label.pack(pady=10)

            # Bouton pour confirmer le nouveau mot de passe maître
            master_button = tk.Button(master_window, text=translations[current_language]['confirm'], command=verify_master_password)
            master_button.pack(pady=10)

    except Exception as e:
        # Affiche un message en cas d'erreur
        messagebox.showerror(translations[current_language]['error'], f"Erreur inattendue : {str(e)}")

    master_window.mainloop()

# Appel de la fonction pour afficher la fenêtre principale
show_master_password_window()

def load_language():
    """Charge la langue sauvegardée depuis un fichier, ou utilise 'fr' par défaut."""
    if os.path.exists("langue.conf"):
        with open("langue.conf", "r") as file:
            language = file.read().strip()
            if language in translations:  # Vérifier si la langue est valide
                return language
    return 'fr'  # Langue par défaut si le fichier n'existe pas ou si la langue est invalide

def save_language():
    """Sauvegarde la langue actuelle dans un fichier."""
    with open("langue.conf", "w") as file:
        file.write(current_language)
