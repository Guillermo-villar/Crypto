import os
import json
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# Función para guardar credenciales en un archivo JSON
def guardar_enJSON(credenciales, archivo):
    with open(archivo, 'w') as file:
        json.dump(credenciales, file, indent=4)
    messagebox.showinfo("Guardado", f"Credenciales guardadas en {archivo}")

# Función para cargar credenciales existentes del archivo JSON
def cargar_deJSON(archivo):
    try:
        with open(archivo, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

# Función para hashear la contraseña con Scrypt
def hashear_contraseña(contraseña, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(contraseña.encode())

# Función para verificar la contraseña con Scrypt
def verificar_contraseña(contraseña, salt, hash_guardado):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    try:
        kdf.verify(contraseña.encode(), bytes.fromhex(hash_guardado))
        return True
    except:
        return False
    

# Función para agregar credenciales a la lista y guardarlas
def agregar_credenciales(usuario, contraseña, archivo_json):
    credenciales_guardadas = cargar_deJSON(archivo_json)

    # Generar un nuevo salt aleatorio para este usuario
    salt = os.urandom(16).hex()
    hash_contraseña = hashear_contraseña(contraseña, bytes.fromhex(salt)).hex()

    nueva_credencial = {"usuario": usuario, "salt": salt, "contraseña": hash_contraseña}
    credenciales_guardadas.append(nueva_credencial)
    os.mkdir("Users/" + usuario)
    guardar_enJSON(credenciales_guardadas, archivo_json)

    
def guardar_credencial(usuario, contraseña):
    if usuario and contraseña:
        agregar_credenciales(usuario, contraseña, "credenciales.json")
        messagebox.showinfo("Éxito", "Usuario registrado correctamente.")
    else:
        messagebox.showwarning("Advertencia", "Por favor, completa todos los campos.")
