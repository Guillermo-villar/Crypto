import os
import json
import tkinter as tk
import random, string
from tkinter import messagebox, Toplevel, filedialog
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import subprocess



def generar_contraseña(longitud=16):
    caracteres = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(random.choice(caracteres) for _ in range(longitud))

def obtener_contraseña_CA(archivo_json="clave_CA.json"):
    # Si el archivo ya existe, leer la contraseña desde el archivo
    if os.path.exists(archivo_json):
        with open(archivo_json, "r") as archivo:
            datos = json.load(archivo)
            return datos.get("contraseña_CA")
    
    # Si no existe, generar una nueva contraseña
    contraseña = generar_contraseña()
    datos = {"contraseña_CA": contraseña}
    
    # Guardar la contraseña en el archivo JSON
    with open(archivo_json, "w") as archivo:
        json.dump(datos, archivo, indent=4)
    
    return contraseña

def generar_CA_openssl(contraseña_CA):
    nombre_CA = "CA_Cripto"
    carpeta_CA = "Users/CA"
    if not os.path.exists(carpeta_CA):
        os.makedirs(carpeta_CA)

        # Rutas de los archivos de la CA
        ruta_clave_privada_CA = os.path.join(carpeta_CA, "clave_privada_CA.pem")
        ruta_certificado_CA = os.path.join(carpeta_CA, "certificado_CA.pem")

        # Comando para generar la clave privada de la CA
        subprocess.run([
            "openssl", "genrsa", "-aes256", "-out", ruta_clave_privada_CA, "-passout", f"pass:{contraseña_CA}", "2048"
        ])

        # Comando para generar el certificado autofirmado de la CA
        subprocess.run([
            "openssl", "req", "-new", "-x509", "-key", ruta_clave_privada_CA,
            "-sha256", "-days", "3650", "-out", ruta_certificado_CA,
            "-subj", f"/C=ES/ST=Madrid/L=Madrid/O=MiCA/CN={nombre_CA}",
            "-passin", f"pass:{contraseña_CA}"
        ])

        return ruta_clave_privada_CA, ruta_certificado_CA


contraseña_CA = obtener_contraseña_CA()

generar_CA_openssl(contraseña_CA)


#Funciones para Firma y Cifrado
def generar_par_claves(usuario, contraseña):
    # Generar un par de claves RSA
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    clave_publica = clave_privada.public_key()

    # Serializar la clave privada con cifrado usando la contraseña del usuario
    clave_privada_pem = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(contraseña.encode())
    )

    # Serializar la clave pública sin cifrar
    clave_publica_pem = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Crear carpeta "claves" dentro de la carpeta del usuario si no existe
    carpeta_claves = os.path.join("Users", usuario, "claves")
    if not os.path.exists(carpeta_claves):
        os.makedirs(carpeta_claves)

    # Guardar las claves en la carpeta "claves"
    ruta_clave_publica = os.path.join(carpeta_claves, "clave_publica.pem")
    ruta_clave_privada = os.path.join(carpeta_claves, "clave_privada.pem")

    with open(ruta_clave_publica, "wb") as pub_file:
        pub_file.write(clave_publica_pem)

    with open(ruta_clave_privada, "wb") as priv_file:
        priv_file.write(clave_privada_pem)

    return ruta_clave_publica, ruta_clave_privada


