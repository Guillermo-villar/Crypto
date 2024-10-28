import os
import json
import tkinter as tk
from tkinter import messagebox, Toplevel, filedialog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Userstk import cargar_deJSON, hashear_contraseña, verificar_contraseña, agregar_credenciales

def cargar_clave_maestra():
    archivo_clave = "clave_maestra.json"
    if os.path.exists(archivo_clave):
        with open(archivo_clave, 'r') as f:
            data = json.load(f)
            return bytes.fromhex(data["clave_maestra"]), bytes.fromhex(data["salt_maestro"])
    else:
        texto_clave_maestra = "Texto muy secreto de la clave maestra muy segura"
        salt_maestro = os.urandom(16).hex()
        clave_maestra = hashear_contraseña(texto_clave_maestra, bytes.fromhex(salt_maestro))
        with open(archivo_clave, 'w') as f:
            json.dump({"clave_maestra": clave_maestra.hex(), "salt_maestro": salt_maestro}, f)
        return clave_maestra, bytes.fromhex(salt_maestro)

clave_maestra, salt_maestro = cargar_clave_maestra()

def cifrar_clave_aes(clave_aes):
    cipher = Cipher(algorithms.AES(clave_maestra), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    clave_cifrada = encryptor.update(clave_aes) + encryptor.finalize()
    return clave_cifrada

def descifrar_clave_aes(clave_cifrada):
    cipher = Cipher(algorithms.AES(clave_maestra), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    clave_aes_descifrada = decryptor.update(clave_cifrada) + decryptor.finalize()
    return clave_aes_descifrada

def cifrar_datos_aes_gcm(data, associated_data=None, bit_length=128):
    key = AESGCM.generate_key(bit_length=bit_length)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data)
    return key, nonce, ciphertext

def descifrar_datos_aes_gcm(key, nonce, ciphertext, associated_data=None):
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except Exception as e:
        print(f"Error en la descodificación: {e}")
        return None

def guardar_informacion_cifrado(usuario, nombre_archivo, clave, nonce):
    archivo_info = "informacion_cifrado.json"
    try:
        with open(archivo_info, 'r') as f:
            informacion_cifrado = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        informacion_cifrado = {"documentos": {}}

    if nombre_archivo not in informacion_cifrado["documentos"]:
        informacion_cifrado["documentos"][nombre_archivo] = {
            "clave": cifrar_clave_aes(clave).hex(),
            "nonce": nonce.hex(),
            "usuarios": [usuario]
        }
    else:
        if usuario not in informacion_cifrado["documentos"][nombre_archivo]["usuarios"]:
            informacion_cifrado["documentos"][nombre_archivo]["usuarios"].append(usuario)

    with open(archivo_info, 'w') as f:
        json.dump(informacion_cifrado, f, indent=4)

def verificar_acceso_usuario(usuario, nombre_archivo):
    try:
        with open("informacion_cifrado.json", 'r') as f:
            informacion_cifrado = json.load(f)
        if "documentos" not in informacion_cifrado:
            return False
        return nombre_archivo in informacion_cifrado["documentos"] and usuario in informacion_cifrado["documentos"][nombre_archivo]["usuarios"]
    except FileNotFoundError:
        return False

def seleccionar_archivo(usuario):
    archivo = filedialog.askopenfilename(
        title="Selecciona un archivo .txt",
        filetypes=[("Archivos de texto", "*.txt")]
    )
    if archivo:
        with open(archivo, "rb") as file:
            contenido = file.read()
        clave, nonce, contenido_cifrado = cifrar_datos_aes_gcm(contenido, b"Archivo de usuario")
        ruta_destino = os.path.join("Users", usuario, os.path.basename(archivo) + ".enc")
        with open(ruta_destino, "wb") as file:
            file.write(contenido_cifrado)
        guardar_informacion_cifrado(usuario, os.path.basename(archivo), clave, nonce)
        messagebox.showinfo("Éxito", f"Archivo {os.path.basename(archivo)} cifrado y subido correctamente a la carpeta de {usuario}")
        print(f"Archivo cifrado guardado en: {ruta_destino}")
        print(f"Clave (hex): {clave.hex()}")
        print(f"Nonce (hex): {nonce.hex()}")

def compartir_documento(usuario, nombre_archivo, usuario_a_compartir):
    try:
        with open("informacion_cifrado.json", 'r') as f:
            informacion_cifrado = json.load(f)
        if nombre_archivo in informacion_cifrado["documentos"]:
            if usuario in informacion_cifrado["documentos"][nombre_archivo]["usuarios"]:
                if usuario_a_compartir not in informacion_cifrado["documentos"][nombre_archivo]["usuarios"]:
                    informacion_cifrado["documentos"][nombre_archivo]["usuarios"].append(usuario_a_compartir)
                    with open("informacion_cifrado.json", 'w') as f:
                        json.dump(informacion_cifrado, f, indent=4)
                    messagebox.showinfo("Éxito", f"El archivo {nombre_archivo} ha sido compartido con {usuario_a_compartir}.")
                else:
                    messagebox.showinfo("Información", f"{usuario_a_compartir} ya tiene acceso a este archivo.")
            else:
                messagebox.showerror("Error", "No tienes permisos para compartir este documento.")
    except FileNotFoundError:
        messagebox.showerror("Error", "El archivo de información de cifrado no fue encontrado.")

def editar_documento(usuario, nombre_archivo):
    if verificar_acceso_usuario(usuario, nombre_archivo):
        ruta_archivo = None
        for root_dir, dirs, files in os.walk("Users"):
            if nombre_archivo + ".enc" in files:
                ruta_archivo = os.path.join(root_dir, nombre_archivo + ".enc")
                break
        if ruta_archivo is None:
            messagebox.showerror("Error", "No se encontró el archivo cifrado.")
            return
        try:
            with open(ruta_archivo, "rb") as f:
                contenido_cifrado = f.read()
                print(f"Contenido cifrado de {nombre_archivo}: {contenido_cifrado.hex()}")
        except Exception as e:
            print(f"Error al leer el archivo cifrado: {e}")
            messagebox.showerror("Error", "No se pudo leer el archivo cifrado.")
            return
        try:
            with open("informacion_cifrado.json", "r") as f:
                informacion_cifrado = json.load(f)
                info_cifrado = informacion_cifrado["documentos"][nombre_archivo]
                clave = bytes.fromhex(info_cifrado["clave"])
                nonce = bytes.fromhex(info_cifrado["nonce"])
                associated_data = b"Archivo de usuario"
        except Exception as e:
            print(f"Error al cargar información de cifrado: {e}")
            messagebox.showerror("Error", "No se pudo cargar la información de cifrado.")
            return
        print(f"Clave: {info_cifrado['clave']}")
        print(f"Nonce: {info_cifrado['nonce']}")
        contenido = descifrar_datos_aes_gcm(descifrar_clave_aes(clave), nonce, contenido_cifrado, associated_data)
        if contenido is None:
            messagebox.showerror("Error", "No se pudo descifrar el documento.")
            return
        ventana_edicion = Toplevel(root)
        ventana_edicion.title(f"Editar {nombre_archivo}")
        text_area = tk.Text(ventana_edicion, wrap="word")
        text_area.insert(tk.END, contenido.decode())
        text_area.pack(expand=True, fill="both")
        def guardar_cambios():
            nuevo_contenido = text_area.get("1.0", tk.END).encode()
            nueva_clave, nuevo_nonce, nuevo_contenido_cifrado = cifrar_datos_aes_gcm(nuevo_contenido, associated_data)
            with open(ruta_archivo, "wb") as f:
                f.write(nuevo_contenido_cifrado)
            info_cifrado["clave"] = cifrar_clave_aes(nueva_clave).hex()
            info_cifrado["nonce"] = nuevo_nonce.hex()
            with open("informacion_cifrado.json", "w") as f:
                informacion_cifrado["documentos"][nombre_archivo] = info_cifrado
                json.dump(informacion_cifrado, f, indent=4)
            messagebox.showinfo("Éxito", "Documento guardado y cifrado nuevamente.")
            ventana_edicion.destroy()
        btn_guardar = tk.Button(ventana_edicion, text="Guardar cambios", command=guardar_cambios)
        btn_guardar.pack(pady=5)
    else:
        messagebox.showerror("Error", "No tienes permisos para editar este documento.")

def guardar_credencial(usuario, contraseña):
    if usuario and contraseña:
        agregar_credenciales(usuario, contraseña, "credenciales.json")
        messagebox.showinfo("Éxito", "Usuario registrado correctamente.")
    else:
        messagebox.showwarning("Advertencia", "Por favor, completa todos los campos.")

def iniciar_sesion():
    for widget in root.winfo_children():
        widget.destroy()
    tk.Label(root, text="Usuario:").pack(pady=5)
    entry_usuario = tk.Entry(root, width=30)
    entry_usuario.pack(pady=5)
    tk.Label(root, text="Contraseña:").pack(pady=5)
    entry_contraseña = tk.Entry(root, show="*", width=30)
    entry_contraseña.pack(pady=5)
    btn_registrar = tk.Button(root, text="Registrar", command=lambda: guardar_credencial(entry_usuario.get(), entry_contraseña.get()), width=20)
    btn_registrar.pack(pady=5)
    btn_iniciar_sesion = tk.Button(root, text="Iniciar sesión", command=lambda: verificar_login(entry_usuario.get(), entry_contraseña.get()), width=20)
    btn_iniciar_sesion.pack(pady=5)

def verificar_login(usuario, contraseña):
    credenciales = cargar_deJSON("credenciales.json")
    for cred in credenciales:
        if cred["usuario"] == usuario and verificar_contraseña(contraseña, bytes.fromhex(cred["salt"]), cred["contraseña"]):
            mostrar_opciones(usuario)
            return
    messagebox.showerror("Error", "Usuario o contraseña incorrectos.")

def mostrar_opciones(usuario):
    for widget in root.winfo_children():
        widget.destroy()
    tk.Label(root, text=f"Bienvenido, {usuario}!", font=("Arial", 16)).pack(pady=10)
    btn_subir = tk.Button(root, text="Subir archivo", command=lambda: seleccionar_archivo(usuario), width=20)
    btn_subir.pack(pady=5)
    frame_compartir = tk.Frame(root)
    frame_compartir.pack(pady=10)
    tk.Label(frame_compartir, text="Nombre del archivo a compartir:").pack(side=tk.LEFT)
    entry_compartir = tk.Entry(frame_compartir, width=20)
    entry_compartir.pack(side=tk.LEFT, padx=(5, 0))
    tk.Label(frame_compartir, text="Usuario a compartir:").pack(side=tk.LEFT)
    entry_usuario_a_compartir = tk.Entry(frame_compartir, width=15)
    entry_usuario_a_compartir.pack(side=tk.LEFT, padx=(5, 0))
    btn_compartir = tk.Button(root, text="Compartir archivo", command=lambda: compartir_documento(usuario, entry_compartir.get(), entry_usuario_a_compartir.get()), width=20)
    btn_compartir.pack(pady=5)
    tk.Label(root, text="Nombre del archivo a editar:").pack(pady=(10, 0))
    entry_editar = tk.Entry(root, width=30)
    entry_editar.pack(pady=5)
    btn_editar = tk.Button(root, text="Editar archivo", command=lambda: editar_documento(usuario, entry_editar.get()), width=20)
    btn_editar.pack(pady=5)

root = tk.Tk()
root.title("Sistema de Gestión de Usuarios")
root.geometry("400x400")
iniciar_sesion()
root.mainloop()
