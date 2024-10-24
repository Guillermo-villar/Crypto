import os
import json
import tkinter as tk
from tkinter import messagebox, Toplevel, filedialog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# Función para guardar credenciales en un archivo JSON
def guardar_credenciales(credenciales, archivo):
    with open(archivo, 'w') as file:
        json.dump(credenciales, file, indent=4)
    messagebox.showinfo("Guardado", f"Credenciales guardadas en {archivo}")

# Función para cargar credenciales existentes del archivo JSON
def cargar_credenciales(archivo):
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
    credenciales_guardadas = cargar_credenciales(archivo_json)
    salt = os.urandom(16).hex()
    hash_contraseña = hashear_contraseña(contraseña, bytes.fromhex(salt)).hex()
    
    nueva_credencial = {"usuario": usuario, "salt": salt, "contraseña": hash_contraseña}
    credenciales_guardadas.append(nueva_credencial)
    os.makedirs(f"Users/{usuario}", exist_ok=True)
    guardar_credenciales(credenciales_guardadas, archivo_json)

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

# Función para guardar la información de cifrado (clave y nonce) en un archivo JSON
def guardar_informacion_cifrado(usuario, nombre_archivo, clave, nonce):
    archivo_info = "informacion_cifrado.json"
    
    try:
        with open(archivo_info, 'r') as f:
            informacion_cifrado = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        informacion_cifrado = {"documentos": {}}

    # Asegúrate de que estás almacenando la clave y el nonce en formato hexadecimal
    if nombre_archivo not in informacion_cifrado["documentos"]:
        informacion_cifrado["documentos"][nombre_archivo] = {
            "clave": clave.hex(),
            "nonce": nonce.hex(),
            "usuarios": [usuario]
        }
    else:
        if usuario not in informacion_cifrado["documentos"][nombre_archivo]["usuarios"]:
            informacion_cifrado["documentos"][nombre_archivo]["usuarios"].append(usuario)

    with open(archivo_info, 'w') as f:
        json.dump(informacion_cifrado, f, indent=4)
# Función para verificar si el usuario tiene acceso al documento
def verificar_acceso_usuario(usuario, nombre_archivo):
    try:
        with open("informacion_cifrado.json", 'r') as f:
            informacion_cifrado = json.load(f)
        
        if "documentos" not in informacion_cifrado:
            return False

        return nombre_archivo in informacion_cifrado["documentos"] and usuario in informacion_cifrado["documentos"][nombre_archivo]["usuarios"]
    
    except FileNotFoundError:
        return False

# Función para abrir el cuadro de diálogo y seleccionar un archivo .txt
def seleccionar_archivo(usuario):
    archivo = filedialog.askopenfilename(
        title="Selecciona un archivo .txt",
        filetypes=[("Archivos de texto", "*.txt")]
    )
    if archivo:
        with open(archivo, "rb") as file:
            contenido = file.read()
        
        # Cifrar los datos leídos del archivo
        clave, nonce, contenido_cifrado = cifrar_datos_aes_gcm(contenido, b"Archivo de usuario")
        
        # Guardar el archivo cifrado en la carpeta del usuario
        ruta_destino = os.path.join("Users", usuario, os.path.basename(archivo) + ".enc")
        with open(ruta_destino, "wb") as file:
            file.write(contenido_cifrado)
        
        # Guardar la información de cifrado en el archivo JSON
        guardar_informacion_cifrado(usuario, os.path.basename(archivo), clave, nonce)
        
        # Mensaje de éxito
        messagebox.showinfo("Éxito", f"Archivo {os.path.basename(archivo)} cifrado y subido correctamente a la carpeta de {usuario}")

        # Verificación adicional
        print(f"Archivo cifrado guardado en: {ruta_destino}")
        print(f"Clave (hex): {clave.hex()}")
        print(f"Nonce (hex): {nonce.hex()}")

# Función para compartir un documento
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
        # Buscar el archivo en todas las carpetas de usuarios
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
                print(f"Contenido cifrado de {nombre_archivo}: {contenido_cifrado.hex()}")  # Mostrar el contenido cifrado
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
                associated_data = b"Archivo de usuario"  # Asegúrate de usar el mismo associated_data
        except Exception as e:
            print(f"Error al cargar información de cifrado: {e}")
            messagebox.showerror("Error", "No se pudo cargar la información de cifrado.")
            return

        print(f"Clave: {info_cifrado['clave']}")  # Mostrar clave en hexadecimal
        print(f"Nonce: {info_cifrado['nonce']}")  # Mostrar nonce en hexadecimal
        
        contenido = descifrar_datos_aes_gcm(clave, nonce, contenido_cifrado, associated_data)
        
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
            
            info_cifrado["clave"] = nueva_clave.hex()
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

# Función para manejar el registro de usuario
def guardar_credencial():
    usuario = entry_usuario.get()
    contraseña = entry_contraseña.get()
    if usuario and contraseña:
        agregar_credenciales(usuario, contraseña, "credenciales.json")
    else:
        messagebox.showwarning("Advertencia", "Por favor, completa todos los campos.")

# Función para manejar el inicio de sesión
def iniciar_sesion():
    usuario = entry_usuario.get()
    contraseña = entry_contraseña.get()
    
    credenciales = cargar_credenciales("credenciales.json")
    for cred in credenciales:
        if cred["usuario"] == usuario and verificar_contraseña(contraseña, bytes.fromhex(cred["salt"]), cred["contraseña"]):
            mostrar_opciones(usuario)
            return
    
    messagebox.showerror("Error", "Usuario o contraseña incorrectos.")

# Función para mostrar las opciones después de iniciar sesión
def mostrar_opciones(usuario):
    for widget in root.winfo_children():
        widget.destroy()
    
    tk.Label(root, text=f"Bienvenido, {usuario}!", font=("Arial", 16)).pack(pady=10)

    # Botón para subir archivo
    btn_subir = tk.Button(root, text="Subir archivo", command=lambda: seleccionar_archivo(usuario), width=20)
    btn_subir.pack(pady=5)

    # Sección para compartir archivos
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

    # Botón para editar archivo
    tk.Label(root, text="Nombre del archivo a editar:").pack(pady=(10, 0))
    entry_editar = tk.Entry(root, width=30)
    entry_editar.pack(pady=5)

    btn_editar = tk.Button(root, text="Editar archivo", command=lambda: editar_documento(usuario, entry_editar.get()), width=20)
    btn_editar.pack(pady=5)

# Configuración de la interfaz gráfica
root = tk.Tk()
root.title("Sistema de Gestión de Usuarios")
root.geometry("400x400")

tk.Label(root, text="Usuario:").pack(pady=5)
entry_usuario = tk.Entry(root, width=30)
entry_usuario.pack(pady=5)

tk.Label(root, text="Contraseña:").pack(pady=5)
entry_contraseña = tk.Entry(root, show="*", width=30)
entry_contraseña.pack(pady=5)

btn_registrar = tk.Button(root, text="Registrar", command=guardar_credencial, width=20)
btn_registrar.pack(pady=5)

btn_iniciar_sesion = tk.Button(root, text="Iniciar sesión", command=iniciar_sesion, width=20)
btn_iniciar_sesion.pack(pady=5)

root.mainloop()
