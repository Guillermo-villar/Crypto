import os
import json
import tkinter as tk
import shutil
from tkinter import messagebox, Toplevel, filedialog
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from external import *

# Funciones de manejo de credenciales
def guardar_enJSON(credenciales, archivo):
    with open(archivo, 'w') as file:
        json.dump(credenciales, file, indent=4)
    messagebox.showinfo("Guardado", f"Credenciales guardadas en {archivo}")

def cargar_deJSON(archivo):
    try:
        with open(archivo, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

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

def agregar_credenciales(usuario, contraseña ,contraseña_clavepriv, archivo_json):
    credenciales_guardadas = cargar_deJSON(archivo_json)
    salt = os.urandom(16).hex()
    hash_contraseña = hashear_contraseña(contraseña, bytes.fromhex(salt)).hex()
    hash_contraseña_clavepriv = hashear_contraseña(contraseña_clavepriv, bytes.fromhex(salt)).hex()
    nueva_credencial = {"usuario": usuario, "salt": salt, "contraseña": hash_contraseña, "contraseña_clavepriv": hash_contraseña_clavepriv}
    
    # Ensure the Users directory exists before creating a user directory
    if not os.path.exists("Users"):
        os.mkdir("Users")
    
    os.mkdir(os.path.join("Users", usuario))
    os.mkdir(os.path.join("Users", usuario, "claves"))
    contraseña_CA = obtener_contraseña_CA()
    ruta_clave_privada_CA, ruta_certificado_CA = generar_CA_openssl(contraseña_CA)
    ruta_certificado, ruta_clavepriv = generar_certificado_usuario(usuario, contraseña_clavepriv, ruta_clave_privada_CA, ruta_certificado_CA, contraseña_CA)
    nueva_credencial.update({"rutapublica" : ruta_certificado, "rutaprivada": ruta_clavepriv})
    credenciales_guardadas.append(nueva_credencial)
    guardar_enJSON(credenciales_guardadas, archivo_json)

def guardar_credencial(usuario, contraseña ,contraseña_clavepriv):
    if (usuario and contraseña):
        agregar_credenciales(usuario, contraseña, contraseña_clavepriv, "credenciales.json")
        messagebox.showinfo("Éxito", "Usuario registrado correctamente.")
    else:
        messagebox.showwarning("Advertencia", "Por favor, completa todos los campos.")

# Funciones de manejo de claves
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

# Funciones de cifrado y descifrado de datos
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

# Funciones de manejo de información de cifrado
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

# Funciones de manejo de archivos
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

def compartir_documento(usuario, nombre_archivo, usuario_a_compartir):
    try:
        with open("informacion_cifrado.json", 'r') as f:
            informacion_cifrado = json.load(f)
        if nombre_archivo in informacion_cifrado["documentos"]:
            if usuario in informacion_cifrado["documentos"][nombre_archivo]["usuarios"]:
                with open("credenciales.json", 'r') as cred_file:
                    credenciales = json.load(cred_file)
                usuarios_existentes = [u["usuario"] for u in credenciales]
                if usuario_a_compartir not in usuarios_existentes:
                    messagebox.showerror("Error", f"{usuario_a_compartir} no es un usuario registrado.")
                    return
                if usuario_a_compartir not in informacion_cifrado["documentos"][nombre_archivo]["usuarios"]:
                    # Agregar al usuario destinatario a la lista de usuarios con acceso
                    informacion_cifrado["documentos"][nombre_archivo]["usuarios"].append(usuario_a_compartir)
                    
                    # Guardar la información actualizada en el archivo de metadatos
                    with open("informacion_cifrado.json", 'w') as f:
                        json.dump(informacion_cifrado, f, indent=4)
                    
                    # Copiar el archivo cifrado a la carpeta del usuario destinatario
                    ruta_origen = os.path.join("Users", usuario, nombre_archivo + ".enc")
                    ruta_destino = os.path.join("Users", usuario_a_compartir, nombre_archivo + ".enc")
                    if os.path.exists(ruta_origen):
                        shutil.copy(ruta_origen, ruta_destino)
                        messagebox.showinfo("Éxito", f"El archivo {nombre_archivo} ha sido compartido con {usuario_a_compartir}.")
                    else:
                        messagebox.showerror("Error", "El archivo original no se encontró en la carpeta del remitente.")
                else:
                    messagebox.showinfo("Información", f"{usuario_a_compartir} ya tiene acceso a este archivo.")
            else:
                messagebox.showerror("Error", "No tienes permisos para compartir este documento.")
        else:
            messagebox.showerror("Error", "El archivo no existe.")
    except FileNotFoundError:
        messagebox.showerror("Error", "El archivo de información de cifrado no fue encontrado.")


def verificar_permisos_edicion(usuario, nombre_archivo, ruta_certificado):
    archivo_info = "metadatos_edicion.json"
    try:
        with open(archivo_info, 'r') as f:
            metadatos = json.load(f)
            if nombre_archivo not in metadatos["documentos"]:
                messagebox.showerror("Error", "No se encontraron metadatos de edición para el archivo.")
                return False

            metadatos_archivo = metadatos["documentos"][nombre_archivo]
            firma_ultima_edicion = bytes.fromhex(metadatos_archivo["firma"])
            contenido_actual = open(os.path.join("Users", usuario, nombre_archivo + ".enc"), "rb").read()
            if verificar_firma(contenido_actual, firma_ultima_edicion, ruta_certificado):
                return True
            else:
                messagebox.showerror("Error", "La firma del último editor no coincide. No se puede editar.")
                return False
    except FileNotFoundError:
        messagebox.showerror("Error", "Archivo de metadatos de edición no encontrado.")
        return False

# Nueva función para solicitar la contraseña de la clave privada
def obtener_contraseña_clave_privada(usuario):
    # Implementa un cuadro de diálogo o método para solicitar la contraseña al usuario
    password = tk.simpledialog.askstring("Contraseña", f"Ingrese la contraseña de la clave privada de {usuario}:")
    return password if password else ""

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
        except Exception as e:
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
            messagebox.showerror("Error", "No se pudo cargar la información de cifrado.")
            return

        contenido = descifrar_datos_aes_gcm(descifrar_clave_aes(clave), nonce, contenido_cifrado, associated_data)
        if contenido is None:
            messagebox.showerror("Error", "No se pudo descifrar el documento.")
            return

        # Ventana de edición
        ventana_edicion = Toplevel(root)
        ventana_edicion.title(f"Editar {nombre_archivo}")
        text_area = tk.Text(ventana_edicion, wrap="word")
        text_area.insert(tk.END, contenido.decode())
        text_area.pack(expand=True, fill="both")
        
        def guardar_cambios():
            nuevo_contenido = text_area.get("1.0", tk.END).encode()
            nueva_clave, nuevo_nonce, nuevo_contenido_cifrado = cifrar_datos_aes_gcm(nuevo_contenido, associated_data)
            
            # Solicitar la clave privada para firmar los cambios
            password_clave_privada = tk.simpledialog.askstring("Clave Privada", "Introduce la clave privada para firmar los cambios:", show="*")
            
            try:
                # Verificar y firmar el documento
                firma = firmar_documento(nuevo_contenido.decode(), os.path.join("Users", usuario, "claves/clave_privada.pem"), password_clave_privada)
                if firma is None:
                    raise ValueError("Clave privada incorrecta.")
                
                # Guardar la firma en los metadatos
                guardar_metadatos_edicion(usuario, nombre_archivo, firma)

                # Guardar el nuevo contenido cifrado
                with open(ruta_archivo, "wb") as f:
                    f.write(nuevo_contenido_cifrado)
                
                # Actualizar los metadatos
                info_cifrado["clave"] = cifrar_clave_aes(nueva_clave).hex()
                info_cifrado["nonce"] = nuevo_nonce.hex()
                with open("informacion_cifrado.json", "w") as f:
                    informacion_cifrado["documentos"][nombre_archivo] = info_cifrado
                    json.dump(informacion_cifrado, f, indent=4)
                
                messagebox.showinfo("Éxito", "Documento guardado y cifrado nuevamente.")
                ventana_edicion.destroy()
            except ValueError as ve:
                messagebox.showerror("Error", f"La clave privada introducida es incorrecta")
            except Exception as e:
                messagebox.showerror("Error", "No se pudo firmar el documento. Verifica que la clave privada sea correcta.")

        btn_guardar = tk.Button(ventana_edicion, text="Guardar cambios", command=guardar_cambios)
        btn_guardar.pack(pady=5)

def ver_historial_edicion(nombre_archivo):
    archivo_info = "metadatos_edicion.json"
    try:
        with open(archivo_info, 'r') as f:
            metadatos = json.load(f)
            if nombre_archivo not in metadatos["documentos"]:
                messagebox.showinfo("Historial de Edición", "No se encontraron registros de edición para este archivo.")
                return

            historial_texto = f"Historial de edición para el archivo '{nombre_archivo}':\n\n"
            for registro in metadatos["documentos"][nombre_archivo]:
                historial_texto += (
                    f"Editor: {registro['editor']}\n"
                    f"Firma: {registro['firma']}\n"
                    f"Timestamp: {registro['timestamp']}\n\n"
                )

            # Mostrar la información en una ventana emergente
            ventana_historial = Toplevel(root)
            ventana_historial.title(f"Historial de Edición - {nombre_archivo}")
            texto_historial = tk.Text(ventana_historial, wrap="word")
            texto_historial.insert(tk.END, historial_texto)
            texto_historial.pack(expand=True, fill="both")
            texto_historial.config(state="disabled")  # Desactivar edición
    except FileNotFoundError:
        messagebox.showerror("Error", "El archivo de metadatos de edición no fue encontrado.")
    except json.JSONDecodeError:
        messagebox.showerror("Error", "Error al leer los metadatos de edición.")
        
        
def iniciar_sesion():
    for widget in root.winfo_children():
        widget.destroy()
    tk.Label(root, text="Usuario:").pack(pady=5)
    entry_usuario = tk.Entry(root, width=30)
    entry_usuario.pack(pady=5)
    tk.Label(root, text="Contraseña:").pack(pady=5)
    entry_contraseña = tk.Entry(root, show="*", width=30)
    entry_contraseña.pack(pady=5)
    tk.Label(root, text="Contraseña de clave priv").pack(pady=5)
    entry_contraseña_clave = tk.Entry(root, show="*", width=30)
    entry_contraseña_clave.pack(pady=5)
    btn_registrar = tk.Button(root, text="Registrar", command=lambda: guardar_credencial(entry_usuario.get(), entry_contraseña.get(), entry_contraseña_clave.get()), width=20)
    btn_registrar.pack(pady=5)
    btn_iniciar_sesion = tk.Button(root, text="Iniciar sesión", command=lambda: verificar_login(entry_usuario.get(), entry_contraseña.get()), width=20)
    btn_iniciar_sesion.pack(pady=5)
    


def verificar_login(usuario, contraseña):
    credenciales = cargar_deJSON("credenciales.json")
    for cred in credenciales:
        if cred["usuario"] == usuario and verificar_contraseña(contraseña, bytes.fromhex(cred["salt"]), cred["contraseña"]):
            ventana_seleccion(usuario)
            return
    messagebox.showerror("Error", "Usuario o contraseña incorrectos.")

# Funciones de interfaz de usuario
def ver_carpeta(usuario):
    ventana_carpeta = Toplevel(root)
    ventana_carpeta.title(f"Carpeta de {usuario}")
    ventana_carpeta.geometry("400x300")
    ruta_carpeta = os.path.join("Users", usuario)
    
    if not os.path.exists(ruta_carpeta):
        messagebox.showerror("Error", f"No se encontró la carpeta de {usuario}.")
        return

    archivos = os.listdir(ruta_carpeta)
    # Excluir la carpeta 'claves' de la lista de archivos
    archivos = [archivo for archivo in archivos if archivo != "claves"]

    if not archivos:
        tk.Label(ventana_carpeta, text="La carpeta está vacía.", font=("Arial", 12)).pack(pady=10)
    else:
        tk.Label(ventana_carpeta, text="Archivos en tu carpeta:", font=("Arial", 12, "bold")).pack(pady=10)
        listbox_archivos = tk.Listbox(ventana_carpeta, width=50, height=10)
        listbox_archivos.pack(pady=5)
        
        # Agregar archivos a la lista, eliminando la extensión '.enc'
        for archivo in archivos:
            if archivo.endswith(".enc"):
                listbox_archivos.insert(tk.END, archivo[:-4])  # Elimina la extensión '.enc'
            else:
                listbox_archivos.insert(tk.END, archivo)
        
        def on_select(event):
            seleccion = listbox_archivos.curselection()
            if seleccion:
                nombre_archivo = listbox_archivos.get(seleccion[0])
                # Agregar la extensión '.enc' si es necesario para abrir el archivo
                if not nombre_archivo.endswith(".enc"):
                    nombre_archivo += ".enc"
                editar_documento(usuario, nombre_archivo.replace(".enc", ""))

        listbox_archivos.bind("<<ListboxSelect>>", on_select)

def ventana_seleccion(usuario):
    for widget in root.winfo_children():
        widget.destroy()
    tk.Label(root, text=f"Bienvenido, {usuario}!", font=("Arial", 16)).pack(pady=10)
    btn_ver_carpeta = tk.Button(root, text="Ver mi carpeta", command=lambda: ver_carpeta(usuario), width=20)
    btn_ver_carpeta.pack(pady=5)
    btn_acceder_sistema = tk.Button(root, text="Acceder al sistema", command=lambda: mostrar_opciones(usuario), width=20)
    btn_acceder_sistema.pack(pady=5)

def mostrar_opciones(usuario):
    for widget in root.winfo_children():
        widget.destroy()
    tk.Label(root, text=f"Bienvenido, {usuario}!", font=("Arial", 16)).pack(pady=10)
    btn_volver = tk.Button(root, text="← Volver", command=lambda: ventana_seleccion(usuario), font=("Arial", 12))
    btn_volver.pack(anchor="nw", padx=10, pady=5)
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
    
    frame_historial = tk.Frame(root)
    frame_historial.pack(pady=10)
    tk.Label(frame_historial, text="Nombre del archivo para ver historial:").pack(side=tk.LEFT)
    entry_historial = tk.Entry(frame_historial, width=30)
    entry_historial.pack(side=tk.LEFT, padx=(5, 0))
    btn_ver_historial = tk.Button(root, text="Ver historial", command=lambda: ver_historial_edicion(entry_historial.get()), width=20)
    btn_ver_historial.pack(pady=5)

root = tk.Tk()
root.title("Sistema de Gestión de Usuarios")
root.geometry("600x400")
iniciar_sesion()
root.mainloop()
