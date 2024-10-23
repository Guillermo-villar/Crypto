import os
import json
import tkinter as tk
from tkinter import messagebox, Toplevel, filedialog
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import shutil

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

    # Generar un nuevo salt aleatorio para este usuario
    salt = os.urandom(16).hex()
    hash_contraseña = hashear_contraseña(contraseña, bytes.fromhex(salt)).hex()

    nueva_credencial = {"usuario": usuario, "salt": salt, "contraseña": hash_contraseña}
    credenciales_guardadas.append(nueva_credencial)
    os.mkdir("Users/"+usuario)
    guardar_credenciales(credenciales_guardadas, archivo_json)

# Función para manejar la acción al presionar "Guardar" en el registro
def guardar_credencial():
    usuario = entry_usuario.get()
    contraseña = entry_contraseña.get()

    if usuario and contraseña:
        agregar_credenciales(usuario, contraseña, "credenciales.json")
        
        respuesta = messagebox.askyesno("Agregar otro", "¿Desea agregar otro usuario?")
        if not respuesta:
            root.quit()  # Salir de la aplicación si no desea agregar más
        else:
            entry_usuario.delete(0, tk.END)
            entry_contraseña.delete(0, tk.END)
    else:
        messagebox.showwarning("Advertencia", "Debe ingresar un usuario y contraseña")

def abrir_sistema(usuario):
    ventana_sistema = Toplevel(root)
    ventana_sistema.title("Sistema")
    ventana_sistema.geometry("400x300")

    # Botón Sistema (puedes agregar funcionalidades adicionales aquí)
    btn_sistema = tk.Button(ventana_sistema, text="Sistema", command=lambda: messagebox.showinfo("Sistema", "Funcionalidad del sistema"))
    btn_sistema.pack(pady=10)

    # Botón Archivos que permitirá seleccionar un archivo .txt
    btn_archivos = tk.Button(ventana_sistema, text="Archivos", command=lambda: seleccionar_archivo(usuario))
    btn_archivos.pack(pady=10)

# Función para abrir el cuadro de diálogo y seleccionar un archivo .txt
def seleccionar_archivo(usuario):
    archivo = filedialog.askopenfilename(
        title="Selecciona un archivo .txt",
        filetypes=[("Archivos de texto", "*.txt")]
    )
    if archivo:
        # Definir la ruta de destino en la carpeta del usuario
        ruta_destino = os.path.join("Users", usuario, os.path.basename(archivo))
        try:
            shutil.copy(archivo, ruta_destino)
            messagebox.showinfo("Éxito", f"Archivo {os.path.basename(archivo)} subido correctamente a la carpeta de {usuario}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al subir el archivo: {e}")

# Función para manejar la acción al presionar "Iniciar sesión"
def iniciar_sesion():
    usuario = entry_usuario.get()
    contraseña = entry_contraseña.get()

    if usuario and contraseña:
        credenciales_guardadas = cargar_credenciales("credenciales.json")
        for credencial in credenciales_guardadas:
            if credencial["usuario"] == usuario:
                salt = bytes.fromhex(credencial["salt"])
                hash_guardado = credencial["contraseña"]
                
                if verificar_contraseña(contraseña, salt, hash_guardado):
                    messagebox.showinfo("Inicio de sesión", "Inicio de sesión exitoso")
                    root.withdraw()  # Cierra la ventana de inicio
                    abrir_sistema(usuario)  # Abre la ventana del sistema
                    return
                else:
                    messagebox.showerror("Error", "Usuario o contraseña incorrectos")
                    return
        messagebox.showerror("Error", "Usuario o contraseña incorrectos")
    else:
        messagebox.showwarning("Advertencia", "Debe ingresar un usuario y contraseña")

# Función para mostrar la pantalla de inicio de sesión o registro
def pantalla_inicio():
    # Ocultar botones de la pantalla inicial
    btn_iniciar_sesion.pack_forget()
    btn_registrarse.pack_forget()

    # Mostrar entradas y botones correspondientes a iniciar sesión o registrarse
    label_usuario.pack(pady=10)
    entry_usuario.pack(pady=5)
    label_contraseña.pack(pady=10)
    entry_contraseña.pack(pady=5)

    if opcion.get() == "iniciar_sesion":
        btn_iniciar.pack(pady=20)
    elif opcion.get() == "registrarse":
        btn_guardar.pack(pady=20)

# Interfaz gráfica con tkinter
root = tk.Tk()
root.title("Gestión de Credenciales")
root.geometry("400x300")

# Variables para la opción seleccionada
opcion = tk.StringVar()

# Botones para seleccionar entre iniciar sesión o registrarse
btn_iniciar_sesion = tk.Button(root, text="Iniciar Sesión", command=lambda: [opcion.set("iniciar_sesion"), pantalla_inicio()])
btn_iniciar_sesion.pack(pady=10)

btn_registrarse = tk.Button(root, text="Registrarse", command=lambda: [opcion.set("registrarse"), pantalla_inicio()])
btn_registrarse.pack(pady=10)

# Etiquetas y entradas para el usuario y la contraseña
label_usuario = tk.Label(root, text="Usuario:")
entry_usuario = tk.Entry(root)

label_contraseña = tk.Label(root, text="Contraseña:")
entry_contraseña = tk.Entry(root, show="*")

# Botones para guardar la credencial o iniciar sesión
btn_guardar = tk.Button(root, text="Guardar", command=guardar_credencial)
btn_iniciar = tk.Button(root, text="Iniciar Sesión", command=iniciar_sesion)

if not os.path.exists("Users"):
    os.mkdir("Users")

# Ejecutar la aplicación
root.mainloop()
