import json
import tkinter as tk
from tkinter import messagebox

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

# Función para agregar credenciales a la lista y guardarlas
def agregar_credenciales(usuario, contraseña, archivo_json):
    credenciales_guardadas = cargar_credenciales(archivo_json)

    # Si no es una lista, lo convertimos en una lista
    if not isinstance(credenciales_guardadas, list):
        credenciales_guardadas = []

    nueva_credencial = {"usuario": usuario, "contraseña": contraseña}
    credenciales_guardadas.append(nueva_credencial)
    
    guardar_credenciales(credenciales_guardadas, archivo_json)

# Función para manejar la acción al presionar "Guardar"
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

# Interfaz gráfica con tkinter
root = tk.Tk()
root.title("Gestión de Credenciales")
root.geometry("400x300")

# Etiquetas y entradas para el usuario y la contraseña
label_usuario = tk.Label(root, text="Usuario:")
label_usuario.pack(pady=10)

entry_usuario = tk.Entry(root)
entry_usuario.pack(pady=5)

label_contraseña = tk.Label(root, text="Contraseña:")
label_contraseña.pack(pady=10)

entry_contraseña = tk.Entry(root, show="*")
entry_contraseña.pack(pady=5)

# Botón para guardar la credencial
btn_guardar = tk.Button(root, text="Guardar", command=guardar_credencial)
btn_guardar.pack(pady=20)

# Ejecutar la aplicación
root.mainloop()
