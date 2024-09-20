import json

# Función para pedir usuario y contraseña
def obtener_credenciales():
    usuario = input("Ingrese su nombre de usuario: ")
    contraseña = input("Ingrese su contraseña: ")
    return {"usuario": usuario, "contraseña": contraseña}

# Guardar todas las credenciales en un archivo JSON
def guardar_credenciales(credenciales, archivo):
    with open(archivo, 'w') as file:
        json.dump(credenciales, file, indent=4)
    print(f"Credenciales guardadas en {archivo}")

# Cargar credenciales existentes del archivo JSON (para guardarlos cada vez que añadimos uno)
def cargar_credenciales(archivo):
    try:
        with open(archivo, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        # Si el archivo no existe o está vacío, devolvemos una lista vacía
        return []

# Función para agregar usuarios de forma iterativa
def agregar_usuarios(archivo_json):
    credenciales_guardadas = cargar_credenciales(archivo_json)

    # Si no es una lista, conviértelo en lista (por si está mal formateado)
    if not isinstance(credenciales_guardadas, list):
        credenciales_guardadas = []

    while True:
        nueva_credencial = obtener_credenciales()
        credenciales_guardadas.append(nueva_credencial)
        guardar_credenciales(credenciales_guardadas, archivo_json)

        # Preguntar si desea agregar más usuarios
        respuesta = input("¿Desea agregar otro usuario? (s/n): ").lower()
        if respuesta != 's':
            break

# Programa principal
if __name__ == "__main__":
    agregar_usuarios("credenciales.json")

# Se puede usar un json con confirmación de cambios para controlar la creación de usuarios d algun tipo

# Usar tkinter como interfaz gráfica (Aquí para control de usuarios)