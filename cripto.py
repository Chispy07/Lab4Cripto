# --- Importaciones necesarias ---
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# --- Actividad 2.3: Función para ajustar Clave / IV ---
# Esta función es genérica y funciona para cualquier algoritmo
def ajustar_tamano(entrada_bytes, tamano_requerido):
    """
    Ajusta la entrada (Clave o IV) al tamaño requerido.
    - Si es más larga, la trunca.
    - Si es más corta, la rellena con bytes aleatorios.
    """
    longitud_actual = len(entrada_bytes)
    
    if longitud_actual == tamano_requerido:
        return entrada_bytes
    
    elif longitud_actual > tamano_requerido:
        print(f"    [Ajuste] La entrada ({longitud_actual} bytes) era muy larga. Truncando a {tamano_requerido} bytes.")
        return entrada_bytes[:tamano_requerido]
        
    else:
        bytes_faltantes = tamano_requerido - longitud_actual
        print(f"    [Ajuste] La entrada ({longitud_actual} bytes) era muy corta. Rellenando con {bytes_faltantes} bytes aleatorios.")
        relleno_aleatorio = get_random_bytes(bytes_faltantes)
        return entrada_bytes + relleno_aleatorio

# --- Actividad 2.4: Funciones de Cifrado / Descifrado Genéricas ---

def cifrar_cbc(cipher_module, key, iv, texto_plano):
    """
    Cifra un texto plano usando el módulo (AES, DES, DES3) proporcionado.
    """
    print("\n--- 1. PROCESO DE CIFRADO ---")
    try:
        # Usamos el módulo (ej. AES) para crear el cifrador en modo CBC
        cipher = cipher_module.new(key, cipher_module.MODE_CBC, iv)
        
        # Aplicamos padding al texto (PKCS#7)
        # Usamos el block_size del módulo (16 para AES, 8 para DES/DES3)
        texto_plano_padded = pad(texto_plano, cipher_module.block_size)
        
        # Ciframos
        texto_cifrado = cipher.encrypt(texto_plano_padded)
        print(f"¡Cifrado exitoso!")
        print(f"Texto Cifrado (hex): {texto_cifrado.hex()}")
        return texto_cifrado
        
    except Exception as e:
        print(f"[ERROR AL CIFRAR] {e}")
        return None

def descifrar_cbc(cipher_module, key, iv, texto_cifrado):
    """
    Descifra un texto cifrado usando el módulo (AES, DES, DES3) proporcionado.
    """
    print("\n--- 2. PROCESO DE DESCIFRADO ---")
    try:
        # Creamos un NUEVO objeto descifrador
        decipher = cipher_module.new(key, cipher_module.MODE_CBC, iv)
        
        # Desciframos
        texto_descifrado_padded = decipher.decrypt(texto_cifrado)
        
        # Quitamos el padding (PKCS#7)
        texto_descifrado = unpad(texto_descifrado_padded, cipher_module.block_size)
        print(f"¡Descifrado exitoso!")
        print(f"Texto Original (utf-8): {texto_descifrado.decode('utf-8')}")
        return texto_descifrado

    except (ValueError, KeyError) as e:
        print(f"[ERROR AL DESCIFRAR] Error de padding o clave incorrecta.")
        return None
    except Exception as e:
        print(f"[ERROR AL DESCIFRAR] {e}")
        return None

# --- PROGRAMA PRINCIPAL ---

# --- 1. Seleccionar el Algoritmo ---
print("--- Selección de Algoritmo de Cifrado ---")
print("1. DES")
print("2. 3DES (Triple DES)")
print("3. AES-256")

algo_choice = ""
while algo_choice not in ['1', '2', '3']:
    algo_choice = input("Elige un algoritmo (1, 2 o 3): ")

# --- 2. Definir parámetros según la elección ---
if algo_choice == '1':
    cipher_module = DES
    key_size = 8  # 8 bytes (56 bits efectivos)
    iv_size = 8   # 8 bytes (bloque de 64 bits)
    algo_name = "DES"
elif algo_choice == '2':
    cipher_module = DES3
    key_size = 24  # 24 bytes (168 bits, 3-Key 3DES)
    iv_size = 8    # 8 bytes (bloque de 64 bits)
    algo_name = "3DES"
else:
    cipher_module = AES
    key_size = 32  # 32 bytes (256 bits)
    iv_size = 16   # 16 bytes (bloque de 128 bits)
    algo_name = "AES-256"

print(f"\nHas seleccionado: {algo_name}")
print(f"Tamaño de Clave requerido: {key_size} bytes")
print(f"Tamaño de IV requerido:    {iv_size} bytes")

# --- 3. Actividad 2.2: Solicitar datos ---
print("\n--- Configuración de Entradas ---")
key_str = input("Introduce la CLAVE (Key): ")
iv_str = input("Introduce el IV: ")
texto_plano_str = input("Introduce el TEXTO a cifrar: ")

# Convertir las entradas a bytes
key_bytes = key_str.encode('utf-8')
iv_bytes = iv_str.encode('utf-8')
texto_plano_bytes = texto_plano_str.encode('utf-8')

# --- 4. Actividad 2.3: Ajustar Clave e IV ---
print(f"\n--- Ajustando Clave e IV para {algo_name} ---")

# Ajustar la CLAVE
print(f"Clave original (hex): {key_bytes.hex()}")
key_final = ajustar_tamano(key_bytes, key_size)
print(f"Clave final (hex):    {key_final.hex()} (Tamaño: {len(key_final)} bytes)")

# Ajustar el IV
print(f"\nIV original (hex): {iv_bytes.hex()}")
iv_final = ajustar_tamano(iv_bytes, iv_size)
print(f"IV final (hex):    {iv_final.hex()} (Tamaño: {len(iv_final)} bytes)")

# --- 5. Actividad 2.4: Ejecutar Cifrado y Descifrado ---
texto_cifrado = cifrar_cbc(cipher_module, key_final, iv_final, texto_plano_bytes)

if texto_cifrado:
    # Solo intentamos descifrar si el cifrado fue exitoso
    descifrar_cbc(cipher_module, key_final, iv_final, texto_cifrado)