from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# -----INGRESO DE DATOS-----

print("\n--- Ingreso de datos ---")

texto = input("\nIngrese el texto a cifrar: ")

# DES 
print("\n--- DES ---")
key_des = input("Ingrese la clave: ")
iv_des = input("Ingrese el vector de inicialización: ")

# 3DES 
print("\n--- 3DES ---")
key_3des = input("Ingrese la clave: ")
iv_3des = input("Ingrese el vector de inicialización: ")

# AES-256 
print("\n--- AES-256 ---")
key_aes = input("Ingrese la clave: ")
iv_aes = input("Ingrese el vector de inicialización: ")

# -----AJUSTE DEL TAMAÑO DE LA CLAVE Y IV-----

print("\n--- Ajuste de claves y vectores de inicialización ---")

# Ajustar la longitud de las claves y vectores de inicializacion 
def ajustar_clave(clave, longitud):
    clave_bytes = clave.encode()
    if len(clave_bytes) < longitud:
        clave_bytes += get_random_bytes(longitud - len(clave_bytes))
    else:
        clave_bytes = clave_bytes[:longitud]
    return clave_bytes

# DES 
key_des = ajustar_clave(key_des, 8)
iv_des = ajustar_clave(iv_des, 8)
print("\n--- DES ---")
print("Clave final (hexadecimal):", key_des.hex())
print("IV final (hexadecimal):", iv_des.hex())

# 3DES 
key_3des = ajustar_clave(key_3des, 24)
iv_3des = ajustar_clave(iv_3des, 8)
print("\n--- 3DES ---")
print("Clave final (hexadecimal):", key_3des.hex())
print("IV final (hexadecimal):", iv_3des.hex())

# AES-256 
key_aes = ajustar_clave(key_aes, 32)
iv_aes = ajustar_clave(iv_aes, 16)
print("\n--- AES-256 ---")
print("Clave final (hexadecimal):", key_aes.hex())
print("IV final (hexadecimal):", iv_aes.hex())

# ----CIFRADO Y DESCIFRADO-----

print("\n--- Cifrado y descifrado ---")

# DES
cipher_des = DES.new(key_des, DES.MODE_CBC, iv_des)
cifrado_des = cipher_des.encrypt(pad(texto.encode(), 8))

decipher_des = DES.new(key_des, DES.MODE_CBC, iv_des)
descifrado_des = unpad(decipher_des.decrypt(cifrado_des), 8)

print("\n--- DES ---")
print("Texto cifrado (base64):", base64.b64encode(cifrado_des).decode())
print("Texto descifrado:", descifrado_des.decode())

# 3DES
cipher_3des = DES3.new(key_3des, DES3.MODE_CBC, iv_3des)
cifrado_3des = cipher_3des.encrypt(pad(texto.encode(), 8))

decipher_3des = DES3.new(key_3des, DES3.MODE_CBC, iv_3des)
descifrado_3des = unpad(decipher_3des.decrypt(cifrado_3des), 8)

print("\n--- 3DES ---")
print("Texto cifrado (base64):", base64.b64encode(cifrado_3des).decode())
print("Texto descifrado:", descifrado_3des.decode())

# AES-256
cipher_aes = AES.new(key_aes, AES.MODE_CBC, iv_aes)
cifrado_aes = cipher_aes.encrypt(pad(texto.encode(), 16))

decipher_aes = AES.new(key_aes, AES.MODE_CBC, iv_aes)
descifrado_aes = unpad(decipher_aes.decrypt(cifrado_aes), 16)

print("\n--- AES-256 ---")
print("Texto cifrado (base64):", base64.b64encode(cifrado_aes).decode())
print("Texto descifrado:", descifrado_aes.decode())