# Lab4Cripto
Este repositorio incluye un codigo en Python el cual utiliza el cifrado simetrico tales como 
- DES
- 3DES(Triple-DES)
- AES-256
1. Instalar la libreria pycryptodome a traves del siguiente comando 
```sh
pip install pycryptodome 
```
2. Para luego correr el codigo
Para Python3:
```sh
python3 critpo.py
```
Para la version de Python menor a Python3:
```sh
python cripto.py
```
3. Seguir las instrucciones del codigo(entradas por teclado,etc) si llegan a faltar bytes en la clave o vector de inicializacion el mismo codigo se encarga de rellenar con caracteres aleatorios hasta completar la cantidad de bytes.