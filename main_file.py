import json
from datetime import datetime
import os
import base64
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


#Clase empleada para introducir los datos de un nuevo usuario en la bade de datos
class user_record:
    def __init__(self, introduced_username, introduced_password, employed_salt):
        self._username = introduced_username
        self._password = [introduced_password, employed_salt]


class message:
    def __init__(self, sender, recipient, content):
        self._sender = sender
        self._recipient = recipient
        self._content = content


exit = 0
usuarios = []

now = datetime.now()
dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
print(dt_string)


while exit != 1:
    homepage_action = 2
    signed_up = False
    while homepage_action != 0 and homepage_action != 1:
        homepage_action = int(input("¿Es la primera vez que visita la página?"
                                    " (1=Afirmación/0=Negación):\n"))


        #Darse de alta por primera vez
        if homepage_action == 1:
            new_user = str(input("Introduzca su futuro nombre de usuario:\n"))
            new_password = str(input("Introduzca su nueva contraseña:\n"))
            confirmed_password = str(input("Confirme su nueva contraseña:\n"))

            if new_password != confirmed_password:
                homepage_action = 2
                print("Las contraseñas no coinciden")
            else:
                with open("usuarios.json", "r", encoding="utf-8", newline="") as file:
                    usuarios = json.load(file)
                flag = 0

                for i in usuarios:
                    if new_user == i["_username"]:
                        print("Ese nombre de usuario ya existe")
                        flag = 1

                if flag == 0:
                    salt = os.urandom(16)
                    kdf = Scrypt(
                        salt=salt,
                        length=32,
                        n=2 ** 14,
                        r=8,
                        p=1,
                    )

                    key = kdf.derive(bytes(new_password, encoding="utf-8"))
                    print(salt)

                    stored_salt = base64.b64encode(salt).decode("utf-8")
                    stored_key = base64.b64encode(key).decode("utf-8")

                    new_user = user_record(new_user, stored_key, stored_salt)
                    usuarios.append(new_user.__dict__)
                    with open("usuarios.json", "w", encoding="utf-8", newline="") as file:
                        json.dump(usuarios, file, indent=2)


        #Iniciar seión en una cuenta ya existente
        elif homepage_action == 0:
            current_user = str(input("Introduzca su nombre de usuario:\n"))
            current_password = str(input("Introduzca su contraseña:\n"))
            with open("usuarios.json", "r", encoding="utf-8", newline="") as file:
                usuarios = json.load(file)
            flag = 0
            for i in usuarios:
                if current_user == i["_username"]:
                    salt = base64.b64decode(i["_password"][1].encode("utf-8"))

                    kdf = Scrypt(
                        salt=salt,
                        length=32,
                        n=2 ** 14,
                        r=8,
                        p=1,
                    )

                    stored_password = base64.b64decode(i["_password"][0].encode("utf-8"))
                    current_password = bytes(current_password, encoding="utf-8")
                    print(stored_password)
                    print(current_password)

                    try:
                        kdf.verify(current_password, stored_password)
                    except cryptography.exceptions.InvalidKey as error:
                        flag = 0
                    else:
                        flag = 1
            if flag == 0:
                print("Sus credenciales son incorrentas")
            else:
                signed_up = True

        #respuesta distinta a 1 o 0
        else:
            print("Por favor otorgue una respuesta válida")


    #Bucle que pregunta al usuario que servicio desea utilizar siempre que exista una cuenta actualmente abierta
    while signed_up == True:
        account_action = int(input("¿Qué desea hacer?"
                                   "(0=Comprobar mensajes/1=Enviar mensajes/2=Cerrar sesión):\n"))


        #Enviar mensaje a otro usuario
        if account_action == 1:
            recipient_user = str(input("¿A quién desea enviar mensajes?\n"))
            with open("usuarios.json", "r", encoding="utf-8", newline="") as file:
                usuarios = json.load(file)
            flag = 0
            for i in usuarios:
                if recipient_user == i["_username"]:
                    flag = 1

            if flag == 1:
                first_message = True

                for i in usuarios:
                    if recipient_user == i["_username"]:

                        for j in i:
                            if current_user == j:
                                first_message = False

                        if first_message == True:
                            i[current_user] = {}


                        print(i[current_user])

                        now = datetime.now()
                        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
                        introduced_message = str(input("Escriba el mensaje:\n"))

                        introduced_message = bytes(introduced_message, encoding="utf-8")
                        aad = b"authenticated but unencrypted data"
                        key = ChaCha20Poly1305.generate_key()
                        chacha = ChaCha20Poly1305(key)
                        nonce = os.urandom(12)
                        message_to_store = chacha.encrypt(nonce, introduced_message, aad)

                        print(message_to_store)
                        #stored_date = base64.b64encode(dt_string).decode("utf-8")

                        nonce_to_store = base64.b64encode(nonce).decode("utf-8")
                        message_to_store = base64.b64encode(message_to_store).decode("utf-8")
                        aad_to_store = base64.b64encode(aad).decode("utf-8")
                        key_to_store = base64.b64encode(key).decode("utf-8")
                        print(message_to_store)

                        i[current_user][dt_string] = [nonce_to_store, message_to_store, aad_to_store, key_to_store]
                        with open("usuarios.json", "w", encoding="utf-8", newline="") as file:
                            json.dump(usuarios, file, indent=2)

            else:
                print("Ese usuario no existe")


        #Comprobar mensajes de otro usuario en cuestión
        elif account_action == 0:
            checked_user = str(input("¿De quién desea ver los mensajes recibidos?\n"))
            with open("usuarios.json", "r", encoding="utf-8", newline="") as file:
                usuarios = json.load(file)

            flag = 0
            for i in usuarios:
                if current_user == i["_username"]:

                    for j in i:
                        if checked_user == j:
                            flag = 1

                            for k in i[j].keys():
                                stored_nonce = i[j][k][0]
                                stored_message = i[j][k][1]
                                stored_aad = i[j][k][2]

                                stored_nonce = base64.b64decode(stored_nonce.encode("utf-8"))
                                stored_message = base64.b64decode(stored_message.encode("utf-8"))
                                stored_aad = base64.b64decode(stored_aad.encode("utf-8"))

                                stored_key = i[j][k][3]
                                stored_key = base64.b64decode(stored_key.encode("utf-8"))
                                chacha = ChaCha20Poly1305(stored_key)

                                showed_message = str(chacha.decrypt(stored_nonce, stored_message, stored_aad))[2:-1]
                                print(k + ": " + showed_message + "\n")

            if flag == 0:
                print("No tiene mensajes de este usuario o el usuario no existe")


        elif account_action == 2:
            signed_up = False


        else:
            print("Por favor otorge una respuesta válida")

        if signed_up == True:
            signed_up = int(input("¿Desea mantener la sesión abierta?"
                              " (1=Afirmación/0=Negación):\n"))
            signed_up = bool(signed_up)
        print(signed_up)


    exit = int(input("¿Desea salir de la aplicación?"
                     " (1=Afirmación/0=Negación):\n"))
    print(exit)





