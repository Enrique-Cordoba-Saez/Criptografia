# pylint: skip-file
import json
from datetime import datetime
import os
import base64
import cryptography
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

"""Estas dos constantes se emplean 
para la localización de lo archivos JSON"""
CLAVES_PUBLICAS_JSON = "claves_publicas_firmas.json"
USUARIOS_JSON = "usuarios.json"
CLAVES_MENSAJES_JSON = "claves_mensajes.json"

"""Esta clave debería estar guardada a salvo en otro
espacio más seguro, pero por el momento la mantendremos aquí"""
CLAVE_MAESTRA = b'_e\xe6\xdaJP+VH)C\xc0\x17\xcc\xc5]2\xc7\xe9\xde\x85[\xa2\xdb\xb8")\x94\x97\xc0p\x94'


# Clase empleada para introducir los datos de un nuevo usuario en la base de datos
class user_record:
    def __init__(self, introduced_username, introduced_password, employed_salt,
                 private_nonce, private_key, private_aad):
        self._username = introduced_username
        self._password = [introduced_password, employed_salt]
        self._private_key = [private_nonce, private_key, private_aad]


# Clase empleada para introducir los datos de un nuevo intercambio de mensajes entre usuarios en la base de datos
class messaging_key_entry:
    def __init__(self, user1, user2, entry_nonce, entry_key, entry_aad):
        self._involved_users = [user1, user2]
        self._key = [entry_nonce, entry_key, entry_aad]


class public_signature_key_entry:
    def __init__(self, introduced_username, introduced_key):
        self._username = introduced_username
        self._signature_key = introduced_key


# Variable que indica si la app está en ejecución (1) o no (0)
exit_app = 0
"""Listas de Python empleadas para almacenar temporalmente el contenido
de los archivos JSON"""
usuarios = []
claves_mensajes = []
claves_publicas = []

# Impresión en la consola del tiempo actual al iniciar el programa
now = datetime.now()
dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
print(dt_string)

"""Bucle principal de la aplicación que no se detiene hasta que la variable
exit_app sea fijada a 1"""
while exit_app != 1:
    homepage_action = -1
    signed_up = False
    while homepage_action != 0 and homepage_action != 1:

        """Preguntar al usuario por la acción que desea realizar 
        representada por la variable homepage_action"""
        try:
            homepage_action = int(input("¿Es la primera vez que visita la página?"
                                        " (1=Afirmación/0=Negación):\n"))

        # Obtención de una respuesta distinta a 1 o 0
        except ValueError:
            print("Por favor otorgue una respuesta válida")
        else:
            if homepage_action not in [0, 1]:
                print("Por favor otorgue una respuesta válida")

        # Darse de alta por primera vez
        if homepage_action == 1:
            new_user = str(input("Introduzca su futuro nombre de usuario:\n"))
            new_password = str(input("Introduzca su nueva contraseña:\n"))
            confirmed_password = str(input("Confirme su nueva contraseña:\n"))

            if new_password != confirmed_password:
                homepage_action = 2
                print("Las contraseñas no coinciden")
            else:
                with open(USUARIOS_JSON, "r", encoding="utf-8", newline="") as file:
                    usuarios = json.load(file)

                # Buscamos si el nombre de usuario solicitado ya ha sido reclamado
                flag = 0
                for i in usuarios:
                    if new_user == i["_username"]:
                        print("Ese nombre de usuario ya existe")
                        flag = 1

                """Si las credenciales introducidas son válidas se crea una nueva 
                entrada de usuario en el archivo JSON de almacenamiento de usuarios
                y mensajes (usuarios.json)"""
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
                    stored_salt = base64.b64encode(salt).decode("utf-8")
                    stored_key = base64.b64encode(key).decode("utf-8")

                    # Ahora generamos las claves de firma privada y pública
                    private_sign_key = ed25519.Ed25519PrivateKey.generate()
                    public_sign_key = private_sign_key.public_key()
                    private_sign_key = private_sign_key.private_bytes_raw()
                    public_sign_key = public_sign_key.public_bytes_raw()
                    stored_public_sign_key = base64.b64encode(public_sign_key).decode("utf-8")

                    # Cifrado de la clave de firma privada
                    aad = b"authenticated but unencrypted data"
                    chachaMaestro = ChaCha20Poly1305(CLAVE_MAESTRA)
                    nonce = os.urandom(12)

                    private_sign_key = chachaMaestro.encrypt(nonce, private_sign_key, aad)
                    private_sign_key_to_store = base64.b64encode(private_sign_key).decode("utf-8")
                    sign_nonce_to_store = base64.b64encode(nonce).decode("utf-8")
                    sign_aad_to_store = base64.b64encode(aad).decode("utf-8")

                    # Introducimos una nueva entrada del almacén de claves de firma pública
                    with open(CLAVES_PUBLICAS_JSON, "r", encoding="utf-8", newline="") as signatureFile:
                        claves_publicas = json.load(signatureFile)
                    entrada = public_signature_key_entry(new_user, stored_public_sign_key)
                    claves_publicas.append(entrada.__dict__)
                    with open(CLAVES_PUBLICAS_JSON, "w", encoding="utf-8", newline="") as signatureFile:
                        json.dump(claves_publicas, signatureFile, indent=2)

                    # Aquí creamos la entrada del usuario en la base de datos de usuarios
                    new_user = user_record(new_user, stored_key, stored_salt, sign_nonce_to_store,
                                           private_sign_key_to_store, sign_aad_to_store)
                    usuarios.append(new_user.__dict__)
                    with open(USUARIOS_JSON, "w", encoding="utf-8", newline="") as file:
                        json.dump(usuarios, file, indent=2)

        # Iniciar sesión en una cuenta ya existente
        elif homepage_action == 0:
            current_user = str(input("Introduzca su nombre de usuario:\n"))
            current_password = str(input("Introduzca su contraseña:\n"))
            with open(USUARIOS_JSON, "r", encoding="utf-8", newline="") as file:
                usuarios = json.load(file)

            # Búsqueda del nombre especificado entre las entradas de usuarios
            flag = 0
            for i in usuarios:
                if current_user == i["_username"]:

                    """Extracción de la información necesaria para la verificación
                    dentro de la entrada de usuario correspondiente"""
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
                    # Comparación de la contraseña introducida con la contraseña almacenada
                    try:
                        kdf.verify(current_password, stored_password)
                    except cryptography.exceptions.InvalidKey as error:
                        flag = 0
                    else:
                        flag = 1

            if flag == 0:
                print("Sus credenciales son incorrectas")

            else:
                signed_up = True

    # Bucle que pregunta al usuario que servicio desea utilizar mientras haya una cuenta actualmente abierta
    while signed_up:
        account_action = -1
        while account_action != 0 and account_action != 1 and account_action != 2:
            # Preguntar al usuario por la acción que desea realizar
            try:
                account_action = int(input("¿Qué desea hacer?"
                                           "(0=Comprobar mensajes/1=Enviar mensajes/2=Cerrar sesión):\n"))
            # Obtención de una respuesta distinta a 2, 1 o 0
            except ValueError:
                print("Por favor otorgue una respuesta válida")
            else:
                if account_action not in [0, 1, 2]:
                    print("Por favor otorgue una respuesta válida")

        # Enviar mensaje a otro usuario
        if account_action == 1:
            recipient_user = str(input("¿A quién desea enviar mensajes?\n"))
            with open(USUARIOS_JSON, "r", encoding="utf-8", newline="") as file:
                usuarios = json.load(file)

            # Comprobar que el usuario a quien se desea enviar un mensaje realmente existe
            flag = 0
            for i in usuarios:
                if recipient_user == i["_username"]:
                    flag = 1
            if flag == 1:

                with open(CLAVES_MENSAJES_JSON, "r", encoding="utf-8", newline="") as keysFile:
                    claves_mensajes = json.load(keysFile)
                for i in usuarios:
                    if recipient_user == i["_username"]:

                        """Comprobar si es la primera vez que los 2 usuarios entablan contacto
                        En cuyo caso se crea una nueva clave de cifrado"""
                        first_message = True
                        warning = 0
                        for j in claves_mensajes:
                            if current_user in j["_involved_users"] and recipient_user in j["_involved_users"]:
                                first_message = False
                        if first_message:
                            i.update({current_user: {}})
                            key = ChaCha20Poly1305.generate_key()

                            aad = b"authenticated but unencrypted data"
                            chachaMaestro = ChaCha20Poly1305(CLAVE_MAESTRA)
                            nonce = os.urandom(12)

                            key = chachaMaestro.encrypt(nonce, key, aad)
                            key_to_store = base64.b64encode(key).decode("utf-8")
                            nonce_to_store = base64.b64encode(nonce).decode("utf-8")
                            aad_to_store = base64.b64encode(aad).decode("utf-8")

                            new_messaging_key = messaging_key_entry(current_user, recipient_user,
                                                                    nonce_to_store, key_to_store, aad_to_store)
                            claves_mensajes.append(new_messaging_key.__dict__)
                            with open(CLAVES_MENSAJES_JSON, "w", encoding="utf-8", newline="") as keysFile:
                                json.dump(claves_mensajes, keysFile, indent=2)

                        # Si no es la primera vez, puede ser que uno de los dos interlocutores aún
                        # no haya enviado mensajes en cuyo caso es necesario hacer uso de la variable 'warning'
                        # para que se ejecute 'recipient_user.update({current_user: {}})' (Ver línea 238)
                        else:
                            warning = 1
                            for a in usuarios:
                                if recipient_user == a["_username"]:
                                    for b in a.keys():
                                        if b == current_user:
                                            warning = 0

                        """Redactar y cifrar el mensaje"""
                        now = datetime.now()
                        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
                        introduced_message = str(input("Escriba el mensaje:\n"))
                        introduced_message = bytes(introduced_message, encoding="utf-8")
                        for k in claves_mensajes:
                            if current_user in k["_involved_users"] and recipient_user in k["_involved_users"]:
                                stored_key = base64.b64decode(k["_key"][1].encode("utf-8"))

                                aadMaestro = base64.b64decode(k["_key"][2].encode("utf-8"))
                                chachaMaestro = ChaCha20Poly1305(CLAVE_MAESTRA)
                                nonceMaestro = base64.b64decode(k["_key"][0].encode("utf-8"))

                                key = chachaMaestro.decrypt(nonceMaestro, stored_key, aadMaestro)

                        aad = b"authenticated but unencrypted data"
                        chacha = ChaCha20Poly1305(key)
                        nonce = os.urandom(12)
                        message_to_store = chacha.encrypt(nonce, introduced_message, aad)

                        # Firma del mensaje a enviar con clave privada
                        for w in usuarios:
                            if w["_username"] == current_user:
                                print(current_user)
                                decoded_sender_private_key_nonce = base64.b64decode(
                                                                    w["_private_key"][0].encode("utf-8"))
                                decoded_sender_private_key = base64.b64decode(w["_private_key"][1].encode("utf-8"))
                                decoded_sender_private_key_aad = base64.b64decode(w["_private_key"][2].encode("utf-8"))

                                chachaMaestro_firma = ChaCha20Poly1305(CLAVE_MAESTRA)
                                sender_private_key = chachaMaestro_firma.decrypt(
                                    decoded_sender_private_key_nonce, decoded_sender_private_key,
                                    decoded_sender_private_key_aad)
                                sender_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(sender_private_key)
                                print(sender_private_key)
                                print(type(message_to_store))
                                signed_message_to_store = sender_private_key.sign(message_to_store)


                        if warning == 1:
                            i.update({current_user: {}})

                        """Aquí se almacena el mensaje dentro de la base de datos json"""
                        nonce_to_store = base64.b64encode(nonce).decode("utf-8")
                        message_to_store = base64.b64encode(message_to_store).decode("utf-8")
                        aad_to_store = base64.b64encode(aad).decode("utf-8")
                        signed_message_to_store = base64.b64encode(signed_message_to_store).decode("utf-8")

                        i[current_user][dt_string] = [nonce_to_store, message_to_store, aad_to_store,
                                                      signed_message_to_store]
                        with open(USUARIOS_JSON, "w", encoding="utf-8", newline="") as file:
                            json.dump(usuarios, file, indent=2)

            else:
                print("Ese usuario no existe")

        # Comprobar mensajes recibidos de otros usuarios
        elif account_action == 0:
            with open(USUARIOS_JSON, "r", encoding="utf-8", newline="") as file:
                usuarios = json.load(file)
            with open(CLAVES_MENSAJES_JSON, "r", encoding="utf-8", newline="") as keysFile:
                claves_mensajes = json.load(keysFile)
            with open(CLAVES_PUBLICAS_JSON, "r", encoding="utf-8", newline="") as signFile:
                claves_publicas = json.load(signFile)

            flag = 0
            for i in usuarios:
                if current_user == i["_username"]:

                    # Repetir el proceso por cada otro usuario que le ha enviado mensajes
                    # al que está haciendo uso de la aplicación
                    for j in i.keys():
                        if j != "_username" and j != "_password" and j != "_private_key":
                            flag = 1
                            print("De " + j + ":")

                            # Extraemos la clave pública del emisor "j"
                            for q in claves_publicas:
                                if q["_username"] == j:
                                    clave_publica_firma = q["_signature_key"]
                                    clave_publica_firma = base64.b64decode(clave_publica_firma.encode("utf-8"))
                                    clave_publica_firma = ed25519.Ed25519PublicKey.from_public_bytes(
                                        clave_publica_firma)

                            # Extraemos la clave simétrica de cifrado de las comunicaciones entre
                            # el emisor "j" y el receptor "current_user"
                            for h in claves_mensajes:
                                if current_user in h["_involved_users"] and j in h["_involved_users"]:
                                    stored_key = base64.b64decode(h["_key"][1].encode("utf-8"))

                                    aadMaestro = base64.b64decode(h["_key"][2].encode("utf-8"))
                                    chachaMaestro = ChaCha20Poly1305(CLAVE_MAESTRA)
                                    nonceMaestro = base64.b64decode(h["_key"][0].encode("utf-8"))

                                    key = chachaMaestro.decrypt(nonceMaestro, stored_key, aadMaestro)

                            # Repetir proceso por cada mensaje del emisor "j"
                            for k in i[j].keys():
                                stored_nonce = i[j][k][0]
                                stored_message = i[j][k][1]
                                stored_aad = i[j][k][2]
                                stored_signed_message = i[j][k][3]

                                stored_nonce = base64.b64decode(stored_nonce.encode("utf-8"))
                                stored_message = base64.b64decode(stored_message.encode("utf-8"))
                                stored_aad = base64.b64decode(stored_aad.encode("utf-8"))
                                stored_signed_message = base64.b64decode(stored_signed_message.encode("utf-8"))

                                chacha = ChaCha20Poly1305(key)

                                # Comprobamos la veracidad del mensaje mediante la firma pública del emisor
                                print(clave_publica_firma)
                                try:
                                    clave_publica_firma.verify(stored_signed_message, stored_message)
                                except cryptography.exceptions.InvalidSignature as error:
                                    print("El siguiente mensaje puede no provenir del emisor")
                                else:
                                    print("El siguiente mensaje es verídico")



                                showed_message = str(chacha.decrypt(stored_nonce, stored_message, stored_aad))[2:-1]
                                print(k + ": " + showed_message)

            if flag == 0:
                print("Aún no ha recibido ningún mensaje")

        # Cerrar la sesión
        elif account_action == 2:
            signed_up = False

        if signed_up:
            signed_up = -1
            while signed_up != 1 and signed_up != 0:
                # Preguntar al usuario por la acción que desea realizar
                try:
                    signed_up = int(input("¿Desea mantener la sesión abierta?"
                                          " (1=Afirmación/0=Negación):\n"))

                # Obtención de una respuesta distinta a 1 o 0
                except ValueError:
                    print("Por favor otorgue una respuesta válida")
                else:
                    if signed_up not in [0, 1]:
                        print("Por favor otorgue una respuesta válida")

        signed_up = bool(signed_up)

    exit_app = -1
    while exit_app != 0 and exit_app != 1:
        # Preguntar al usuario por la acción que desea realizar
        try:
            exit_app = int(input("¿Desea salir de la aplicación?"
                                 " (1=Afirmación/0=Negación):\n"))

        # Obtención de una respuesta distinta a 1 o 0
        except ValueError:
            print("Por favor otorgue una respuesta válida")
        else:
            if exit_app not in [0, 1]:
                print("Por favor otorgue una respuesta válida")
