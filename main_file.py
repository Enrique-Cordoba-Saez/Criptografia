# pylint: skip-file
import json
import time
from datetime import datetime, timedelta
import os
import base64
import cryptography
import abc
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import KeySerializationEncryption, Encoding, PrivateFormat
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

"""Estas dos constantes se emplean 
para la localización de lo archivos JSON"""
USUARIOS_JSON = "JSON/usuarios.json"
CLAVES_MENSAJES_JSON = "JSON/claves_mensajes.json"

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


# Variable que indica si la app está en ejecución (1) o no (0)
exit_app = 0
"""Listas de Python empleadas para almacenar temporalmente el contenido
de los archivos JSON"""
usuarios = []
claves_mensajes = []

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
                    private_sign_key = private_sign_key.private_bytes_raw()

                    """--------------------------------------------------------------------
                    Creación de un certificado y su petición de firma para la autoridad AC1
                    --------------------------------------------------------------------"""
                    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                        # Información sobre el usuario.
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "MADRID"),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, "LEGANES"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M"),
                        x509.NameAttribute(NameOID.COMMON_NAME, 'Usuario: ' + str(new_user)),
                        x509.NameAttribute(NameOID.EMAIL_ADDRESS, str(new_user) + '@uc3m.alumnos.es')
                    ])).add_extension(
                        x509.SubjectAlternativeName([
                            # Describe what sites we want this certificate for.
                            x509.DNSName("mysite.com"),
                            x509.DNSName("www.mysite.com"),
                            x509.DNSName("subdomain.mysite.com"),
                        ]),
                        critical=False,
                    ).sign(ed25519.Ed25519PrivateKey.from_private_bytes(private_sign_key), None)

                    # Extracción de la clave privada de la autoridad
                    with open("AC1/privado/ca1key.pem", "rb") as authkey:
                        authority_private_key = serialization.load_pem_private_key(authkey.read(),
                                                                                   password=b'claveAC1', )

                    # Creación de un directorio para depositar el certificado y clave del nuevo usuario
                    os.mkdir(str(new_user))
                    with open(str(new_user) + "/" + str(new_user) + "key.pem", "wb") as usu:
                        psk = ed25519.Ed25519PrivateKey.from_private_bytes(private_sign_key)
                        usu.write(psk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8,
                                                    serialization.BestAvailableEncryption(bytes('clave' + str(new_user),
                                                                                                encoding="utf-8"))))
                    # Envio de la solicitud de firma del certificado del nuevo usuario a la autoridad
                    with open("AC1/solicitudes/" + str(new_user) + "req.pem", "wb") as f:
                        f.write(csr.public_bytes(serialization.Encoding.PEM))
                    with open("AC1/serial", "r") as serial:
                        NUMERO_SERIAL_DE_LA_AUTORIDAD = serial.read().strip()
                        print("AC1/nuevoscerts/" + NUMERO_SERIAL_DE_LA_AUTORIDAD + ".pem")

                    print("Se esta procesando su certificación")
                    while not os.path.isfile("AC1/nuevoscerts/" + NUMERO_SERIAL_DE_LA_AUTORIDAD + ".pem"):
                        pass
                    time.sleep(1)
                    os.rename("AC1/nuevoscerts/" + NUMERO_SERIAL_DE_LA_AUTORIDAD + ".pem", str(new_user) + "/"
                              + str(new_user) + "cert.pem")
                    print("Usted ha sido verificado con éxito")

                    """--------------------------------
                    Cifrado de la clave de firma privada
                    ---------------------------------"""
                    aad = b"authenticated but unencrypted data"
                    chachaMaestro = ChaCha20Poly1305(CLAVE_MAESTRA)
                    nonce = os.urandom(12)

                    private_sign_key = chachaMaestro.encrypt(nonce, private_sign_key, aad)
                    private_sign_key_to_store = base64.b64encode(private_sign_key).decode("utf-8")
                    sign_nonce_to_store = base64.b64encode(nonce).decode("utf-8")
                    sign_aad_to_store = base64.b64encode(aad).decode("utf-8")

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

                                decoded_sender_private_key_nonce = base64.b64decode(
                                    w["_private_key"][0].encode("utf-8"))
                                decoded_sender_private_key = base64.b64decode(w["_private_key"][1].encode("utf-8"))
                                decoded_sender_private_key_aad = base64.b64decode(w["_private_key"][2].encode("utf-8"))

                                chachaMaestro_firma = ChaCha20Poly1305(CLAVE_MAESTRA)
                                sender_private_key = chachaMaestro_firma.decrypt(
                                    decoded_sender_private_key_nonce, decoded_sender_private_key,
                                    decoded_sender_private_key_aad)
                                sender_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(sender_private_key)

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

            flag = 0
            for i in usuarios:
                if current_user == i["_username"]:

                    # Repetir el proceso por cada otro usuario que le ha enviado mensajes
                    # al que está haciendo uso de la aplicación
                    for j in i.keys():
                        if j != "_username" and j != "_password" and j != "_private_key":
                            flag = 1

                            """Comprobamos la autenticidad del certificado del emisor
                                                             consultado a la autoridad AC1"""
                            # Certificado del emisor
                            with open(str(j) + "/" + str(j) + "cert.pem", "rb") as certFile:
                                certificate_in_bytes = certFile.read()
                                certificate = x509.load_pem_x509_certificate(certificate_in_bytes)

                            # También debemos consultar el certificado de la autoridad
                            with open("AC1/ac1cert.pem", "rb") as AC1File:
                                AC1_certificate_in_bytes = AC1File.read()
                                AC1_certificate = x509.load_pem_x509_certificate(AC1_certificate_in_bytes)

                            """Verificamos la firma del certificado asociado al emisor mediante la clave 
                            pública de la autoridad"""
                            signature_toVerify = certificate.signature
                            AC1_clave_publica = AC1_certificate.public_key()

                            try:
                                AC1_clave_publica.verify(signature_toVerify, certificate.tbs_certificate_bytes,
                                                         certificate.signature_algorithm_parameters,
                                                         certificate.signature_hash_algorithm)
                            except cryptography.exceptions.InvalidSignature as error:
                                print("Este usuario puede no ser quien dice ser")
                            else:
                                print("Este usuario ha sido certificado por la autoridad central")

                            print("De " + j + ":")

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

                                """Comprobamos ahora la veracidad del mensaje mediante la clave pública 
                                de firma del emisor"""

                                try:
                                    certificate.public_key().verify(stored_signed_message, stored_message)
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
