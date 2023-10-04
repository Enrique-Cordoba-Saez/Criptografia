import json
from datetime import datetime
import Crypto

exit = 0
usuarios = []


class user_record:
    def __init__(self, introduced_username, introduced_password):
        self._username = introduced_username
        self._password = introduced_password


class message:
    def __init__(self, sender, recipient, content):
        self._sender = sender
        self._recipient = recipient
        self._content = content



now = datetime.now()
dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
print(dt_string)


while exit != 1:
    homepage_action = 2
    signed_up = False
    while homepage_action != 0 and homepage_action != 1:
        homepage_action = int(input("¿Es la primera vez que visita la página?\n"))


        #Sign up for the first time
        if homepage_action == 1:
            new_user = str(input("Introduzca su futuro nombre de usuario:\n"))
            new_password = int(input("Introduzca su nueva contraseña:\n"))
            confirmed_password = int(input("Confirme su nueva contraseña:\n"))
            if new_password != confirmed_password:
                homepage_action = 2
                print("Las contraseñas no coinciden")
            with open("users.json", "r", encoding="utf-8", newline="") as file:
                usuarios = json.load(file)
            flag = 0
            for i in usuarios:
                if new_user == i["_username"]:
                    print("Ese nombre de usuario ya existe")
                    flag = 1
            if flag == 0:
                new_user = user_record(new_user, confirmed_password)
                usuarios.append(new_user.__dict__)
                with open("users.json", "w", encoding="utf-8", newline="") as file:
                    json.dump(usuarios, file, indent=2)


        #Log in normally
        elif homepage_action == 0:
            current_user = str(input("Introduzca su nombre de usuario:\n"))
            current_password = int(input("Introduzca su contraseña:\n"))
            with open("users.json", "r", encoding="utf-8", newline="") as file:
                usuarios = json.load(file)
            flag = 0
            for i in usuarios:
                if current_user == i["_username"]:
                    if current_password == i["_password"]:
                        flag = 1
            if flag == 0:
                print("Sus credenciales son incorrentas")
            else:
                signed_up = True


        #Wrong answer given
        else:
            print("Por favor otorge una respuesta válida")



    while signed_up == True:
        account_action = int(input("¿Qué desea hacer?\n"))


        #Enviar mensaje
        if account_action == 1:
            recipient_user = str(input("¿A quién desea enviar mensajes?\n"))
            with open("users.json", "r", encoding="utf-8", newline="") as file:
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
                                print(i[j])
                                now = datetime.now()
                                dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
                                i[j][dt_string] = str(input("Escriba el mensaje:\n"))
                                with open("users.json", "w", encoding="utf-8", newline="") as file:
                                    json.dump(usuarios, file, indent=2)
                        if first_message == True:
                            i[current_user] = {}
                            now = datetime.now()
                            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
                            i[current_user][dt_string] = str(input("Escriba el mensaje:\n"))
                            with open("users.json", "w", encoding="utf-8", newline="") as file:
                                json.dump(usuarios, file, indent=2)

            else:
                print("Ese usuario no existe")


        #Comprobar mensajes
        elif account_action == 0:
            checked_user = str(input("¿De quién desea ver los mensajes recibidos?\n"))
            with open("users.json", "r", encoding="utf-8", newline="") as file:
                usuarios = json.load(file)
            flag = 0
            for i in usuarios:
                if current_user == i["_username"]:
                    for j in i:
                        if checked_user == j:
                            flag = 1
                            for k in i[j].keys():
                                print(k + ": " + i[j][k] + "\n")
            if flag == 0:
                print("No tiene mensajes de este usuario o el usuario no existe")


        else:
            print("Por favor otorge una respuesta válida")

        signed_up = int(input("¿Desea mantener la sesión abierta?\n"))
        signed_up = bool(signed_up)
        print(signed_up)


    exit = int(input("¿Desea salir de la aplicación?\n"))
    print(exit)





