import re
import hashlib

def mdp101():
    
    while True :
        mdp = input ("Veuillez saisir un Mot de Passe : ")
        if not (len(mdp) >= 8):
            print ("Le mot de passe doit contenir au moins 8 caractères.")
        elif not re.search ("[A-Z]" , mdp):
            print ("Le mot de passe doit contenir au moins une Majuscule.")
        elif not re.search ("[a-z]" , mdp):
            print ("le mot de passe doit contenir au moins une minuscule.")
        elif not re.search ("[0-9]" , mdp):
            print ("le mot de passe doit contenir au moins un chiffre.")
        elif not re.search ("[?!@#$%^&*]", mdp):
            print ("le mot de passe doit contenir au moins un caractère spécial.")
        else :
            print ("Le mot de passe est valide !")
            return mdp
        
mdp = mdp101()

def mdp_crypt(mdp):
    return hashlib.sha256(mdp.encode()).hexdigest()

def save_mdp(mdp): 
    hashed = mdp_crypt(mdp)
    with open("mdps.json", "a") as file:
        file.write(hashed + "\n")
        print("Mot de passe enregistré avec succès!")
        print(f"Votre mot de passe crypté '{mdp}' : {hashed}") 

hashed = mdp_crypt(mdp)
save_mdp(mdp)

def check_double(mdp) :  #vérifie si le mdp existe dans le json en comparant le hash du mdp du user avec les hashes enregistrés.
    with open("mdps.json", "r") as file:
        hashed_mdps = file.readlines()
        hashed_mdp = mdp_crypt(mdp)
        if hashed_mdp + "\n" in hashed_mdps:
            print("Ce mot de passe existe déjà.")
        else:
            save_mdp(mdp)  #Si le mdp est nouveau, "save_mdp" pour enregistrer

def add_mdp():            #Demande de saisir un nouveau mdp, puis utilise "checkpwd" pour vérif si le mdp est existant dans "mdps.json"
    mdp101()
    check_double(mdp)

def list_mdp():           #Lit le fichier "mdps.json" et affiche la liste des hashes des mdp enregistrés
    with open("mdps.json", "r") as file:
        hashed_mdps = file.readlines()
        if hashed_mdps:
            print("Liste des mots de passe enregistrés: ")
            for hashed_mdp in hashed_mdps:
                print(hashed_mdp.strip())
        else:
            print("Aucun mot de passe enregistré.")

while True:  #Afficher le menu avec les trois options
    print("Que voulez-vous faire ?")
    print("1 - Ajouter un mot de passe")
    print("2 - Afficher les mots de passe enregistrés")
    print("3 - Quitter")
    choice = input(">")
    if choice == "1":
        add_mdp()
    elif choice == "2":
        list_mdp()
    elif choice == "3":
        break
    else:
        print("Choix invalide.")