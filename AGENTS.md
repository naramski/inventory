# Agents

* Ne fais jamais de commit. 

* Utilise des structure pour stocker les données, pas des array génériques ou des "Value" de serde. 


* Quand tu dois mettre à jour une donnée dans un système (SnipeIT ou Intune), ne mets à jour que les champs modifiés, conserver les valeurs existantes. 
* Reste conci dans test explications
* Ne crée pas de fichier de changements summary.
* Quand tu dois comparer deux users, fait le sur base de l'adresse email. 
* Quand tu dois faire correspondre deux devices, fais le sur base du numéro de série. Si le numéro de série échoue fait le sur l'asset tag (snipeit) qui correspond au device id (intune)

# Modèle

Dans SnipeIt et Intune on a les correspondance suivantes :

* Serial dans snipeit correspond à Serial_number dans intune. Il peut être None. 
* Asset_Tag doit toujours être défini. Il est équivalent au id dans intune device.  