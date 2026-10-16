# TP — Détection et correction d'une injection SQL avec SonarQube

Entreprise fil rouge : NOVA SERVICES
Application étudiée : TIWAP (application volontairement vulnérable, utilisée uniquement comme support d'analyse)
Outils : Docker Compose, SonarQube Community Build 26.10, PostgreSQL 17, SonarScanner CLI 8.1, Python 3.13, pytest

---

## 1. Architecture du laboratoire

J'ai déployé trois services avec Docker Compose (fichier `compose.yaml`) :

| Service | Rôle |
|---|---|
| `db` | Base PostgreSQL qui stocke les données de SonarQube (projets, analyses, utilisateurs) |
| `sonarqube` | Interface web et moteur d'analyse, accessible uniquement sur `127.0.0.1:9000` |
| `scanner` | SonarScanner CLI, qui analyse le dossier `TIWAP` monté dans `/usr/src`. Il ne démarre que quand je l'appelle (profil `scan`) |

Les trois services communiquent sur le réseau Docker `sonarnet`. Les données sont conservées dans des volumes, donc elles survivent à un `docker compose down`.

Le mot de passe de la base n'est pas dans `compose.yaml` : il est lu depuis un fichier `.env`, qui est exclu par `.gitignore`. Le jeton d'analyse est passé uniquement par variable d'environnement au moment du scan. Il n'apparaît dans aucun fichier.

J'ai gardé le `compose.yaml` du laboratoire séparé du `docker-compose.yml` de TIWAP. Toutes mes commandes Docker sont lancées depuis `tp-sonarqube-nova`, ce qui évite de démarrer l'application vulnérable par erreur.

**Question 1 — Pourquoi SonarQube utilise PostgreSQL plutôt que de tout stocker dans son conteneur ?**
Un conteneur est jetable : si on le supprime ou qu'on le met à jour, ce qu'il contient disparaît. En séparant la base dans son propre service avec un volume persistant, les analyses et la configuration sont conservées indépendamment de SonarQube. La base embarquée est réservée aux tests et n'est pas adaptée à un usage réel.

**Question 2 — Pourquoi `http://sonarqube:9000` entre conteneurs et `http://localhost:9000` dans le navigateur ?**
Dans un conteneur, `localhost` désigne le conteneur lui-même. Pour le scanner, `localhost:9000` pointerait donc sur lui-même, où il n'y a rien. Docker fournit un DNS interne au réseau `sonarnet`, qui résout le nom du service `sonarqube` vers le bon conteneur. Mon navigateur, lui, passe par le port publié sur ma machine (`127.0.0.1:9000`).

---

## 2. Analyse initiale

Configuration de l'analyse (`TIWAP/sonar-project.properties`) :

```properties
sonar.projectKey=tiwap
sonar.projectName=TIWAP
sonar.projectVersion=1.0
sonar.sources=.
sonar.sourceEncoding=UTF-8
sonar.python.version=3
```

Résultat global (voir capture de l'Overview) :

- 2,4k lignes de code analysées
- 51 problèmes ouverts : 30 en sécurité, 21 en fiabilité, 7 en maintenabilité (un problème peut toucher plusieurs catégories)
- Quality Gate : **Failed** (1 condition non respectée)
- Duplications : 6,1 %
- Couverture : 0,0 %

Dans cette version de SonarQube, les Security Hotspots sont dépréciés. La page dédiée est vide et les résultats de ce type apparaissent directement dans l'onglet Issues, en catégorie Security.

### Tableau d'analyse initiale (anomalies de sécurité pertinentes)

J'ai extrait la liste complète des 30 problèmes de sécurité via l'API (`issues_securite_avant.txt`). Les plus pertinents :

| Règle | Fichier et ligne | Problème | Type | Impact potentiel | Confiance | Action |
|---|---|---|---|---|---|---|
| python:S6779 | app.py L29 | Clé secrète Flask écrite en dur (Blocker) | Vulnérabilité | Falsification des sessions si le code fuite | Non examiné manuellement | Corriger : clé dans une variable d'environnement |
| python:S8392 | app.py L913 | Application liée à toutes les interfaces réseau (Blocker) | Vulnérabilité | Exposition de l'application sur le réseau | Non examiné manuellement | Corriger : écouter sur 127.0.0.1 hors besoin réel |
| python:S4507 | app.py L913 | Mode debug activé | Revue | Exécution de code via la console de debug Flask | Non examiné manuellement | Corriger avant toute mise en production |
| python:S4502 | app.py L28 | Protection CSRF désactivée | Revue | Actions forcées à l'insu de l'utilisateur | Non examiné manuellement | Examiner puis corriger |
| python:S5247 | app.py L40 | Échappement automatique désactivé | Revue | Injection XSS dans les templates | Non examiné manuellement | Examiner puis corriger |
| python:S5659 | helper/auth.py L39 | Jeton JWT utilisé sans vérification de signature | Vulnérabilité | Usurpation d'identité avec un jeton forgé | Non examiné manuellement | Corriger : vérifier la signature |
| python:S4830 | app.py L723, L728, L731 | Validation des certificats TLS désactivée | Vulnérabilité | Interception des échanges (man-in-the-middle) | Non examiné manuellement | Corriger : réactiver la validation |
| python:S2068 / javascript:S2068 | helper/mongodb_manager.py L68-69, init-db.js L8, L12 | Mots de passe potentiellement en dur | Revue | Accès à la base si le code fuite | Non examiné manuellement | Examiner, sortir les secrets du code |
| python:S4790 | vulnerabilities/SQLi.py L151, helper/db_manager.py L47, L55, helper/mongodb_manager.py L45 | Hachage faible (MD5) | Revue | Mots de passe cassables en cas de fuite de la base | Confirmé pour SQLi.py (import de `md5`) | Corriger : algorithme adapté aux mots de passe |
| python:S3330 / S2092 | app.py L848, L880, L898 | Cookies sans `HttpOnly` ni `secure` | Revue | Vol de cookie de session | Non examiné manuellement | Examiner puis corriger |
| python:S2245 | app.py L760 | Générateur pseudo-aléatoire non sûr | Revue | Valeurs prévisibles si usage sécurité | Non examiné manuellement | Examiner l'usage |
| docker:S6471 / S6470 | Dockerfile L1, L4 | Conteneur lancé en root, copie récursive | Revue | Privilèges excessifs, fichiers sensibles dans l'image | Non examiné manuellement | Examiner |
| Web:S5725 | templates/dashboard_layout.html L19-21 | Scripts externes sans contrôle d'intégrité | Revue | Script modifié chez le fournisseur exécuté | Non examiné manuellement | Corriger : attributs `integrity` |
| **Aucune règle** | **vulnerabilities/SQLi.py L22-25** | **Injection SQL dans `sqli_low()`** | **Non signalée par SonarQube** | **Contournement d'authentification** | **Confirmé par examen du code** | **Corriger (anomalie étudiée)** |

---

## 3. Recherche de l'injection SQL

### Ce que SonarQube a signalé

Aucun des 30 problèmes de sécurité ne correspond à une injection SQL. La règle dédiée (`pythonsecurity:S3649`) n'apparaît pas. Le seul résultat dans `vulnerabilities/SQLi.py` concerne le hachage MD5 (ligne 151), pas les requêtes.

Dans l'édition Community, l'analyse de flux (taint analysis), qui suit une donnée depuis `request.form` jusqu'à `execute()`, n'est pas disponible. Je n'ai donc pas de résultat de scanner pour cette anomalie, et je l'ai identifiée par examen manuel du code.

### Examen manuel

J'ai recherché les requêtes SQL et les entrées utilisateur :

```bash
grep -RInE "execute\(|SELECT|request\.args|request\.form" TIWAP --include="*.py"
```

Deux styles de code apparaissent dans le même projet :

| Fichier | Style | Verdict |
|---|---|---|
| `helper/db_manager.py` | `execute("... WHERE username = ?", (username,))` | Requête paramétrée, correcte |
| `vulnerabilities/SQLi.py` L22, L40, L63, L82, L100, L123 | `"... WHERE username='%s' ..." % (...)` | Entrée insérée dans le texte SQL |
| `vulnerabilities/SQLi.py` L145 | `f"... WHERE username=\"{username}\""` | Même problème avec une f-string |

J'ai choisi d'étudier la fonction `sqli_low()` (lignes 22 à 25), qui gère une connexion par identifiant et mot de passe.

### Chemin de la donnée

1. **Entrée** : `app.py`, route `/sql-injection`, niveau 0 : `username = request.form.get('username')` et `password = request.form.get('password')`. Les valeurs viennent directement du formulaire.
2. **Transmission** : `sqli.sqli_low(username=username, password=password)`.
3. **Construction** : `SQLi.py` L22 : les valeurs sont insérées dans la requête avec `%s`.
4. **Exécution** : `SQLi.py` L25 : `cur.execute(stmt)` exécute le texte tel quel.

---

## 4. Mécanisme de la vulnérabilité

Code vulnérable :

```python
stmt = "SELECT userid, username FROM users WHERE username='%s' AND password='%s'" \
       % (str(username), str(password))

result = cur.execute(stmt)
```

La saisie de l'utilisateur fait partie du texte de la requête. Une apostrophe dans la saisie ferme la chaîne SQL, et ce qui suit est interprété comme du SQL. Par exemple, avec le mot de passe `' OR '1'='1`, la requête devient :

```sql
SELECT userid, username FROM users WHERE username='x' AND password='' OR '1'='1'
```

La condition `'1'='1'` est toujours vraie, donc la requête renvoie des utilisateurs sans connaître le mot de passe. C'est un contournement d'authentification, qui touche la confidentialité des données.

Deux éléments aggravent ou modèrent le risque :
- La route est protégée par `@is_logged` : il faut déjà être connecté. Cela réduit l'exposition, mais tout utilisateur authentifié peut exploiter la faille.
- En cas d'erreur, la fonction renvoie l'exception SQL brute (`return e`). Ces messages donnent des indications à un attaquant pour ajuster sa saisie.

---

## 5. Correction

J'ai travaillé sur une branche dédiée, `fix/sql-injection-lab`, et je n'ai modifié que la fonction `sqli_low()`.

Code corrigé :

```python
stmt = "SELECT userid, username FROM users WHERE username = ? AND password = ?"

result = cur.execute(stmt, (str(username), str(password)))
```

### Explication technique

La requête est maintenant paramétrée. La structure SQL est fixée à l'avance avec des marqueurs `?`, et les valeurs de l'utilisateur sont passées à part, en second argument de `execute()`. Le pilote SQLite les transmet comme des valeurs, jamais comme du code SQL. Une apostrophe ou un `OR` dans la saisie est donc cherché tel quel dans la colonne, et ne modifie plus la logique de la requête.

J'ai utilisé `?` parce que TIWAP utilise SQLite (`TIWAP.db`). Avec un autre pilote, le marqueur serait différent (par exemple `%s` avec psycopg pour PostgreSQL).

La même pratique est déjà appliquée dans `helper/db_manager.py`, ce qui montre que la correction est cohérente avec le reste du projet.

Le diff complet est dans `correction_sqli.diff`.

---

## 6. Tests

Le dépôt TIWAP ne contient aucun test. J'ai donc écrit un test de non-régression : `tests/test_sqli_low.py`.

Le test remplace la vraie base par une base SQLite en mémoire contenant deux utilisateurs fictifs (`alice` et `bob`). Il est isolé, reproductible, et ne touche pas `TIWAP.db`. Il vérifie quatre cas :

| Test | Ce qu'il vérifie |
|---|---|
| `test_identifiants_valides_fonctionnent` | Un utilisateur avec le bon mot de passe est toujours reconnu : le comportement normal est conservé |
| `test_mauvais_mot_de_passe_ne_renvoie_rien` | Un mauvais mot de passe ne renvoie rien |
| `test_injection_dans_le_mot_de_passe_neutralisee` | `' OR '1'='1` dans le mot de passe ne renvoie rien |
| `test_injection_dans_le_nom_utilisateur_neutralisee` | `' OR '1'='1' --` dans le nom d'utilisateur ne renvoie rien |

Pour prouver que le test détecte vraiment la faille, je l'ai lancé sur les deux versions du code :

| Version | Résultat |
|---|---|
| Code vulnérable (commit précédent) | **2 échecs sur 4** : les deux tests d'injection échouent, la requête renvoie alice et bob sans le bon mot de passe |
| Code corrigé | **4 tests réussis sur 4** |

Les sorties complètes sont dans `preuve_tests_avant.txt` et `preuve_tests_apres.txt`. Si une modification future réintroduit la concaténation, ce test échouera.

---

## 7. Comparaison avant / après

J'ai relancé l'analyse SonarQube sur la branche corrigée et comparé la liste des problèmes de sécurité.

| Critère | Avant correction | Après correction |
|---|---|---|
| Anomalie étudiée | Injection SQL dans `sqli_low()` | Injection neutralisée |
| Règle concernée | Aucune règle déclenchée (taint analysis absente de l'édition Community) | Aucune règle déclenchée |
| Emplacement | `vulnerabilities/SQLi.py` L22-25, appelée par la route `/sql-injection` | Même fonction, L22-24 |
| Code vulnérable présent ? | Oui, confirmé par lecture du code | Non, requête paramétrée |
| Tests de régression | Aucun dans le dépôt. Avec mon test : 2 échecs sur 4 | 4 réussis sur 4 |
| Problèmes de sécurité SonarQube | 30 | 30 |
| Risque résiduel | Élevé | Faible sur cette fonction (voir ci-dessous) |

La seule différence entre les deux listes est le problème S4790 (hachage MD5), qui passe de la ligne 151 à la ligne 150. Ma correction a retiré une ligne dans le fichier, donc ce problème s'est décalé. Ce n'est ni un nouveau problème ni une correction.

SonarQube n'avait pas détecté l'injection avant la correction, il ne peut donc pas en constater la disparition après. La preuve de la correction repose sur la lecture du code et sur le test de non-régression.

Risque résiduel après correction :
- Les autres fonctions de `SQLi.py` (niveaux medium et hard, blind SQL injection, ligne 145) utilisent toujours la concaténation.
- `return e` renvoie toujours les erreurs SQL détaillées à l'utilisateur.
- Les mots de passe sont hachés en MD5 (S4790).

---

## 8. Fiche de traitement de l'anomalie — NOVA SERVICES

Pour cette fiche, je considère l'anomalie comme si elle se trouvait dans une application interne de NOVA SERVICES de gestion des clients.

| Élément | Contenu |
|---|---|
| Anomalie | Injection SQL dans la fonction de connexion `sqli_low()` |
| Actif concerné | Application de gestion des clients (module d'authentification) |
| Source de détection | Revue manuelle du code. Non détectée par SonarQube Community |
| Responsable de correction | Développeur référent de l'application, validation par le tech lead |
| Priorité | **Élevée** |
| Échéance | 7 jours après détection (23 octobre 2026) |
| Statut | Corrigé sur la branche `fix/sql-injection-lab`, en attente de revue et de fusion |
| Preuve de correction | Diff du code, test de non-régression (2/4 avant, 4/4 après), nouvelle analyse SonarQube |
| Risque résiduel | Autres requêtes non paramétrées dans le même fichier, messages d'erreur SQL exposés, hachage MD5 |
| Actions suivantes | Corriger les autres requêtes, remplacer `return e` par un message générique, remplacer MD5 |

### Justification de la priorité

| Critère | Analyse |
|---|---|
| Criticité de l'application et des données | Données clients : confidentialité importante |
| Exposition | Route accessible à tout utilisateur connecté |
| Exploitabilité | Simple : une saisie dans un formulaire suffit, sans outil particulier |
| Conséquences CIA | Confidentialité : accès à des comptes sans mot de passe. Intégrité et disponibilité : limitées pour cette requête `SELECT`, mais d'autres requêtes du même type pourraient en être affectées |
| Mesures compensatoires | Authentification préalable (`@is_logged`), qui réduit l'exposition sans empêcher l'exploitation |

Je ne la classe pas en critique, parce que la route demande déjà une authentification. Si la même faille se trouvait sur une page publique, je la classerais critique avec une correction sous 48 heures.

---

## 9. Mini-tableau de bord

Valeurs relevées sur TIWAP au 16 octobre 2026 :

| Indicateur | Valeur actuelle |
|---|---|
| Problèmes de sécurité ouverts | 30 (dont 2 Blocker) |
| Quality Gate | Failed |
| Couverture de tests | 0,0 % |
| Anomalies corrigées et vérifiées | 1 (injection SQL `sqli_low`) |

### Définition des indicateurs proposés

| Indicateur | Définition | Source | Fréquence | Responsable | Décision qu'il permet de prendre |
|---|---|---|---|---|---|
| Vulnérabilités ouvertes par priorité | Nombre de vulnérabilités non corrigées, par niveau de priorité | SonarQube + suivi des tickets | À chaque analyse, synthèse hebdomadaire | Responsable sécurité | Répartir l'effort de correction et décider d'un sprint dédié si les priorités élevées augmentent |
| Vulnérabilités critiques ou élevées en retard | Nombre de vulnérabilités dont l'échéance est dépassée | Suivi des tickets | Hebdomadaire | Tech lead | Escalader au management et bloquer une mise en production si le chiffre n'est pas à zéro |
| Délai médian de correction | Temps médian entre la détection et la correction vérifiée | Dates de détection et de fermeture des tickets | Mensuelle | Responsable sécurité | Ajuster les échéances ou les ressources si le délai dépasse l'objectif |
| Pourcentage de corrections vérifiées | Part des corrections confirmées par une nouvelle analyse ou un test | Tickets + résultats de tests et d'analyses | Mensuelle | Tech lead | Refuser la clôture d'une anomalie sans preuve de vérification |
| Part des projets analysés | Projets analysés par SonarQube / projets du périmètre | Liste des projets SonarQube vs inventaire applicatif | Mensuelle | Responsable sécurité | Intégrer l'analyse aux projets qui ne sont pas encore couverts |

Le nombre total d'anomalies ne suffit pas à mesurer le niveau de sécurité. Sur TIWAP, il est resté à 30 avant et après ma correction, alors qu'une faille importante a bien été corrigée. À l'inverse, l'injection SQL n'était pas comptée du tout.

---

## 10. Conclusion sur les limites de l'analyse statique

SonarQube a trouvé de vrais problèmes sur TIWAP : une clé secrète en dur, un mode debug actif, une vérification JWT absente, des certificats non validés. Il n'a pourtant pas détecté l'injection SQL, qui est la vulnérabilité principale de l'application. Dans l'édition Community, l'analyse qui suit une donnée depuis l'entrée utilisateur jusqu'à la requête n'est pas disponible.

Un rapport SonarQube sans injection SQL ne veut donc pas dire qu'une application n'en contient pas. Les résultats dépendent de l'édition, des règles actives et de la manière dont le code est écrit. Il faut les compléter par une revue manuelle du code, des tests de non-régression et, si possible, des tests dynamiques.

L'analyse a aussi montré d'autres limites : la couverture affichée est de 0 % alors que des tests existent, parce qu'aucun rapport de couverture n'est fourni à SonarQube. Le nombre d'anomalies n'a pas bougé après une correction réelle. L'outil reste utile pour repérer rapidement de nombreux problèmes et suivre leur évolution, à condition de vérifier et qualifier chaque résultat.

---

## 11. Questions de compréhension

**1. Quel est le rôle de PostgreSQL dans cette architecture ?**
Il stocke les données de SonarQube : projets, résultats d'analyses, historique, utilisateurs et configuration. Grâce à son volume, ces données sont conservées même si le conteneur SonarQube est supprimé ou mis à jour.

**2. Pourquoi `localhost:9000` fonctionne depuis le navigateur mais n'est pas l'adresse à utiliser depuis le conteneur du scanner ?**
Dans le conteneur, `localhost` désigne le scanner lui-même. Il doit utiliser le nom du service `sonarqube`, résolu par le DNS du réseau Docker. Le navigateur passe par le port publié sur ma machine.

**3. Quelle différence entre une analyse statique et un test d'intrusion dynamique ?**
L'analyse statique lit le code sans l'exécuter : elle peut couvrir tout le code tôt dans le développement, mais elle manque des cas et produit des faux positifs. Le test dynamique attaque l'application en fonctionnement : il confirme qu'une faille est réellement exploitable, mais ne voit que les parties qu'il atteint.

**4. Pourquoi la concaténation d'une entrée utilisateur dans une requête SQL crée-t-elle un risque ?**
La saisie devient une partie du texte SQL. Avec des caractères comme l'apostrophe, l'utilisateur peut fermer la chaîne et ajouter sa propre logique, comme dans `' OR '1'='1`.

**5. En quoi une requête paramétrée réduit-elle ce risque ?**
La structure de la requête est fixée avec des marqueurs, et les valeurs sont transmises séparément au pilote. Elles sont toujours traitées comme des données, jamais comme du SQL.

**6. Pourquoi une validation de l'entrée ne remplace-t-elle pas les requêtes paramétrées ?**
Une validation ou un filtrage de caractères peut être contourné (encodages, cas oubliés) et dépend du contexte. Certaines valeurs légitimes contiennent aussi des apostrophes, comme un nom de famille. La validation est un complément utile, mais la séparation entre code SQL et données est la vraie protection.

**7. Pourquoi un résultat de SonarQube doit-il être vérifié et qualifié ?**
L'outil peut se tromper dans les deux sens : faux positifs (problème signalé mais pas exploitable) et faux négatifs (comme l'injection SQL ici). Il faut confirmer le résultat dans le code, évaluer son impact réel et décider de l'action.

**8. Que faire si aucune vulnérabilité SQL n'est signalée ?**
Ne pas conclure qu'il n'y en a pas. Faire une revue manuelle des requêtes et des entrées utilisateur, comme je l'ai fait avec `grep`, écrire des tests, envisager un outil avec analyse de flux ou un test dynamique, et documenter la limite.

**9. Comment prioriser une vulnérabilité affectant une application métier critique ?**
En tenant compte de la sensibilité des données, de l'exposition de l'application, de la facilité d'exploitation, des conséquences sur la confidentialité, l'intégrité et la disponibilité, et des protections déjà en place. La gravité affichée par l'outil aide, mais ne remplace pas cette évaluation métier.

**10. Pourquoi le nombre total d'anomalies n'est-il pas un indicateur suffisant ?**
Il mélange des problèmes de gravités très différentes et ne compte que ce que l'outil détecte. Sur TIWAP, il est resté à 30 après la correction d'une faille importante, et l'injection SQL n'y figurait pas.

**11. Quelles protections ajouter autour du scanner et de son jeton dans un pipeline CI/CD ?**
Stocker le jeton dans les secrets du pipeline (variables masquées et protégées), jamais dans le dépôt ni dans les logs. Utiliser un jeton limité au projet, avec une date d'expiration et une rotation régulière. Restreindre l'accès au serveur SonarQube et révoquer le jeton dès qu'il n'est plus utile.

**12. Comment prouver qu'une correction est effective et durable ?**
Effective : le code ne contient plus la construction vulnérable, et un test qui échouait sur l'ancien code réussit sur le nouveau. Durable : ce test est exécuté automatiquement à chaque modification (CI), et l'analyse est relancée régulièrement pour détecter une réintroduction.

---

## 12. Fichiers fournis

| Fichier | Contenu |
|---|---|
| `compose.yaml` | Déploiement SonarQube + PostgreSQL + scanner, sans secret |
| `sonar-project.properties` | Configuration de l'analyse |
| Capture de l'Overview | Projet TIWAP analysé dans SonarQube |
| `issues_securite_avant.txt` / `issues_securite_apres.txt` | Liste des 30 problèmes de sécurité avant et après correction |
| `correction_sqli.diff` | Code vulnérable et version corrigée |
| `test_sqli_low.py` | Test de non-régression |
| `preuve_tests_avant.txt` / `preuve_tests_apres.txt` | Exécution du test sur l'ancien et le nouveau code |
| `commits.txt` | Commits de la branche `fix/sql-injection-lab` |

Aucun jeton ni mot de passe ne figure dans ces fichiers. Le jeton d'analyse a été révoqué à la fin du laboratoire.
