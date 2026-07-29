# Prompt projet — WireGuard ACL Manager avec SSO Gateway

Copie-colle ce prompt dans Claude Code (ou un autre outil agentique) pour démarrer le projet. Adapte la stack si besoin, tout est modifiable.

---

## Contexte / objectif

Je veux construire un outil self-hosted de gestion d'accès réseau basé sur WireGuard, qui remplace les fonctionnalités "control plane + ACL + SSO" de solutions comme NetBird/Tailscale, mais en 100% open-source et sous mon contrôle total, sans dépendance à un service cloud tiers ni feature gating commercial.

Le principe :
1. Deux types de peers, avec des flows d'enrôlement et d'auth différents :
   - **Peers "serveur"** : machines/services qui n'ont pas d'utilisateur humain derrière (ex : un serveur backend, un service applicatif). Pas de login SSO/portail — l'authentification/autorisation repose uniquement sur une **clé de sécurité** (secret d'enrôlement long, généré côté admin, provisionné une seule fois au device). Une fois enrôlé avec sa clé, ce peer est rattaché directement à ses groupes et n'a pas de notion de "session" à expirer — pas de repassage en quarantaine automatique par timeout (sauf révocation manuelle de la clé par l'admin).
   - **Peers "user"** : devices utilisés par un humain (laptop, téléphone). Ceux-là passent par le flow quarantaine → portail de login (SSO/OIDC ou compte local) → attribution de groupes → expiration de session périodique, comme décrit ci-dessous.
2. Chaque device qui se connecte en WireGuard reçoit une IP tunnel fixe.
   - Pour un peer **user** : atterrit par défaut dans un état **quarantaine** (aucun accès réseau sauf au portail de login).
   - Pour un peer **serveur** : atterrit directement dans ses groupes assignés dès que la clé de sécurité fournie à l'enrôlement est valide — pas de quarantaine ni de portail.
3. Pour les peers user, l'utilisateur doit s'authentifier sur un portail web accessible uniquement depuis l'intérieur du tunnel, via **deux méthodes d'auth possibles** : SSO/OIDC (contre un IdP existant, ex Authentik ou Keycloak — je les self-host déjà) OU une authentification locale built-in (username/password stocké en DB, hashé). Le choix de la méthode doit être configurable par utilisateur ou globalement — pas de dépendance stricte à un IdP externe, l'outil doit rester utilisable même sans IdP configuré.
4. Une fois authentifié (ou enrôlé pour un serveur), le peer est rattaché à un ou plusieurs **groupes**, et des **policies ACL** définissent quel groupe peut parler à quel groupe/CIDR/port.
5. Le moteur génère un ruleset **nftables** à partir de ces policies, le valide (`nft -c -f`), puis l'applique de façon atomique sans couper les connexions existantes.
6. Pour les peers user uniquement : la session est réévaluée périodiquement — si l'utilisateur ne s'est pas ré-authentifié depuis N heures, le peer repasse en quarantaine automatiquement. Les peers serveur ne sont pas concernés par ce mécanisme (accès stable tant que la clé n'est pas révoquée).

## Stack technique souhaitée

Backend 100% Python (FastAPI) — pas de Rust/Tauri sur ce projet, contrairement à mes autres projets perso (PentestWS). Je veux garder une stack simple à maintenir seul.

- **Backend** : Python exclusivement (FastAPI) — API REST, logique métier, génération des règles nftables, agent gateway. Pas de Rust/Tauri sur ce projet, tout le backend et l'agent réseau restent en Python pour rester simple à maintenir/déployer.
- **Base de données** : PostgreSQL uniquement (pas de SQLite, même en dev — je veux rester sur un seul moteur du dev à la prod pour éviter les différences de comportement), accès via SQLAlchemy ou équivalent
- **Filtrage réseau** : nftables exclusivement (pas d'iptables/legacy) — ruleset généré et appliqué via `nft -f`, avec sets/maps nommés pour représenter les groupes de peers de façon performante
- **Frontend admin + portail captif** : Next.js + React + TypeScript + Tailwind CSS
- **Application réseau** : agent Python qui tourne sur la gateway WireGuard (box Linux dédiée), génère et applique le ruleset nftables
- **Communication backend ↔ agent gateway** : au choix — API REST interne avec auth par token, ou agent qui poll la DB directement si sur la même box. Propose la solution la plus simple et fiable, pas besoin de sur-ingénierie.

## Fonctionnalités attendues (par ordre de priorité)

### Phase 1 — Fondations
- Schéma DB avec les tables : `users`, `peers` (avec un champ `peer_type` = `server` ou `user`, un champ `enrollment_key_hash` + `enrollment_key_expires_at` optionnel pour les serveurs — clé en clair jamais stockée, montrée une seule fois à la génération), `groups`, `peer_groups` (many-to-many), `peer_tags` (tags libres many-to-many sur les peers, pour filtrage dans le dashboard sans impacter le modèle ACL), `acl_rules`, `audit_log`, `sessions` (avec `last_authenticated_at`, non pertinent pour les peers `server`)
- CRUD API pour users/peers/groups/policies, avec endpoint dédié de génération/révocation de clé d'enrôlement pour les peers serveur (avec date d'expiration optionnelle — utile pour un serveur temporaire type lab CTF, la clé devient invalide passé ce délai même sans révocation manuelle)
- Endpoint d'import/export des policies ACL (groupes + `acl_rules`) au format JSON — permet de versionner les ACL dans un repo git séparé et de les réappliquer après un rebuild de la gateway. L'import doit valider le JSON avant application (mêmes garanties d'atomicité que pour le ruleset nftables) et supporter un mode dry-run (diff affiché sans appliquer)
- Génération d'un ruleset nftables à partir des `acl_rules` (source group → dest group/CIDR, proto, port range, action, priority)
- Validation atomique (`nft -c -f` avant application réelle) et rollback si échec

### Phase 2 — Enrôlement serveurs + quarantaine/portail d'auth pour les users

**Peers serveur :**
- Endpoint admin pour générer une clé d'enrôlement (secret long, aléatoire, affiché une seule fois)
- Flow d'enrôlement : le device présente la clé au premier contact avec l'agent gateway, celui-ci vérifie le hash, crée/active le peer directement dans ses groupes assignés — pas de quarantaine, pas de portail
- Révocation : l'admin peut invalider une clé et/ou retirer le peer, ce qui doit régénérer immédiatement le ruleset

**Peers user :**
- État par défaut d'un nouveau peer user = quarantaine (accès uniquement au portail, DNS si nécessaire, tout le reste drop)
- Portail web de login accessible uniquement via le tunnel WireGuard, avec deux flows disponibles :
  - **OIDC** contre un IdP externe (Authentik/Keycloak, configuré via variables d'env, endpoint/client_id/secret non hardcodés)
  - **Auth locale** : username/password en DB, hash avec un algo robuste (argon2 ou bcrypt), pas de compte par défaut en clair
- Table `users` doit supporter les deux cas : soit un `external_idp_subject` (si compte lié à un IdP), soit un `password_hash` (si compte local), les deux pouvant coexister selon les comptes
- **Rate limiting sur le portail** : throttling par IP/peer sur les tentatives de login (ex : slowapi ou FastAPI-limiter), indispensable puisqu'un peer en quarantaine a déjà accès réseau au portail et pourrait le bruteforcer sans ce garde-fou
- **MFA optionnelle pour l'auth locale** : TOTP (via pyotp) activable par utilisateur, pour ne pas dépendre uniquement d'un mot de passe sur les comptes sans IdP externe. Non requis pour les comptes OIDC (le MFA est alors géré côté IdP)
- Binding peer ↔ user fait à l'enregistrement du device (pas de binding dynamique par IP à chaque requête, pour éviter la fragilité)
- Après login réussi (peu importe la méthode) : mise à jour de `last_authenticated_at`, le peer est rattaché à ses groupes, régénération + application du ruleset

### Phase 3 — Expiration de session et ré-évaluation (peers user uniquement)
- Job périodique (cron ou scheduler intégré) qui vérifie la fraîcheur de `last_authenticated_at` par peer **user**
- Si expiré : le peer repasse en quarantaine automatiquement, régénération du ruleset
- Durée de session configurable par groupe (ex : `pentest-lab` expire après 4h, `admin` après 24h)
- Les peers **serveur** sont explicitement exclus de ce mécanisme — leur accès reste stable tant que leur clé d'enrôlement n'est pas révoquée manuellement

### Phase 4 — Dashboard admin
- Vue d'ensemble des peers connectés, leur statut (quarantaine / actif), dernier login, tags associés
- Filtrage/recherche des peers par tags dans le dashboard
- Gestion visuelle des groupes et de la matrice de policies (qui peut parler à qui)
- Interface d'import/export JSON des policies (upload, preview du diff en dry-run, confirmation avant application)
- **Kill switch admin** : action globale qui repasse immédiatement *tous* les peers en quarantaine (y compris les peers serveur, en exception à leur comportement normal), indépendamment de leur session — pour réagir vite en cas de compromission suspectée. Doit être clairement isolé dans l'UI (confirmation explicite, pas un bouton accessible par erreur) et tracé dans l'audit log
- Logs d'audit (qui a modifié quoi, qui s'est connecté quand, qui a déclenché le kill switch)

### Phase 5 — Roadmap future (pas prioritaire, à garder en tête pour l'architecture)

Ne pas implémenter maintenant, mais concevoir Phase 1-4 pour ne pas bloquer ces évolutions plus tard :
- **Routing par zones custom** : au-delà des groupes plats, un système de zones réseau (à la NetBird) où chaque zone a ses propres routes/exit nodes, et les policies ACL peuvent s'appliquer zone-à-zone en plus de groupe-à-groupe
- **Reverse proxy intégré** : un reverse proxy (Traefik/Caddy) devant les services web internes, avec la SSO gérée au niveau du proxy pour les services HTTP (en complément du portail captif niveau réseau, pas en remplacement)
- **Protection CrowdSec** : bouncer CrowdSec sur la gateway pour bannir dynamiquement les IPs qui scannent/bruteforcent le portail de login ou les endpoints exposés, en complément des ACL statiques

Le schéma DB (Phase 1) doit rester extensible pour ces cas : par exemple prévoir que `groups` puisse évoluer vers une notion de `zones` sans tout casser, et que les `acl_rules` ne soient pas trop couplées à une hypothèse "un seul reverse proxy" ou "pas de bouncer externe".

## Contraintes techniques importantes

- **Jamais stocker de clé privée WireGuard côté serveur** — seules les clés publiques des peers sont connues du backend
- **Application atomique des règles réseau** — ne jamais appliquer un ruleset non validé, risque de couper l'accès à distance à la gateway elle-même
- **Reload sans coupure des connexions existantes** — privilégier `wg syncconf` pour les changements de peers WireGuard, et un reload nftables qui ne droppe pas les connexions déjà `ESTABLISHED` des autres peers
- **Pas de MITM TLS** — pas d'interception transparente du trafic HTTPS pour rediriger vers le portail ; la quarantaine bloque tout sauf le portail, l'utilisateur doit s'y rendre explicitement (comme un vrai captive portal propre, pas un hack DNS/TLS fragile)
- **Idempotence** — regénérer le ruleset complet à partir de l'état DB doit toujours donner un résultat cohérent, pas de drift entre DB et règles appliquées

## Ce que je veux comme livrable de ta part

1. Propose une structure de repo (monorepo ou multi-repo, à toi de juger) avec les dossiers pour backend/frontend/agent
2. Commence par la Phase 1 : schéma DB + migrations, API CRUD de base, et le générateur de règles nftables avec ses tests
3. Écris des tests pour le générateur nftables en particulier (c'est la partie la plus sensible : un bug ici peut couper l'accès à ma gateway)
4. Documente dans un README comment lancer le projet en local (dev) et comment le déployer sur une gateway Linux réelle
5. Pose-moi des questions si un point d'architecture n'est pas clair avant de te lancer dans du code, plutôt que de deviner

## Mon environnement

- Homelab Proxmox avec OPNsense en routeur principal
- Une box Linux dédiée peut servir de gateway WireGuard si besoin (LXC ou VM séparée)
- J'ai déjà NetBird self-hosté (peut servir de référence mais l'objectif est de m'en affranchir à terme sur ce use case précis)
- IdP disponible : Authentik ou Keycloak (à choisir/configurer)
- Stack habituelle (autres projets) : Python, Rust/Tauri, Next.js/React, Docker/LXC sur Proxmox — mais pour ce projet précis, backend 100% Python, pas de Rust/Tauri