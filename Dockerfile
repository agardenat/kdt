# Les images sont pleinement qualifiées : un nom court dépend du registre configuré sur la
# machine qui construit, ce qui est à la fois non reproductible et une porte ouverte au
# typosquattage.
#
# Image de kdt-web : le serveur et le bundle du front, dans une image sans rien d'autre.
#
# kdt-web ne détient aucun accès au cluster qui lui soit propre — chaque requête part avec le
# credential de la personne connectée. Ce qu'il détient, ce sont ces credentials : un shell dans
# le conteneur suffirait à lire la mémoire du processus, et il n'y en a pas.

FROM docker.io/library/node:22-alpine AS front

WORKDIR /src/web

# Le manifeste seul d'abord : tant qu'il ne change pas, `npm ci` n'est pas rejoué à chaque
# modification d'un composant.
COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
# `npm run build` passe par `tsc --noEmit` : une erreur de typage arrête l'image ici plutôt que
# de produire un bundle qu'on découvrirait cassé dans le navigateur.
RUN npm run build

FROM docker.io/library/rust:1.95-alpine AS build

# `git` n'est pas dans l'image : `kdt-identity-api` est une dépendance git, et cargo la récupère
# lui-même au premier build.
RUN apk add --no-cache musl-dev git

WORKDIR /src

# Les manifestes seuls d'abord, avec des souches à la place des sources : tant que les
# dépendances ne changent pas, leur couche est réutilisée et la compilation ne repart pas de
# zéro. kdt en tire plus de six cents crates, c'est la couche qui compte.
COPY Cargo.toml Cargo.lock ./
COPY crates/web/Cargo.toml crates/web/
RUN mkdir -p src crates/web/src \
    && echo 'fn main() {}' > src/main.rs \
    && echo 'fn main() {}' > crates/web/src/main.rs \
    && touch src/lib.rs \
    && cargo build --release --locked -p kdt-web \
    && rm -rf src crates/web/src

COPY src src
COPY crates crates
# Sans ce `touch`, cargo garde les artefacts des souches ci-dessus : leurs horodatages sont
# plus récents que ceux des sources qu'on vient de copier.
RUN find src crates -name '*.rs' -exec touch {} + \
    && cargo build --release --locked -p kdt-web

FROM scratch

# Rattache l'image à son dépôt. GitHub lit ce label au push pour lier le package au dépôt : la
# page du package y gagne le README et le lien vers les sources, et les droits d'accès suivent
# ceux du dépôt. Sans lui, le package reste un objet isolé dont la visibilité se règle à la main.
LABEL org.opencontainers.image.source=https://github.com/agardenat/kdt
LABEL org.opencontainers.image.licenses=Apache-2.0
LABEL org.opencontainers.image.description="Interface web de kdt, adossée à kdt-identity"

# Le portail est joint en https, avec un certificat qu'un tiers a émis : sans racines, kdt-web
# ne pourrait échanger aucun code d'autorisation. La CA de l'apiserver, elle, vient du compte
# de service.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /src/target/release/kdt-web /usr/local/bin/
COPY --from=front /src/web/dist /usr/local/share/kdt-web

# Le bundle est là : le servir est le cas nominal de l'image, et une variable oubliée dans le
# chart donnerait un serveur qui ne rend que son API, sans que rien ne le dise au navigateur.
ENV KDT_WEB_ASSETS=/usr/local/share/kdt-web

# Correspond au `runAsUser` du chart. Déclaré ici aussi pour que l'image ne tourne pas en root
# même lancée sans contexte de sécurité.
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/kdt-web"]
