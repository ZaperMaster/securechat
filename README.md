# SecureChat

Mensajería 1 a 1 con cifrado extremo a extremo (E2E) sobre
[libsodium](https://doc.libsodium.org/). Tiene dos clientes que se entienden entre sí:

- **Web / app instalable (PWA)**: el cifrado ocurre en el navegador con libsodium.js.
- **Terminal**: Python con PyNaCl.

El servidor solo reenvía bytes cifrados: nunca ve el texto ni tiene claves para descifrarlo.

Esta versión está pensada para **uso local**: el servidor escucha solo en tu equipo
(o en tu red Wi-Fi con `--lan`) y pide un **código de acceso** que genera al
arrancar. Quien monta el servidor se lo da a sus amigos; sin él no se puede entrar.

> ⚠️ **Proyecto educativo. No está auditado.** No lo uses para información sensible
> real. Si necesitas mensajería segura de verdad, usa [Signal](https://signal.org).

## Capturas

![Chat en el ordenador, con la vista previa de un enlace](docs/img/chat-ordenador.jpg)

| Pantalla de acceso | En el móvil | Opciones |
|---|---|---|
| <img src="docs/img/acceso.jpg" alt="Pantalla de acceso con ilustración" width="420"> | <img src="docs/img/chat-movil.jpg" alt="Chat en el móvil" width="200"> | <img src="docs/img/opciones-movil.jpg" alt="Opciones en el móvil" width="200"> |

## Cómo viaja un mensaje

```mermaid
sequenceDiagram
    autonumber
    participant A as Móvil de Lucía
    participant S as Servidor (relay)
    participant B as Móvil de Marco
    Note over A,B: Cada uno tiene su identidad Ed25519, que nunca sale del dispositivo sin cifrar
    A->>S: hello + firma del reto (demuestra que es @lucia)
    B->>S: publica sus prekeys firmadas (SPK + OPK de un solo uso)
    A->>S: ¿prekeys de @marco?
    S-->>A: SPK firmada + una OPK (y la borra)
    Note over A: X3DH → clave compartida<br/>Double Ratchet → clave nueva por mensaje<br/>Relleno a un tamaño fijo y XChaCha20-Poly1305
    A->>S: sobre cifrado (para cada dispositivo de Marco)
    Note over S: Solo ve bytes, el remitente y el destinatario.<br/>Si Marco no está, lo guarda en su cola.
    S->>B: sobre cifrado
    Note over B: Descifra, comprueba la clave fijada (TOFU)<br/>y valida el contenido antes de enseñarlo
    B-->>A: ✓✓ entregado / leído (también cifrado)
```

Lo que el servidor **no** ve: el texto, las fotos, el tipo de mensaje (va dentro del
cifrado), los grupos (cada copia va por separado), los perfiles ni las llamadas (los
datos de audio y vídeo van cifrados de punto a punto con DTLS-SRTP; el relé TURN solo
pasa paquetes).

## Qué hace

- **Identidad Ed25519** por usuario, guardada en disco cifrada con una contraseña
  (Argon2id + XSalsa20-Poly1305).
- **Servidor relay** con autenticación por reto firmado: nadie puede conectarse con
  tu nombre sin tu clave privada.
- **X3DH + Double Ratchet** (el diseño de Signal): cada mensaje usa una clave nueva
  y la sesión se "cura" sola tras un compromiso. Funciona igual esté el otro
  conectado o no, gracias a las *signed prekeys* y las *one-time prekeys*.
- **Varios dispositivos por cuenta** (móvil y ordenador a la vez): cada mensaje se
  cifra para cada dispositivo, y lo que envías desde uno aparece en los demás.
- **Fotos, GIF, vídeos, stickers y emojis**, cifrados igual que el texto. El tipo
  de contenido también va dentro del cifrado: el servidor no sabe si es una foto.
- **Perfil cifrado**: nombre visible y foto que solo ven tus contactos. Al
  recortarla a 256 px se eliminan los metadatos EXIF (por ejemplo la ubicación GPS).
- **@usuario único** con mayúsculas, números, `.`, `-` y `_`. La unicidad no
  distingue mayúsculas, así que `Alice` y `alice` no pueden ser dos personas distintas.
  Al abrir un chat se comprueba que el usuario existe.
- **TOFU** (*trust on first use*): la primera clave vista de un contacto queda
  fijada; si cambia, el cliente muestra un aviso y rechaza la sesión.
- **Números de seguridad** (60 dígitos) en *Perfil → Seguridad avanzada*, para quien
  quiera descartar del todo que el propio servidor suplante a un contacto.
- **Mensajes en diferido**: puedes escribir a alguien desconectado; el servidor
  guarda el mensaje cifrado y se lo entrega a cada dispositivo al conectarse.
- **Grupos**: el servidor no sabe que existen. Cada mensaje del grupo se cifra por
  separado para cada miembro (como hacía Signal al principio).
- **Responder, reaccionar, editar y borrar** (mantener pulsado o clic derecho en un
  mensaje), **notas de voz**, **"escribiendo…"** y **"última vez"** (ocultables).
- **Notificaciones con la app cerrada** (Web Push): el aviso no lleva el contenido
  ni el remitente, solo "tienes un mensaje nuevo".
- **Copia de seguridad cifrada** del historial, ajustes de los chats y mensajes
  programados (*Opciones → Copia de seguridad*), que solo tu cuenta puede abrir. Puedes
  hacerla con o sin fotos; la app te recuerda hacerla si pasa más de un mes.
- **Reintentar envíos**: si un mensaje no se puede enviar, se marca en rojo con
  *No se pudo enviar · Reintentar* (también desde el menú del mensaje).
- **Bloqueo de la app** opcional con PIN y, si el dispositivo lo permite, huella, cara
  o Windows Hello (WebAuthn). Se activa en *Opciones → Privacidad*; el PIN se guarda
  solo como hash Argon2id y tras 5 fallos hay que esperar.
- **Notificaciones agrupadas por chat** («3 mensajes nuevos») con botones para
  *Responder* desde la propia notificación y *Marcar como leído*.
- **Vista previa de enlaces** (título, descripción e imagen). La genera el servidor al
  ENVIAR y viaja cifrada dentro del mensaje, así quien lo recibe no visita la web. El
  servidor se protege contra SSRF: solo IP públicas, puertos 80/443, sin re-resolver el
  nombre (DNS rebinding), redirecciones comprobadas y tamaño limitado. Se puede quitar.
- **Pegar con Ctrl+V y arrastrar archivos** al chat abierto o encima de un chat de la
  lista, con una vista previa antes de enviar.
- **Borrar la cuenta** (*Opciones → Borrar mi cuenta*): pide tu contraseña y escribir
  BORRAR, firma la petición con tu clave y el servidor borra claves, copia cifrada, correo
  y mensajes en espera. El @usuario queda libre.
- **Checks como WhatsApp**: 🕓 enviando, ✓ enviado, ✓✓ entregado y ✓✓ azul leído.
  Las confirmaciones viajan cifradas y las de lectura se pueden desactivar.
- **Bandeja de salida**: si te quedas sin conexión (por ejemplo, el móvil corta la
  conexión al pasar la app a segundo plano), los mensajes esperan con 🕓 y salen
  solos al reconectar. La app se reconecta en cuanto vuelves a ella.
- **Sesión recordada e historial**: entras una vez y el dispositivo te recuerda. El
  historial (también fotos y vídeos) se guarda cifrado en el dispositivo.
- **Iniciar sesión desde cualquier dispositivo**: pantallas separadas de "Iniciar
  sesión" y "Crear cuenta". El servidor guarda una copia de tu clave **cifrada con tu
  contraseña** (Argon2id), así que basta con usuario y contraseña en otro equipo.
- **Verificación por correo** opcional al crear cuenta, para frenar bots.
- **Personalización**: 9 temas, color propio, fondos de chat (o tu foto), tamaño de
  letra, forma de las burbujas, estado en el perfil y apodos para tus contactos.
- **Presencia**: ves si tu contacto está en línea o su "última vez".
- **Servicio caído**: si el servidor está apagado, la app lo dice ("quien lo gestiona
  tiene que ponerlo en marcha") y se reconecta sola cuando vuelve.
- Protección contra **repetición, reordenación, manipulación** y claves de orden bajo.

## Uso rápido

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows  (Linux/macOS: source .venv/bin/activate)
pip install -r requirements-dev.txt
```

Arranca el servidor (sirve la web y el relay en el mismo puerto):

```bash
python -m securechat.server
```

Al arrancar muestra la dirección y el **código de acceso** (por ejemplo `K7P2-9QXM`).
Opciones útiles:

- `--lan`: acepta conexiones de otros dispositivos de tu Wi-Fi (muestra tu IP local).
- `--code MI-CODIGO`: usa un código fijo en vez de uno nuevo en cada arranque.
- `--no-code`: sin código (solo para pruebas en tu equipo).
- `--email`: pide verificar un correo al crear cuenta. Necesita un servidor SMTP en
  las variables `SECURECHAT_SMTP_HOST`, `SECURECHAT_SMTP_USER`,
  `SECURECHAT_SMTP_PASSWORD` (y opcionalmente `_PORT` y `_FROM`). Con Gmail, usa una
  *contraseña de aplicación*.
- `--email-pruebas`: igual, pero el código se muestra en la consola del servidor.

Los datos del servidor (usuarios y mensajes en espera, siempre cifrados) se guardan
en `server_users.json` y `server_queue/`.

### Web

Abre <http://localhost:8765> en dos pestañas o navegadores y crea una cuenta en
cada una (por ejemplo `Alice` y `bob`) con el código de acceso del servidor. Escribe el @usuario del otro en "Nuevo chat":
si no existe te lo dice y no se crea el chat. Pulsa sobre tu nombre para poner
tu nombre visible y tu foto.

- 😊 abre emojis y stickers; 📎 envía fotos, GIF o vídeos (máx. 8 MB). También
  puedes pegar una imagen o arrastrarla al chat.
- La clave privada se genera en el navegador y se guarda en `localStorage`, cifrada
  con tu contraseña (Argon2id). En *Mi perfil → Seguridad avanzada* puedes exportarla
  como `identity.json`, compatible con la versión de terminal.
- El historial se guarda cifrado en el dispositivo (IndexedDB).
- En Chrome/Edge aparece **Instalar app** (o el icono de instalar en la barra de
  direcciones) y se abre en su propia ventana, como una app.

### En el móvil (misma red Wi-Fi)

Los navegadores solo permiten instalar apps y usar algunas APIs en **HTTPS** (salvo
en `localhost`), así que para el móvil genera un certificado propio:

```bash
mkdir certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 -subj "/CN=securechat-local" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:192.168.1.19" -keyout certs/key.pem -out certs/cert.pem
```

(cambia `192.168.1.19` por la IP de tu PC: `ipconfig` en Windows). Luego:

```bash
python -m securechat.server --lan --cert certs/cert.pem --key certs/key.pem
```

Abre `https://192.168.1.19:8765` en el móvil, acepta el aviso del certificado
autofirmado y usa *Añadir a pantalla de inicio*. Puede que Windows pida permitir
Python en el firewall. Un certificado autofirmado es aceptable para pruebas en tu
red; no lo es para un despliegue real.

### Terminal

Dos usuarios en dos terminales (pueden hablar también con usuarios de la web).
Añade `--code` con el código del servidor a `chat`:

```bash
python -m securechat init --name alice
python -m securechat chat --name alice --code K7P2-9QXM
```

```bash
python -m securechat init --name bob
python -m securechat chat --name bob --code K7P2-9QXM
```

Dentro del chat de Alice:

```
> /open bob
> hola Bob
> /fp bob          # muestra el número de seguridad; Bob ejecuta /fp alice
> /verify bob      # solo si ambos números coinciden
```

Tests (los de interoperabilidad web ↔ Python necesitan Node.js; si no está, se saltan):

```bash
pytest -q                          # todo, incluidas las pruebas de la web
node --test tests/web/*.test.mjs   # solo las del cliente web
```

## Arquitectura

```
securechat/
  crypto.py        almacén de claves, KDF, huellas y números de seguridad
  ratchet.py       X3DH + Double Ratchet por dispositivo (sin E/S, fácil de testear)
  content.py       formato del contenido cifrado (texto, foto, audio, reacciones, grupos…)
  contacts.py      claves fijadas (TOFU) y estado de verificación
  email_verify.py  verificación por correo (SMTP o consola)
  push.py          notificaciones con la app cerrada (Web Push con VAPID)
  server.py        relay WebSocket por dispositivo + servidor de la web estática
  client.py        lógica de red del cliente, independiente de la interfaz
  cli.py           interfaz de terminal
web/
  js/protocol.js   identidad, KDF y huellas (mismos bytes que crypto.py)
  js/ratchet.js    port de ratchet.py (mismos bytes)
  js/client.js     port de client.py
  js/app.js        interfaz (solo usa textContent: nunca interpreta HTML recibido)
  js/vault.js      sesión recordada (WebCrypto) e historial cifrado (IndexedDB)
  js/emoji.js      emojis y stickers
  sw.js, manifest.webmanifest   PWA instalable y notificaciones
  vendor/          libsodium.js 0.7.15 (copiado, sin CDN)
tests/
  test_ratchet.py      el protocolo, incluido un fuzz de 200 mensajes desordenados
  test_web_interop.py  ejecuta el JS en Node y conversa con Python mensaje a mensaje
  test_preview.py      vista previa de enlaces y protección contra SSRF
  test_web_client.py   lanza las pruebas del cliente web (tests/web/*.test.mjs) con Node
  web/                 pruebas del JS de la web: relleno, validación del contenido,
                       identidad, firmas y números de seguridad
```

`ratchet.py` no hace E/S: toda la criptografía de la conversación se prueba sin red.
La versión JS se valida contra la Python en los tests: misma derivación de claves,
mismo número de seguridad, mismo formato de `identity.json` y conversación real.

## Protocolo

Mensajes JSON sobre WebSocket. `IK` es la identidad Ed25519 de la cuenta (convertida
a X25519 para los DH), `|` concatenación con longitud prefijada.

**Autenticación con el servidor**

```
C -> S  hello { user, IK, device }
S -> C  challenge { nonce (32 bytes aleatorios) }
C -> S  auth { Sig_C("securechat-auth-v1" | nonce | user) }
```

El servidor fija `user -> IK` la primera vez y rechaza después cualquier otra clave.
Cada cuenta puede tener hasta 6 dispositivos; todos comparten `IK` (se recupera con
la copia cifrada con tu contraseña) pero cada uno tiene sus propias prekeys.

**Prekeys de cada dispositivo**

```
SPK  = X25519 firmada: Sig_IK("spk" | user | device | SPK | fecha)   (se renueva cada 7 días)
OPK  = 20 X25519 de un solo uso; el servidor entrega una por petición y la borra
```

**X3DH** (para escribir a un dispositivo por primera vez, aunque esté desconectado)

```
DH1 = DH(IK_A, SPK_B)   DH2 = DH(EK_A, IK_B)   DH3 = DH(EK_A, SPK_B)   DH4 = DH(EK_A, OPK_B)
AD  = A | dispositivo_A | B | dispositivo_B | IK_A | IK_B
SK  = KDF(BLAKE2b(DH1 | DH2 | DH3 | DH4), "sc-x3dh", AD)
```

**Double Ratchet** (el algoritmo de Signal, tal cual)

```
(RK, CK)  = KDF(RK, DH(DHs, DHr))      al cambiar el turno de quién escribe
(CK, MK)  = (KDF(CK, "sc-ck"), KDF(CK, "sc-mk"))   en cada mensaje
ct = XChaCha20-Poly1305(MK, nonce, aad = AD | DHs | PN | N)
```

Se guardan hasta 2000 claves de mensajes saltados (llegan desordenados) y se borran
al usarse. Si los dos empiezan a escribirse a la vez, cada dispositivo guarda las
últimas sesiones y "asciende" la que funciona, como hace Signal. El estado de cada
sesión se guarda en el dispositivo cifrado con una clave derivada de la identidad.

**Varios dispositivos**: cada mensaje se cifra una vez por cada dispositivo del
destinatario y otra por cada uno de mis otros dispositivos (envuelto como `sync`). El
servidor entrega a cada dispositivo o lo guarda en su cola si está desconectado.

## Modelo de amenazas

**Atacante considerado:** controla la red y/o el servidor relay. Puede leer, borrar,
reordenar, repetir e inyectar mensajes, y registrar usuarios falsos.

| Protegido | Cómo |
|---|---|
| Confidencialidad del contenido | AEAD con claves que solo conocen los dispositivos de los dos |
| Integridad y autenticidad | Poly1305 + X3DH con las identidades de ambos |
| Suplantación de remitente | el remitente lo fija el servidor tras el reto firmado, y X3DH lo liga a su `IK` |
| Repetición / reordenación | claves de un solo uso (ratchet y OPK); se borran al usarse |
| MITM en el primer contacto | **solo si** se comparan los números de seguridad |
| MITM tras el primer contacto | claves fijadas (TOFU): un cambio dispara una alerta |
| Robo posterior de la clave de identidad | secreto hacia adelante (claves efímeras y OPK) |
| Robo del estado de una sesión | "curación": el siguiente DH del ratchet lo deja inservible |
| Robo del fichero de claves | cifrado con Argon2id; depende de la fuerza de la contraseña |

**No protegido** (limitaciones conocidas):

- **Metadatos**: el servidor sabe quién habla con quién, cuándo y cuánto ocupa cada
  mensaje. Usa TLS (`wss://`) delante del relay para ocultarlos al menos a la red.
- **Primer contacto sin verificar**: si el servidor es malicioso desde el principio
  y nunca comparáis los números de seguridad, puede hacer de intermediario.
  Escribir bien el @usuario no basta: quien controla el servidor decide a quién
  entrega tus mensajes. Por eso la verificación existe, aunque esté escondida en
  *Seguridad avanzada* para no estorbar en el día a día (igual que en Signal o WhatsApp).
- **Existencia de usuarios**: cualquiera puede preguntar si un @usuario existe y
  si está conectado. Se limita a 30 búsquedas por minuto para frenar la enumeración.
- **Tamaño de los mensajes**: los mensajes se rellenan a tamaños fijos (256 B, 1 KB,
  4 KB, 16 KB, 64 KB y luego múltiplos de 64 KB), pero un envío de 3 MB sigue delatando
  que es una foto o un vídeo.
- **Vista previa de enlaces**: el servidor ve la dirección que compartes (no a quién).
  Si no quieres, desactívala en *Opciones → Privacidad*.
- **Bloqueo con PIN**: es una pantalla de privacidad frente a quien coja tu móvil
  desbloqueado, no cifrado extra: un PIN de 4 cifras se puede adivinar con acceso a los
  ficheros del navegador.
- **Búsqueda de GIF**: no hay buscador tipo Giphy/Tenor porque enviaría lo que
  buscas a un tercero. Los GIF se envían desde tu dispositivo.
- **Disponibilidad**: el servidor puede descartar mensajes o desconectar usuarios.
- **Dispositivo comprometido**: con malware en tu equipo no hay cifrado que valga.
  Python además no permite borrar claves de memoria de forma fiable.
- **Sesión recordada**: la semilla de tu identidad queda cifrada con una clave
  WebCrypto no exportable. Nadie puede copiarla a otro equipo, pero quien use tu
  navegador sí podría abrir la app. "Cerrar sesión" la borra del dispositivo.
- **Copia de la clave en el servidor**: está cifrada con tu contraseña y el servidor
  no puede abrirla, pero quien la descargue podría intentar adivinar la contraseña sin
  conexión. Por eso la descarga está limitada (10 por minuto e IP), exige el código de
  acceso si lo hay, y Argon2id hace cada intento lento. Usa una contraseña larga.
- **Historial local**: va cifrado con una clave derivada de tu identidad. Protege
  frente a quien copie los ficheros del navegador sin tu sesión, no frente a malware.
- **Correo**: el servidor lo ve al crear la cuenta para enviarte el código, pero solo
  guarda una huella (HMAC con un secreto propio) para impedir cuentas repetidas.
- **Confirmaciones de entrega y lectura**: van cifradas, pero su tamaño y momento
  revelan al servidor que hubo actividad. Las de lectura se pueden desactivar.
- **Presencia**: el servidor sabe cuándo te conectas y se lo dice a quien ha hablado contigo.
- **Código de acceso**: unos 40 bits, con un máximo de 10 intentos fallidos por IP y
  minuto. Es un filtro para que no entre cualquiera, no una medida de cifrado.
- **Código servido por el propio servidor (web)**: en la versión web, el servidor
  entrega el JavaScript que cifra. Un servidor malicioso podría servir código
  modificado que filtre tus claves. Es el problema clásico del E2E en navegador;
  la versión de terminal no lo tiene. Mitigaciones reales: app empaquetada y
  firmada, o extensiones que verifican el código (como Meta Code Verify).
- **`localStorage`**: la clave va cifrada, pero cualquier script inyectado en el
  origen podría leerla mientras la sesión está abierta. La CSP estricta y el uso
  exclusivo de `textContent` reducen ese riesgo.
- **Sin one-time prekeys disponibles**: si a alguien se le acaban (por ejemplo, porque
  un atacante las pide todas), el primer mensaje usa solo la SPK y su secreto hacia
  adelante depende de que la SPK se renueve (7 días), como en Signal.
- **Grupos**: el tamaño del envío crece con el número de miembros y el servidor ve a
  quién va cada copia. Signal usa *sender keys* para grupos grandes.
- **Varios dispositivos**: comparten la identidad de la cuenta; un dispositivo robado
  y con la sesión abierta puede leer los mensajes nuevos hasta que lo desvincules desde
  otro (*Mi perfil → Seguridad avanzada → Tus dispositivos*).
- **Notificaciones**: el servicio de avisos del navegador (Google, Mozilla o Apple) sabe
  cuándo te llega algo, aunque no el qué ni de quién.

## Hoja de ruta

- [x] Fase 1 – Chat 1 a 1 por CLI con relay ciego y claves protegidas con contraseña
- [x] Fase 2 – Huellas, números de seguridad y contactos verificados
- [x] Fase 3 – Claves efímeras por sesión (secreto hacia adelante)
- [x] Fase 4 – Interfaz web instalable (PWA), temas, perfiles y multimedia cifrada
- [x] Fase 5 – Mensajes en diferido, checks, bandeja de salida, historial cifrado, correo
- [x] Fase 6 – X3DH + Double Ratchet con one-time prekeys, varios dispositivos, grupos,
  respuestas/reacciones/ediciones, notas de voz, notificaciones push y copia de seguridad
- [x] Fase 7 – *Padding* de mensajes, llamadas WebRTC con relé TURN propio, bloqueo de la
  app, vista previa de enlaces segura y borrado de cuenta
- [ ] Siguiente – *Sender keys* para grupos grandes

## Referencias

- [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/) – Signal
- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/) – Signal
- [The Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- H. Krawczyk, [SIGMA: the "SIGn-and-MAc" approach to authenticated Diffie-Hellman](https://www.iacr.org/cryptodb/archive/2003/CRYPTO/1495/1495.pdf) (CRYPTO 2003)
- [Documentación de libsodium](https://doc.libsodium.org/)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) (X25519), [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) (Ed25519), [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) (Argon2)
