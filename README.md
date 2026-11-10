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

## Qué hace

- **Identidad Ed25519** por usuario, guardada en disco cifrada con una contraseña
  (Argon2id + XSalsa20-Poly1305).
- **Servidor relay** con autenticación por reto firmado: nadie puede conectarse con
  tu nombre sin tu clave privada.
- **Handshake autenticado** con claves efímeras X25519 firmadas por ambas partes.
- **Cifrado autenticado** XChaCha20-Poly1305 con una clave distinta por mensaje
  (ratchet simétrico con BLAKE2b).
- **Secreto perfecto hacia adelante**: las claves efímeras solo viven en memoria;
  robar tu clave de identidad no descifra conversaciones pasadas.
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
- **Mensajes en diferido**: puedes escribir a alguien desconectado. El mensaje se
  cifra con su *prekey* firmada (al estilo X3DH de Signal) y el servidor lo guarda
  cifrado hasta que se conecta.
- **Checks como WhatsApp**: 🕓 enviando, ✓ enviado, ✓✓ entregado y ✓✓ azul leído.
  Las confirmaciones viajan cifradas y las de lectura se pueden desactivar.
- **Bandeja de salida**: si te quedas sin conexión (por ejemplo, el móvil corta la
  conexión al pasar la app a segundo plano), los mensajes esperan con 🕓 y salen
  solos al reconectar. La app se reconecta en cuanto vuelves a ella.
- **Sesión recordada e historial**: entras una vez y el dispositivo te recuerda. El
  historial (también fotos y vídeos) se guarda cifrado en el dispositivo.
- **Verificación por correo** opcional al crear cuenta, para frenar bots.
- **Personalización**: 9 temas, color propio, fondos de chat (o tu foto), tamaño de
  letra, forma de las burbujas, estado en el perfil y apodos para tus contactos.
- **Presencia**: ves si tu contacto está en línea, y la sesión se renueva sola
  cuando alguien recarga la página.
- **Servicio caído**: si el servidor está apagado, la app lo dice ("quien lo gestiona
  tiene que ponerlo en marcha") y se reconecta sola cuando vuelve.
- Protección contra **repetición, reflexión, manipulación** y claves de orden bajo.

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
- Los mensajes solo existen mientras la pestaña está abierta: no se guarda historial.
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
pytest -q
```

## Arquitectura

```
securechat/
  crypto.py    almacén de claves, KDF, huellas y números de seguridad
  sealed.py    mensajes en diferido: prekeys firmadas y sobres sellados
  email_verify.py  verificación por correo (SMTP o consola)
  content.py   formato del contenido cifrado (texto, foto, vídeo, sticker, perfil)
  session.py   handshake + cifrado de mensajes (sin E/S, fácil de testear)
  contacts.py  claves fijadas (TOFU) y estado de verificación
  server.py    relay WebSocket + servidor de la web estática
  client.py    lógica de red del cliente, independiente de la interfaz
  cli.py       interfaz de terminal
web/
  js/protocol.js  port de crypto.py + session.py (mismos bytes)
  js/client.js    port de client.py
  js/app.js       interfaz (solo usa textContent: nunca interpreta HTML recibido)
  js/emoji.js     emojis y stickers
  js/vault.js     sesión recordada (WebCrypto) e historial cifrado (IndexedDB)
  sw.js, manifest.webmanifest   PWA instalable
  vendor/         libsodium.js 0.7.15 (copiado, sin CDN)
tests/
  test_web_interop.py  ejecuta el JS en Node y chatea con el cliente Python
```

`session.py` no hace E/S: toda la criptografía de la conversación se prueba sin red.
La versión JS se valida contra la Python en los tests: misma derivación de claves,
mismo número de seguridad, mismo formato de `identity.json` y chat real entre ambas.

## Protocolo

Mensajes JSON sobre WebSocket. Notación: `A` iniciador, `B` respondedor, `id` clave
de identidad Ed25519, `eph` clave efímera X25519, `|` concatenación con longitud prefijada.

**Autenticación con el servidor**

```
C -> S  hello { user, id }
S -> C  challenge { nonce (32 bytes aleatorios) }
C -> S  auth { Sig_C("securechat-auth-v1" | nonce | user) }
```

El servidor fija `user -> id` la primera vez y rechaza después cualquier otra clave.

**Handshake** (inspirado en SIGMA y en el patrón XX de Noise)

```
A -> B  hs1 { idA, ephA, Sig_A("hs1" | A | B | idA | ephA) }
B -> A  hs2 { idB, ephB, Sig_B("hs2" | A | B | idA | idB | ephA | ephB) }

th   = BLAKE2b(A | B | idA | idB | ephA | ephB)
root = BLAKE2b_keyed(X25519(eph, eph'), "sc-root", th)
ck_AB = KDF(root, "sc-chain-i2r");  ck_BA = KDF(root, "sc-chain-r2i")
```

Las firmas incluyen los nombres de ambos extremos, así que un `hs1` dirigido a Bob
no sirve para abrir una sesión con Carol, y el servidor no puede cambiar el remitente.

**Mensajes**

```
mk_n     = KDF(ck_n, "sc-msg")
ck_{n+1} = KDF(ck_n, "sc-chain")
ct       = XChaCha20-Poly1305(mk_n, nonce aleatorio de 24 bytes, aad = th | emisor | n)
```

El receptor rechaza contadores ya vistos (repeticiones) y saltos de más de 1000.
Si falta un mensaje (destruido o manipulado), la sesión sigue y se avisa al usuario.

Las sesiones solo viven mientras los dos siguen conectados. El servidor avisa
(`presence`) cuando un contacto entra o sale y ambos lados descartan la sesión; la
siguiente se negocia de nuevo. Así recargar la página nunca deja sesiones a medias.

**Mensajes en diferido** (`sealed.py`, inspirado en X3DH sin *one-time prekeys*)

Cada usuario publica una *signed prekey* que se renueva cada 7 días:

```
bundle(B) = { idB, SPK_B, Sig_B("spk" | B | SPK_B | fecha) }

th  = BLAKE2b("sealed" | A | B | idA | idB | SPK_B | eph | id_mensaje)
sig = Sig_A(th)
k   = KDF(X25519(eph, SPK_B), th)
ct  = XChaCha20-Poly1305(k, nonce, aad = th)
```

El servidor guarda el sobre (cifrado) y lo entrega cuando B se conecta. B comprueba
la firma de A, rechaza identificadores de mensaje repetidos y descifra con la parte
privada de su SPK, que guarda cifrada con una clave derivada de su identidad.

## Modelo de amenazas

**Atacante considerado:** controla la red y/o el servidor relay. Puede leer, borrar,
reordenar, repetir e inyectar mensajes, y registrar usuarios falsos.

| Protegido | Cómo |
|---|---|
| Confidencialidad del contenido | AEAD con claves que solo conocen los dos extremos |
| Integridad y autenticidad | Poly1305 + handshake firmado con Ed25519 |
| Suplantación de remitente | firmas sobre la transcripción con ambos nombres |
| Repetición / reflexión de mensajes | contador monótono y emisor en el AAD |
| MITM en el primer contacto | **solo si** se comparan los números de seguridad |
| MITM tras el primer contacto | claves fijadas (TOFU): un cambio dispara una alerta |
| Robo posterior de la clave de identidad | secreto hacia adelante (claves efímeras) |
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
- **Tamaño de los mensajes**: el tipo de contenido va cifrado, pero un mensaje de
  3 MB delata que es una foto o un vídeo. Rellenar (*padding*) los mensajes lo ocultaría.
- **Búsqueda de GIF**: no hay buscador tipo Giphy/Tenor porque enviaría lo que
  buscas a un tercero. Los GIF se envían desde tu dispositivo.
- **Disponibilidad**: el servidor puede descartar mensajes o desconectar usuarios.
- **Dispositivo comprometido**: con malware en tu equipo no hay cifrado que valga.
  Python además no permite borrar claves de memoria de forma fiable.
- **Secreto hacia atrás (post-compromise security)**: si alguien roba el estado de
  una sesión activa, puede leer el resto de esa sesión. Signal lo resuelve con el
  ratchet Diffie-Hellman de Double Ratchet; aquí solo hay ratchet simétrico.
- **Mensajes en diferido**: tienen un secreto hacia adelante más débil que las
  sesiones en vivo. Quien robe la SPK privada de Bob (válida 7 días, y se guardan las
  3 últimas) podría leer los sobres dirigidos a ella. Signal lo mitiga con
  *one-time prekeys* y Double Ratchet.
- **Sesión recordada**: la semilla de tu identidad queda cifrada con una clave
  WebCrypto no exportable. Nadie puede copiarla a otro equipo, pero quien use tu
  navegador sí podría abrir la app. "Cerrar sesión" la borra del dispositivo.
- **Historial local**: va cifrado con una clave derivada de tu identidad. Protege
  frente a quien copie los ficheros del navegador sin tu sesión, no frente a malware.
- **Correo**: el servidor lo ve al crear la cuenta para enviarte el código, pero solo
  guarda una huella (HMAC con un secreto propio) para impedir cuentas repetidas.
- **Confirmaciones de entrega y lectura**: van cifradas, pero su tamaño y momento
  revelan al servidor que hubo actividad. Las de lectura se pueden desactivar.
- **Un dispositivo por cuenta**: las prekeys viven en el navegador donde creaste la
  cuenta. Si entras desde otro, los mensajes en espera para el primero no se podrán abrir.
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
- **Negación de autoría**: las firmas Ed25519 del handshake son una prueba
  transferible de que participaste en la conversación (Signal usa X3DH para evitarlo).

## Hoja de ruta

- [x] Fase 1 – Chat 1 a 1 por CLI con relay ciego y claves protegidas con contraseña
- [x] Fase 2 – Huellas, números de seguridad y contactos verificados
- [x] Fase 3 – Claves efímeras por sesión (secreto hacia adelante)
- [x] Fase 4 – Interfaz web instalable (PWA), temas, perfiles y multimedia cifrada
- [x] Fase 5a – Mensajes en diferido con prekeys firmadas, presencia y código de acceso
- [x] Fase 5b – Checks de entrega/lectura, bandeja de salida, historial cifrado, sesión recordada y verificación por correo
- [ ] Fase 6 – Grupos, *one-time prekeys* y varios dispositivos por cuenta
- [ ] Double Ratchet completo, TLS en el relay, historial local cifrado

## Referencias

- [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/) – Signal
- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/) – Signal
- [The Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- H. Krawczyk, [SIGMA: the "SIGn-and-MAc" approach to authenticated Diffie-Hellman](https://www.iacr.org/cryptodb/archive/2003/CRYPTO/1495/1495.pdf) (CRYPTO 2003)
- [Documentación de libsodium](https://doc.libsodium.org/)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) (X25519), [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) (Ed25519), [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) (Argon2)
