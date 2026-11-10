# SecureChat

Mensajería 1 a 1 con cifrado extremo a extremo (E2E) sobre
[libsodium](https://doc.libsodium.org/). Tiene dos clientes que se entienden entre sí:

- **Web / app instalable (PWA)**: el cifrado ocurre en el navegador con libsodium.js.
- **Terminal**: Python con PyNaCl.

El servidor solo reenvía bytes cifrados: nunca ve el texto ni tiene claves para descifrarlo.

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
- **Números de seguridad** (60 dígitos) para verificar contactos por otro canal y
  detectar ataques man-in-the-middle.
- **TOFU** (*trust on first use*): la primera clave vista de un contacto queda
  fijada; si cambia, el cliente muestra un aviso y rechaza la sesión.
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

### Web

Abre <http://localhost:8765> en dos pestañas o navegadores, crea un usuario en cada
una (por ejemplo `alice` y `bob`), escribe el nombre del otro en "Nuevo chat" y
envía mensajes. Con **Verificar** comparas el número de seguridad.

- La clave privada se genera en el navegador y se guarda en `localStorage`, cifrada
  con tu contraseña (Argon2id). Con 🔑 → *Exportar identidad* obtienes un
  `identity.json` compatible con la versión de terminal.
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
python -m securechat.server --host 0.0.0.0 --cert certs/cert.pem --key certs/key.pem
```

Abre `https://192.168.1.19:8765` en el móvil, acepta el aviso del certificado
autofirmado y usa *Añadir a pantalla de inicio*. Puede que Windows pida permitir
Python en el firewall. Un certificado autofirmado es aceptable para pruebas en tu
red; no lo es para un despliegue real.

### Terminal

Dos usuarios en dos terminales (pueden hablar también con usuarios de la web):

```bash
python -m securechat init --name alice
python -m securechat chat --name alice
```

```bash
python -m securechat init --name bob
python -m securechat chat --name bob
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
  session.py   handshake + cifrado de mensajes (sin E/S, fácil de testear)
  contacts.py  claves fijadas (TOFU) y estado de verificación
  server.py    relay WebSocket + servidor de la web estática
  client.py    lógica de red del cliente, independiente de la interfaz
  cli.py       interfaz de terminal
web/
  js/protocol.js  port de crypto.py + session.py (mismos bytes)
  js/client.js    port de client.py
  js/app.js       interfaz (solo usa textContent: nunca interpreta HTML recibido)
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
- **Disponibilidad**: el servidor puede descartar mensajes o desconectar usuarios.
- **Dispositivo comprometido**: con malware en tu equipo no hay cifrado que valga.
  Python además no permite borrar claves de memoria de forma fiable.
- **Secreto hacia atrás (post-compromise security)**: si alguien roba el estado de
  una sesión activa, puede leer el resto de esa sesión. Signal lo resuelve con el
  ratchet Diffie-Hellman de Double Ratchet; aquí solo hay ratchet simétrico.
- **Mensajes sin conexión**: ambos usuarios deben estar conectados (no hay prekeys).
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
- [x] Fase 4 – Interfaz web instalable (PWA) compatible con la CLI
- [ ] Fase 5 – Mensajes sin conexión (prekeys firmadas, al estilo X3DH) y grupos
- [ ] Double Ratchet completo, TLS en el relay, historial local cifrado

## Referencias

- [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/) – Signal
- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/) – Signal
- [The Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- H. Krawczyk, [SIGMA: the "SIGn-and-MAc" approach to authenticated Diffie-Hellman](https://www.iacr.org/cryptodb/archive/2003/CRYPTO/1495/1495.pdf) (CRYPTO 2003)
- [Documentación de libsodium](https://doc.libsodium.org/)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) (X25519), [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) (Ed25519), [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) (Argon2)
