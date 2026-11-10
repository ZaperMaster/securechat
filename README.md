# SecureChat

Mensajería 1 a 1 con cifrado extremo a extremo (E2E), escrita en Python sobre
[libsodium](https://doc.libsodium.org/) (PyNaCl). El servidor solo reenvía bytes
cifrados: nunca ve el texto ni tiene claves para descifrarlo.

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

Terminal 1, el servidor:

```bash
python -m securechat.server
```

Terminales 2 y 3, dos usuarios:

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

Tests:

```bash
pytest -q
```

## Arquitectura

```
securechat/
  crypto.py    almacén de claves, KDF, huellas y números de seguridad
  session.py   handshake + cifrado de mensajes (sin E/S, fácil de testear)
  contacts.py  claves fijadas (TOFU) y estado de verificación
  server.py    relay WebSocket: autenticación y reenvío
  client.py    lógica de red del cliente, independiente de la interfaz
  cli.py       interfaz de terminal
```

`session.py` no hace E/S: toda la criptografía de la conversación se prueba sin red.
`client.py` emite eventos a una cola, así que una GUI futura puede reutilizarlo.

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
- **Negación de autoría**: las firmas Ed25519 del handshake son una prueba
  transferible de que participaste en la conversación (Signal usa X3DH para evitarlo).

## Hoja de ruta

- [x] Fase 1 – Chat 1 a 1 por CLI con relay ciego y claves protegidas con contraseña
- [x] Fase 2 – Huellas, números de seguridad y contactos verificados
- [x] Fase 3 – Claves efímeras por sesión (secreto hacia adelante)
- [ ] Fase 4 – Interfaz gráfica o web (reutilizando `client.py`)
- [ ] Fase 5 – Mensajes sin conexión (prekeys firmadas, al estilo X3DH) y grupos
- [ ] Double Ratchet completo, TLS en el relay, historial local cifrado

## Referencias

- [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/) – Signal
- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/) – Signal
- [The Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- H. Krawczyk, [SIGMA: the "SIGn-and-MAc" approach to authenticated Diffie-Hellman](https://www.iacr.org/cryptodb/archive/2003/CRYPTO/1495/1495.pdf) (CRYPTO 2003)
- [Documentación de libsodium](https://doc.libsodium.org/)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) (X25519), [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) (Ed25519), [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) (Argon2)
