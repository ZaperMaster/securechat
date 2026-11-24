# Seguridad

SecureChat es una app de cifrado: los fallos de seguridad son lo más importante que me puedes contar.

## Informar de una vulnerabilidad

1. **No abras una issue pública** (ni un pull request que la explique).
2. Usa la opción privada de GitHub: pestaña **Security → Report a vulnerability** de este repositorio.
3. Explica qué has encontrado, cómo reproducirlo y qué impacto crees que tiene (por ejemplo: leer mensajes
   de otros, hacerse pasar por alguien, saltarse un bloqueo, tumbar el servidor…).

Intentaré responder en un plazo de 7 días, avisarte cuando esté corregido y, si quieres, darte las gracias
en las notas de la versión.

## Qué entra

- El protocolo (X3DH/PQXDH, Double Ratchet, sender keys, remitente oculto) y su implementación en
  `web/js/` y `securechat/`.
- El servidor (`securechat/server.py`): autenticación, colas, copias de claves, límites y avisos.
- Las apps de Windows (`desktop/`) y Android (`android/`), incluidas sus actualizaciones firmadas.

Las limitaciones ya conocidas están en el [modelo de amenazas](README.md#modelo-de-amenazas) (por ejemplo, los
metadatos que sí ve el servidor). Si crees que alguna es más grave de lo que dice, también cuenta.

## Versiones con soporte

Solo la última versión publicada en [Releases](https://github.com/ZaperMaster/securechat/releases) y el código de
la rama `main`.

## Protección del repositorio

Este repositorio tiene activados el análisis de código (CodeQL), los avisos y actualizaciones de dependencias
(Dependabot), la auditoría semanal de dependencias y la detección de secretos con bloqueo al subir.
