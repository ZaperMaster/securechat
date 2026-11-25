# Llevar el servidor a la nube (gratis, siempre encendido)

Así SecureChat funciona aunque tu PC esté apagado. La dirección **no cambia**
(`securechat.dojo-massometer.ts.net`), así que las apps instaladas siguen funcionando sin
reinstalar nada. Hace falta una máquina Linux siempre encendida; la de **Oracle Cloud "Always
Free"** es gratis para siempre y sobra (Ampere A1: hasta 4 núcleos, 24 GB de RAM y 10 TB de salida
al mes). Pide una tarjeta al darte de alta, solo para verificar.

> Mientras dure la mudanza (unos minutos), el servidor estará apagado. Los mensajes que se envíen
> en ese rato se quedan esperando en el teléfono de quien los manda y salen al volver.

## 1. Crear la máquina (Oracle Cloud)

1. Date de alta en <https://www.oracle.com/cloud/free/> (elige la región más cercana, por ejemplo
   *Spain Central (Madrid)*: no se puede cambiar después).
2. **Compute → Instances → Create instance**:
   - Imagen: **Canonical Ubuntu 24.04**.
   - Forma: **Ampere VM.Standard.A1.Flex** con 1 núcleo y 6 GB (sobra; es "Always Free").
   - Claves SSH: **Generate a key pair** y descarga la clave privada (guárdala en `privado/`).
3. Crea la instancia y apunta su **IP pública**. No hace falta abrir ningún puerto: Tailscale
   conecta hacia fuera.

## 2. Instalar SecureChat en la máquina

Desde tu PC:

```powershell
ssh -i C:\ruta\a\la\clave.key ubuntu@IP_DE_LA_MAQUINA
```

y dentro de la máquina:

```bash
curl -fsSL https://raw.githubusercontent.com/ZaperMaster/securechat/main/nube/instalar.sh | sudo bash
```

Instala Python, el servidor como servicio (arranca solo y se reinicia si falla), una copia diaria
de la base de datos (14 días) y Tailscale.

## 3. Apagar el servidor de tu PC

- Clic derecho en el icono de SecureChat de la bandeja → **Salir**.
- Borra el acceso directo de inicio para que no vuelva a arrancar:
  `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\SecureChat Servidor.lnk`
- **No pueden estar los dos encendidos a la vez**: Tailscale no sabría a cuál mandar a la gente.

## 4. Copiar tus datos

En PowerShell, en la carpeta del proyecto:

```powershell
.\nube\copiar-datos.ps1 -Destino ubuntu@IP_DE_LA_MAQUINA -Clave C:\ruta\a\la\clave.key
```

Copia la base de datos (cuentas, mensajes en espera, copias cifradas), las claves del servidor
(avisos, Firebase, huellas de los correos) y la configuración del correo, y arranca el servicio.

## 5. Darle la dirección de siempre

1. En <https://login.tailscale.com/admin/machines>, a tu **PC** (que ahora se llama `securechat`)
   cámbiale el nombre (por ejemplo `portatil`): **⋯ → Edit machine name**.
2. En la máquina de la nube:

```bash
sudo tailscale up --hostname=securechat      # abre el enlace que te da para añadirla a tu Tailscale
sudo tailscale funnel --bg 8765
sudo tailscale funnel --bg --tls-terminated-tcp=10000 tcp://localhost:3478
```

3. Comprueba que responde: <https://securechat.dojo-massometer.ts.net/config.json>

La **vigilancia de GitHub** (cada 15 minutos) te avisará por correo si deja de responder.

## Mantenimiento

```bash
sudo systemctl status securechat          # ¿está en marcha?
sudo journalctl -u securechat -f          # registro en vivo
sudo /opt/securechat/venv/bin/python -m securechat.server --denuncias --db /var/lib/securechat/usuarios.json
# Actualizar a la última versión del código:
sudo -u securechat git -C /opt/securechat/app pull && sudo systemctl restart securechat
```

Copias diarias de la base de datos: `/var/lib/securechat/copias/`.
