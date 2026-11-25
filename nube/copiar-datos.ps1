# Copia los datos del servidor de tu PC (SecureChatDatos) a la máquina de la nube.
# Uso, en PowerShell en tu PC (con el servidor de la bandeja YA CERRADO):
#   .\nube\copiar-datos.ps1 -Destino ubuntu@IP_DE_LA_MAQUINA -Clave C:\ruta\a\tu\clave-ssh.key
param(
  [Parameter(Mandatory = $true)][string]$Destino,
  [Parameter(Mandatory = $true)][string]$Clave,
  [string]$Datos = "$PSScriptRoot\..\privado\dist\SecureChatDatos"
)
$ErrorActionPreference = "Stop"
if (Get-Process SecureChatServer -ErrorAction SilentlyContinue) {
  throw "Cierra antes el servidor de la bandeja (clic derecho en el icono -> Salir)."
}
$tmp = Join-Path $env:TEMP "securechat-mudanza"
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $tmp | Out-Null

# La base de datos, en un solo fichero coherente (aunque tenga diario WAL)
$py = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
& $py -c "import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d); d.close()" `
  (Join-Path $Datos "usuarios.db") (Join-Path $tmp "usuarios.db")

# Las claves del servidor (sin ellas, los avisos y la verificación de correos dejarían de funcionar)
foreach ($f in "usuarios_secret.key", "usuarios_vapid.pem", "usuarios_fcm.json", "correo.json", "usuarios_denuncias.jsonl") {
  $p = Join-Path $Datos $f
  if (Test-Path $p) { Copy-Item $p $tmp }
}
Write-Host "Copiando a $Destino ..."
scp -i $Clave -r "$tmp\*" "${Destino}:/tmp/securechat-datos/"
ssh -i $Clave $Destino "sudo mkdir -p /var/lib/securechat && sudo cp /tmp/securechat-datos/* /var/lib/securechat/ && sudo chown -R securechat:securechat /var/lib/securechat && sudo chmod 600 /var/lib/securechat/* && rm -rf /tmp/securechat-datos && sudo systemctl restart securechat && systemctl --no-pager status securechat | head -5"
Remove-Item $tmp -Recurse -Force
Write-Host "Hecho. Ahora conecta Tailscale en la máquina (nube/LEEME.md, paso 5)."
