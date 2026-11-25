// Endurece el ejecutable de Electron cambiando sus "fusibles" (opciones grabadas en el binario):
//  * no se puede arrancar como Node (ELECTRON_RUN_AS_NODE) ni pasarle NODE_OPTIONS o --inspect;
//  * las cookies se cifran en disco;
//  * solo se carga la app desde el paquete (app.asar) y se comprueba su integridad.
const path = require("node:path");
const { flipFuses, FuseVersion, FuseV1Options } = require("@electron/fuses");

exports.default = async function afterPack(context) {
  const name = context.packager.appInfo.productFilename;
  const platform = context.electronPlatformName;
  // El ejecutable de Electron en cada sistema
  const exe = platform === "darwin" ? path.join(context.appOutDir, `${name}.app`)
    : platform === "linux" ? path.join(context.appOutDir, context.packager.executableName)
    : path.join(context.appOutDir, `${name}.exe`);
  await flipFuses(exe, {
    version: FuseVersion.V1,
    // En Mac la firma "ad hoc" deja de valer al tocar el binario: se rehace (si no, no arranca en Apple Silicon)
    resetAdHocDarwinSignature: platform === "darwin",
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    [FuseV1Options.EnableCookieEncryption]: true,
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
    [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,
  });
  console.log("fusibles de Electron aplicados en", exe);
};
