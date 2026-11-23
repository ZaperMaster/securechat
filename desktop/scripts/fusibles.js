// Endurece el ejecutable de Electron cambiando sus "fusibles" (opciones grabadas en el binario):
//  * no se puede arrancar como Node (ELECTRON_RUN_AS_NODE) ni pasarle NODE_OPTIONS o --inspect;
//  * las cookies se cifran en disco;
//  * solo se carga la app desde el paquete (app.asar) y se comprueba su integridad.
const path = require("node:path");
const { flipFuses, FuseVersion, FuseV1Options } = require("@electron/fuses");

exports.default = async function afterPack(context) {
  const exe = path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.exe`);
  await flipFuses(exe, {
    version: FuseVersion.V1,
    resetAdHocDarwinSignature: false,
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
