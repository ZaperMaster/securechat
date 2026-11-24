package io.github.zapermaster.securechat;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Botón «Rechazar» de la pantalla de llamada: deja de sonar y lo recuerda para avisar a quien llama. */
public class RechazarLlamada extends BroadcastReceiver {
    @Override
    public void onReceive(Context ctx, Intent intent) {
        LlamadaEntrante.quitar(ctx);
        LlamadasPlugin.pendiente("rechazar");
    }
}
