package io.github.zapermaster.securechat;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.WindowManager;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    static volatile boolean aLaVista = false;

    @Override
    public void onResume() {
        super.onResume();
        aLaVista = true;
    }

    @Override
    public void onPause() {
        super.onPause();
        aLaVista = false;
    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        registerPlugin(LlamadasPlugin.class);
        super.onCreate(savedInstanceState);
        llamada(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        llamada(intent);
    }

    // Se quita al terminar la llamada (la web llama a Llamadas.fin()), o si se abrió desde la
    // pantalla de llamada pero no llegó a haber llamada (también la web, al minuto).

    /** Abierta desde la pantalla de llamada: se ve sobre el bloqueo y recuerda si hay que descolgar. */
    private void llamada(Intent intent) {
        if (intent == null) return;
        String accion = intent.getStringExtra(LlamadaEntrante.EXTRA);
        if (accion == null) return;
        intent.removeExtra(LlamadaEntrante.EXTRA);
        sobreBloqueo(true);
        if ("contestar".equals(accion) || "rechazar".equals(accion)) {
            LlamadaEntrante.quitar(this);
            LlamadasPlugin.pendiente(accion); // por si la web aún está arrancando
            LlamadasPlugin.avisar(accion);    // y si ya está en marcha, al momento
        }
    }

    void sobreBloqueo(boolean si) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(si);
            setTurnScreenOn(si);
        } else if (si) {
            getWindow().addFlags(WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED | WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON);
        } else {
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED | WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON);
        }
    }
}
