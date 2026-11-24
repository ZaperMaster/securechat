package io.github.zapermaster.securechat;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

/**
 * Puente con la web: qué se pulsó en la pantalla de llamada del sistema («contestar» o «rechazar»)
 * para que la app haga lo mismo cuando reciba la llamada cifrada, y quitar esa pantalla.
 */
@CapacitorPlugin(name = "Llamadas")
public class LlamadasPlugin extends Plugin {
    private static String accion = null;
    private static long cuando = 0;

    static synchronized void pendiente(String a) {
        accion = a;
        cuando = System.currentTimeMillis();
    }

    @PluginMethod
    public void pendiente(PluginCall call) {
        JSObject r = new JSObject();
        synchronized (LlamadasPlugin.class) {
            if (accion != null && System.currentTimeMillis() - cuando < 60_000) {
                r.put("accion", accion);
                r.put("hace", System.currentTimeMillis() - cuando);
            }
            accion = null;
        }
        call.resolve(r);
    }

    @PluginMethod
    public void quitar(PluginCall call) {
        LlamadaEntrante.quitar(getContext());
        call.resolve();
    }

    /** Vuelve a la normalidad la pantalla de bloqueo (al terminar la llamada). */
    @PluginMethod
    public void fin(PluginCall call) {
        getActivity().runOnUiThread(() -> ((MainActivity) getActivity()).sobreBloqueo(false));
        call.resolve();
    }
}
