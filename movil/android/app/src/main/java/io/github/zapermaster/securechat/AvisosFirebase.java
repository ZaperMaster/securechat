package io.github.zapermaster.securechat;

import androidx.annotation.NonNull;

import com.capacitorjs.plugins.pushnotifications.MessagingService;
import com.google.firebase.messaging.RemoteMessage;

import java.util.Map;

/**
 * Recibe los avisos de Firebase aunque la app esté cerrada. Las llamadas ("call") se enseñan
 * como pantalla de llamada entrante y "call-stop" la quita (quien llamaba ha colgado o se ha
 * contestado en otro dispositivo). El resto sigue el camino normal del plugin de Capacitor.
 */
public class AvisosFirebase extends MessagingService {
    @Override
    public void onMessageReceived(@NonNull RemoteMessage mensaje) {
        Map<String, String> datos = mensaje.getData();
        String tipo = datos.get("kind");
        if ("call".equals(tipo)) {
            LlamadaEntrante.mostrar(this, datos);
            return;
        }
        if ("call-stop".equals(tipo)) {
            LlamadaEntrante.quitar(this);
            return;
        }
        super.onMessageReceived(mensaje);
    }
}
