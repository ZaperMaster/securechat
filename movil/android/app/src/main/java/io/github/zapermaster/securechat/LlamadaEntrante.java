package io.github.zapermaster.securechat;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.media.AudioAttributes;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.Build;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.app.Person;

import java.util.Map;

/**
 * Pantalla de llamada entrante del sistema (como la de WhatsApp): suena con el tono de llamada,
 * vibra, se enciende la pantalla aunque el móvil esté bloqueado y tiene Contestar / Rechazar.
 *
 * El aviso que manda el servidor no dice quién llama (no lo sabe: los mensajes van cifrados y con
 * remitente oculto). Al contestar se abre SecureChat, que recibe la llamada cifrada y descuelga.
 */
public final class LlamadaEntrante {
    static final String CANAL = "llamadas-entrantes";
    static final int ID = 7001;
    static final String EXTRA = "sc_llamada";      // "contestar" o "abrir"
    static final long DURACION_MS = 45_000;        // lo que suena como mucho

    private LlamadaEntrante() {}

    static void mostrar(Context ctx, Map<String, String> datos) {
        String titulo = valor(datos, "title", "Llamada entrante");
        String texto = valor(datos, "body", "SecureChat");
        String contestar = valor(datos, "answer", "Contestar");
        String rechazar = valor(datos, "decline", "Rechazar");
        crearCanal(ctx, titulo);

        PendingIntent abrir = abrirApp(ctx, "abrir", 1);
        PendingIntent descolgar = abrirApp(ctx, "contestar", 2);
        // Rechazar también abre la app un instante: tiene que avisar (cifrado) a quien llama
        // para que le salga «Llamada rechazada»; después vuelve a esconderse sola.
        PendingIntent colgarPi = abrirApp(ctx, "rechazar", 3);

        Person quien = new Person.Builder().setName("SecureChat").setImportant(true).build();
        NotificationCompat.Builder b = new NotificationCompat.Builder(ctx, CANAL)
            .setSmallIcon(R.drawable.ic_stat_securechat)
            .setContentTitle(titulo)
            .setContentText(texto)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC) // no enseña nada privado: no sabe quién llama
            .setOngoing(true)
            .setAutoCancel(false)
            .setTimeoutAfter(DURACION_MS)
            .setContentIntent(abrir)
            .setFullScreenIntent(abrir, true)
            .setStyle(NotificationCompat.CallStyle.forIncomingCall(quien, colgarPi, descolgar))
            .addPerson(quien);
        // En versiones sin CallStyle nativo, los botones van como acciones normales
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            b.addAction(0, rechazar, colgarPi).addAction(0, contestar, descolgar);
        }
        Notification n = b.build();
        n.flags |= Notification.FLAG_INSISTENT; // el tono se repite hasta contestar o colgar
        try {
            NotificationManagerCompat.from(ctx).notify(ID, n);
        } catch (SecurityException e) {
            // Sin permiso de notificaciones: no se puede enseñar nada
        }
    }

    static void quitar(Context ctx) {
        NotificationManagerCompat.from(ctx).cancel(ID);
    }

    private static PendingIntent abrirApp(Context ctx, String accion, int codigo) {
        Intent i = new Intent(ctx, MainActivity.class)
            .putExtra(EXTRA, accion)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        return PendingIntent.getActivity(ctx, codigo, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    private static void crearCanal(Context ctx, String nombre) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;
        NotificationManager nm = ctx.getSystemService(NotificationManager.class);
        if (nm == null || nm.getNotificationChannel(CANAL) != null) return;
        NotificationChannel canal = new NotificationChannel(CANAL, nombre, NotificationManager.IMPORTANCE_HIGH);
        Uri tono = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE);
        canal.setSound(tono, new AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
            .build());
        canal.enableVibration(true);
        canal.setVibrationPattern(new long[] { 0, 800, 600, 800, 600 });
        canal.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
        canal.setBypassDnd(false);
        nm.createNotificationChannel(canal);
    }

    private static String valor(Map<String, String> datos, String clave, String porDefecto) {
        String v = datos == null ? null : datos.get(clave);
        return v == null || v.isEmpty() ? porDefecto : v;
    }
}
