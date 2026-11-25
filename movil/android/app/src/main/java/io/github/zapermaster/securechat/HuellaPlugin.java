package io.github.zapermaster.securechat;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

/**
 * Huella o cara del sistema para el bloqueo de la app (opcional: lo activa cada persona en
 * Privacidad → Bloqueo de la app). El visor web de una app no admite la huella como Chrome
 * (WebAuthn), así que aquí se usa el diálogo biométrico de Android.
 */
@CapacitorPlugin(name = "Huella")
public class HuellaPlugin extends Plugin {
    private static final int TIPOS = BiometricManager.Authenticators.BIOMETRIC_WEAK;

    @PluginMethod
    public void disponible(PluginCall call) {
        int r = BiometricManager.from(getContext()).canAuthenticate(TIPOS);
        JSObject o = new JSObject();
        o.put("disponible", r == BiometricManager.BIOMETRIC_SUCCESS);
        o.put("configurada", r != BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED);
        call.resolve(o);
    }

    @PluginMethod
    public void verificar(PluginCall call) {
        String titulo = call.getString("titulo", "Desbloquear SecureChat");
        String cancelar = call.getString("cancelar", "Usar el PIN");
        FragmentActivity act = getActivity();
        act.runOnUiThread(() -> {
            BiometricPrompt prompt = new BiometricPrompt(act, ContextCompat.getMainExecutor(act),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                        JSObject o = new JSObject();
                        o.put("ok", true);
                        call.resolve(o);
                    }

                    @Override
                    public void onAuthenticationError(int code, @NonNull CharSequence msg) {
                        JSObject o = new JSObject();
                        o.put("ok", false);
                        o.put("motivo", msg.toString());
                        call.resolve(o);
                    }
                    // onAuthenticationFailed (dedo no reconocido): el diálogo deja reintentar solo
                });
            BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(titulo)
                .setNegativeButtonText(cancelar)
                .setAllowedAuthenticators(TIPOS)
                .setConfirmationRequired(false)
                .build();
            prompt.authenticate(info);
        });
    }
}
