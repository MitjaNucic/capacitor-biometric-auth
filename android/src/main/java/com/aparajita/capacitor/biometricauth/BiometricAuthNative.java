import android.annotation.SuppressLint;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.HashMap;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

@SuppressLint("RestrictedApi")
@CapacitorPlugin(name = "BiometricAuthNative")
public class BiometricAuthNative extends Plugin {

  public static final String RESULT_TYPE = "type";
  public static final String RESULT_ERROR_CODE = "errorCode";
  public static final String RESULT_ERROR_MESSAGE = "errorMessage";
  public static final String TITLE = "androidTitle";
  public static final String SUBTITLE = "androidSubtitle";
  public static final String REASON = "reason";
  public static final String CANCEL_TITLE = "cancelTitle";
  public static final String BIOMETRIC_STRENGTH = "biometricStrength";
  public static final String DEVICE_CREDENTIAL = "allowDeviceCredential";
  public static final String CONFIRMATION_REQUIRED =
    "androidConfirmationRequired";
  public static final String MAX_ATTEMPTS = "androidMaxAttempts";
  public static final int DEFAULT_MAX_ATTEMPTS = 3;
  public static final String BIOMETRIC_FAILURE = "authenticationFailed";
  private static final HashMap<Integer, String> biometryErrorCodeMap;
  private static final HashMap<BiometryType, String> biometryNameMap;
  private static final String INVALID_CONTEXT_ERROR = "invalidContext";
  public static String RESULT_EXTRA_PREFIX;

  static {
    biometryErrorCodeMap = new HashMap<>();
    biometryErrorCodeMap.put(BiometricManager.BIOMETRIC_SUCCESS, "");
    biometryErrorCodeMap.put(BiometricPrompt.ERROR_CANCELED, "systemCancel");
    biometryErrorCodeMap.put(
      BiometricPrompt.ERROR_HW_NOT_PRESENT,
      "biometryNotAvailable"
    );
    biometryErrorCodeMap.put(
      BiometricPrompt.ERROR_HW_UNAVAILABLE,
      "biometryNotAvailable"
    );
    biometryErrorCodeMap.put(BiometricPrompt.ERROR_LOCKOUT, "biometryLockout");
    biometryErrorCodeMap.put(
      BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
      "biometryLockout"
    );
    biometryErrorCodeMap.put(
      BiometricPrompt.ERROR_NEGATIVE_BUTTON,
      "userCancel"
    );
    biometryErrorCodeMap.put(
      BiometricPrompt.ERROR_NO_BIOMETRICS,
      "biometryNotEnrolled"
    );
    biometryErrorCodeMap.put(
      BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
      "noDeviceCredential"
    );
    biometryErrorCodeMap.put(BiometricPrompt.ERROR_NO_SPACE, "systemCancel");
    biometryErrorCodeMap.put(BiometricPrompt.ERROR_TIMEOUT, "systemCancel");
    biometryErrorCodeMap.put(
      BiometricPrompt.ERROR_UNABLE_TO_PROCESS,
      "systemCancel"
    );
    biometryErrorCodeMap.put(BiometricPrompt.ERROR_USER_CANCELED, "userCancel");
    biometryErrorCodeMap.put(BiometricPrompt.ERROR_VENDOR, "systemCancel");
  }

  static {
    biometryNameMap = new HashMap<>();
    biometryNameMap.put(BiometryType.NONE, "No Authentication");
    biometryNameMap.put(BiometryType.FINGERPRINT, "Fingerprint Authentication");
    biometryNameMap.put(BiometryType.FACE, "Face Authentication");
    biometryNameMap.put(BiometryType.IRIS, "Iris Authentication");
  }

  private ArrayList<BiometryType> biometryTypes;
  private KeyStore keyStore;
  private static final String KEY_NAME = "biometric_key";

  private int getAuthenticatorFromCall(PluginCall call) {
    int authenticator = BiometricManager.Authenticators.BIOMETRIC_WEAK;
    Integer value = call.getInt(
      "androidBiometryStrength",
      BiometryStrength.WEAK.ordinal()
    );
    if (value != null && value == BiometryStrength.STRONG.ordinal()) {
      authenticator = BiometricManager.Authenticators.BIOMETRIC_STRONG;
    }
    return authenticator;
  }

  @PluginMethod
  public void checkBiometry(PluginCall call) {
    call.resolve(checkBiometry());
  }

  private JSObject checkBiometry() {
    JSObject result = new JSObject();
    BiometricManager manager = BiometricManager.from(getContext());
    int weakBiometryResult = manager.canAuthenticate(
      BiometricManager.Authenticators.BIOMETRIC_WEAK
    );
    setReasonAndCode(weakBiometryResult, false, result);
    result.put(
      "isAvailable",
      weakBiometryResult == BiometricManager.BIOMETRIC_SUCCESS
    );
    int strongBiometryResult = manager.canAuthenticate(
      BiometricManager.Authenticators.BIOMETRIC_STRONG
    );
    setReasonAndCode(strongBiometryResult, true, result);
    result.put(
      "strongBiometryIsAvailable",
      strongBiometryResult == BiometricManager.BIOMETRIC_SUCCESS
    );
    biometryTypes = getDeviceBiometryTypes();
    result.put("biometryType", biometryTypes.get(0).getType());
    JSArray returnTypes = new JSArray();
    for (BiometryType type : biometryTypes) {
      if (type != BiometryType.NONE) {
        returnTypes.put(type.getType());
      }
    }
    result.put("biometryTypes", returnTypes);
    KeyguardManager keyguardManager = (KeyguardManager) getContext()
      .getSystemService(Context.KEYGUARD_SERVICE);
    result.put(
      "deviceIsSecure",
      keyguardManager != null && keyguardManager.isKeyguardSecure()
    );
    return result;
  }

  private static void setReasonAndCode(
    int canAuthenticateResult,
    boolean strong,
    JSObject result
  ) {
    String reason = "";
    switch (canAuthenticateResult) {
      case BiometricManager.BIOMETRIC_SUCCESS:
        break;
      case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
        reason = "Biometry hardware is present, but currently unavailable.";
        break;
      case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
        reason = "The user does not have any biometrics enrolled.";
        break;
      case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
        reason = "There is no biometric hardware on this device.";
        break;
      case BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED:
        reason =
          "The user can’t authenticate because a security vulnerability has been discovered with one or more hardware sensors.";
        break;
      case BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED:
        reason =
          "The user can’t authenticate because the specified options are incompatible with the current Android version.";
        break;
      case BiometricManager.BIOMETRIC_STATUS_UNKNOWN:
        reason = "Unable to determine whether the user can authenticate.";
        break;
    }
    String errorCode = biometryErrorCodeMap.get(canAuthenticateResult);
    if (errorCode == null) {
      errorCode = "biometryNotAvailable";
    }
    result.put(strong ? "strongReason" : "reason", reason);
    result.put(strong ? "strongCode" : "code", errorCode);
  }

  @NonNull
  private ArrayList<BiometryType> getDeviceBiometryTypes() {
    ArrayList<BiometryType> types = new ArrayList<>();
    PackageManager manager = getContext().getPackageManager();
    if (manager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
      types.add(BiometryType.FINGERPRINT);
    }
    if (manager.hasSystemFeature(PackageManager.FEATURE_FACE)) {
      types.add(BiometryType.FACE);
    }
    if (manager.hasSystemFeature(PackageManager.FEATURE_IRIS)) {
      types.add(BiometryType.IRIS);
    }
    if (types.isEmpty()) {
      types.add(BiometryType.NONE);
    }
    return types;
  }

  private void createKey() {
    try {
      keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      KeyGenerator keyGenerator = KeyGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_AES,
        "AndroidKeyStore"
      );
      keyGenerator.init(
        new KeyGenParameterSpec.Builder(
          KEY_NAME,
          KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
          .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
          .setUserAuthenticationRequired(true)
          .setInvalidatedByBiometricEnrollment(true)
          .setUserAuthenticationValidityDurationSeconds(-1)
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
          .build()
      );
      keyGenerator.generateKey();
    } catch (Exception e) {
      throw new RuntimeException("Failed to create a key", e);
    }
  }

  private Cipher getCipher() {
    try {
      Cipher cipher = Cipher.getInstance(
        KeyProperties.KEY_ALGORITHM_AES +
        "/" +
        KeyProperties.BLOCK_MODE_CBC +
        "/" +
        KeyProperties.ENCRYPTION_PADDING_PKCS7
      );
      keyStore.load(null);
      SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME, null);
      cipher.init(Cipher.ENCRYPT_MODE, key);
      return cipher;
    } catch (Exception e) {
      throw new RuntimeException("Failed to get Cipher", e);
    }
  }

  @PluginMethod
  public void internalAuthenticate(final PluginCall call) {
    createKey();
    Cipher cipher = getCipher();
    BiometricPrompt.CryptoObject cryptoObject =
      new BiometricPrompt.CryptoObject(cipher);

    BiometricPrompt biometricPrompt = new BiometricPrompt(
      this,
      ContextCompat.getMainExecutor(getContext()),
      new BiometricPrompt.AuthenticationCallback() {
        @Override
        public void onAuthenticationSucceeded(
          BiometricPrompt.AuthenticationResult result
        ) {
          Cipher cipher = result.getCryptoObject().getCipher();
          try {
            byte[] encryptedData = getEncryptedData(); // Retrieve actual encrypted data
            byte[] decryptedData = cipher.doFinal(encryptedData);
            // Handle the decrypted data, e.g., load your session or secondary key
            call.resolve();
          } catch (Exception e) {
            call.reject("Failed to decrypt data", e);
          }
        }

        @Override
        public void onAuthenticationFailed() {
          call.reject("Biometric authentication failed", BIOMETRIC_FAILURE);
        }

        @Override
        public void onAuthenticationError(
          int errorCode,
          @NonNull CharSequence errString
        ) {
          call.reject(
            errString.toString(),
            biometryErrorCodeMap.get(errorCode)
          );
        }
      }
    );

    biometricPrompt.authenticate(cryptoObject);
  }

  // Method to store encrypted data
  private void storeEncryptedData(byte[] encryptedData) {
    SharedPreferences sharedPreferences = getContext()
      .getSharedPreferences("BiometricAuthPrefs", Context.MODE_PRIVATE);
    SharedPreferences.Editor editor = sharedPreferences.edit();
    editor.putString(
      "encryptedData",
      Base64.encodeToString(encryptedData, Base64.DEFAULT)
    );
    editor.apply();
  }

  // Method to retrieve encrypted data
  private byte[] getEncryptedData() {
    SharedPreferences sharedPreferences = getContext()
      .getSharedPreferences("BiometricAuthPrefs", Context.MODE_PRIVATE);
    String encryptedDataString = sharedPreferences.getString(
      "encryptedData",
      null
    );
    if (encryptedDataString != null) {
      return Base64.decode(encryptedDataString, Base64.DEFAULT);
    } else {
      throw new RuntimeException("No encrypted data found");
    }
  }
}
