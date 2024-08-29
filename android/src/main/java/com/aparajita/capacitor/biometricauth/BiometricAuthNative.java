package com.aparajita.capacitor.biometricauth;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import androidx.activity.result.ActivityResult;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.HashMap;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

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
  public static String DATA = "data";
  public static String DATA_KEY = "data_key";
  public static String IV_KEY = "ivKey";
  private PluginCall savedCall;
  private KeyStore keyStore;
  private Cipher cipher;

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

    KeyguardManager keyguardManager = (KeyguardManager) this.getContext()
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

  private void createKey(String keyName) throws Exception {
    keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null);

    KeyGenerator keyGenerator = KeyGenerator.getInstance(
      KeyProperties.KEY_ALGORITHM_AES,
      "AndroidKeyStore"
    );
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      keyGenerator.init(
        new KeyGenParameterSpec.Builder(
          keyName,
          KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
          .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
          .setUserAuthenticationRequired(true)
          .setInvalidatedByBiometricEnrollment(true)
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
          .setUserAuthenticationValidityDurationSeconds(-1)
          .build()
      );
    }
    keyGenerator.generateKey();
  }

  private boolean initCipher(String keyName) {
    try {
      keyStore.load(null);
      SecretKey key = (SecretKey) keyStore.getKey(keyName, null);

      if (key == null) {
        Log.e(
          "BiometricAuthNative",
          "SecretKey is null. Failed to retrieve key from KeyStore."
        );
        return false;
      }

      cipher = Cipher.getInstance(
        KeyProperties.KEY_ALGORITHM_AES +
        "/" +
        KeyProperties.BLOCK_MODE_CBC +
        "/" +
        KeyProperties.ENCRYPTION_PADDING_PKCS7
      );
      cipher.init(Cipher.ENCRYPT_MODE, key);

      // Store the IV after encryption initialization
      byte[] iv = cipher.getIV();
      storeIV(iv, savedCall);
      Log.d(
        "BiometricAuthNative",
        "Encryption IV: " + Base64.encodeToString(iv, Base64.DEFAULT)
      );

      return true;
    } catch (Exception e) {
      Log.e("BiometricAuthNative", "Cipher initialization failed", e);
      return false;
    }
  }

  @Nullable
  private BiometricPrompt.CryptoObject createCryptoObject(String keyName) {
    try {
      SecretKey key = (SecretKey) keyStore.getKey(keyName, null);

      // Retrieve the IV from stored data and use it for decryption
      byte[] iv = getStoredIV(savedCall);
      Log.d(
        "BiometricAuthNative",
        "Decryption IV: " + Base64.encodeToString(iv, Base64.DEFAULT)
      );
      cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

      return new BiometricPrompt.CryptoObject(cipher);
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  @PluginMethod
  public void internalAuthenticate(final PluginCall call) {
    try {
      // Save the call for later use in the callbacks
      this.savedCall = call;

      // Ensure that encryptedData and encryptedDataKey are provided
      if (!call.getData().has(DATA) || !call.getData().has(DATA_KEY)) {
        call.reject("Missing encryptedData or encryptedDataKey");
        return;
      }

      String encryptedDataKey = call.getString(DATA_KEY);

      // Initialize key and cipher for encryption
      createKey(encryptedDataKey);
      boolean cipherInitialized = initCipher(encryptedDataKey);

      if (cipherInitialized) {
        // Create a CryptoObject for the BiometricPrompt
        BiometricPrompt.CryptoObject cryptoObject =
          new BiometricPrompt.CryptoObject(cipher);
        startBiometricPromptWithCryptoObject(
          call,
          "Biometric Authentication",
          cryptoObject
        );
      } else {
        call.reject("Failed to initialize cryptography.");
      }
    } catch (Exception e) {
      e.printStackTrace();
      call.reject("Failed to create key or initialize cipher.");
    }
  }

  @ActivityCallback
  private void authenticateResult(PluginCall call, ActivityResult result) {
    if (call == null) return;

    JSObject resultObject = new JSObject();
    Intent intent = result.getData();

    if (intent != null) {
      resultObject.put(
        RESULT_TYPE,
        intent.getStringExtra(RESULT_EXTRA_PREFIX + "type")
      );
      resultObject.put(
        RESULT_ERROR_CODE,
        intent.getStringExtra(RESULT_EXTRA_PREFIX + "errorCode")
      );
      resultObject.put(
        RESULT_ERROR_MESSAGE,
        intent.getStringExtra(RESULT_EXTRA_PREFIX + "errorMessage")
      );
    }

    if (result.getResultCode() == Activity.RESULT_OK) {
      call.resolve(resultObject);
    } else {
      call.reject("Authentication failed", resultObject.toString());
    }
  }

  private final BiometricPrompt.AuthenticationCallback authenticationCallback =
    new BiometricPrompt.AuthenticationCallback() {
      @Override
      public void onAuthenticationSucceeded(
        @NonNull BiometricPrompt.AuthenticationResult result
      ) {
        try {
          Log.d("BiometricAuthNative", "Authentication succeeded");

          // Retrieve the original data from the saved call (this should be the plain text "Token")
          String originalData = savedCall.getString(DATA);
          Log.d("BiometricAuthNative", "Original Data: " + originalData);

          // Use the authenticated cipher to encrypt the plain text data
          Cipher cipher = result.getCryptoObject().getCipher();
          byte[] encryptedData = cipher.doFinal(
            originalData.getBytes(StandardCharsets.UTF_8)
          );

          // Store the IV used during encryption
          byte[] iv = cipher.getIV();
          storeIV(iv, savedCall);

          // Convert encrypted data to Base64 and log it
          String encryptedDataString = Base64.encodeToString(
            encryptedData,
            Base64.DEFAULT
          );
          Log.d(
            "BiometricAuthNative",
            "Encrypted Data (Base64): " + encryptedDataString
          );

          // Store the encrypted data
          storeEncryptedData(encryptedData, savedCall);

          // Prepare the result object to send back to the frontend
          JSObject resultObject = new JSObject();
          resultObject.put("encryptedData", encryptedDataString);

          // Resolve the saved call with the encrypted data
          savedCall.resolve(resultObject);
        } catch (Exception e) {
          e.printStackTrace();
          Log.e("BiometricAuthNative", "Encryption failed", e);
          savedCall.reject("Encryption failed.");
        } finally {
          savedCall = null;
        }
      }

      @Override
      public void onAuthenticationFailed() {
        Log.d("BiometricAuthNative", "Authentication failed");
        if (savedCall != null) {
          savedCall.reject("Authentication failed.");
          savedCall = null;
        }
      }

      @Override
      public void onAuthenticationError(
        int errorCode,
        @NonNull CharSequence errString
      ) {
        Log.d("BiometricAuthNative", "Authentication error: " + errString);
        if (savedCall != null) {
          savedCall.reject("Authentication error: " + errString);
          savedCall = null;
        }
      }
    };

  private void startBiometricPromptWithCryptoObject(
    PluginCall call,
    String title,
    BiometricPrompt.CryptoObject cryptoObject
  ) {
    getActivity()
      .runOnUiThread(() -> {
        try {
          BiometricPrompt biometricPrompt = new BiometricPrompt(
            getActivity(),
            authenticationCallback
          );

          BiometricPrompt.PromptInfo promptInfo =
            new BiometricPrompt.PromptInfo.Builder()
              .setTitle(call.getString(TITLE, title))
              .setSubtitle(call.getString(SUBTITLE))
              .setDescription(call.getString(REASON))
              .setNegativeButtonText(call.getString(CANCEL_TITLE, "Cancel"))
              .setConfirmationRequired(
                call.getBoolean(CONFIRMATION_REQUIRED, true)
              )
              .build();

          biometricPrompt.authenticate(promptInfo, cryptoObject);
        } catch (Exception e) {
          call.reject("Failed to authenticate", e);
        }
      });
  }

  private void storeEncryptedData(byte[] encryptedData, PluginCall call) {
    Log.d(
      "BiometricAuthNative",
      "Storing encrypted data with key: " + call.getString(DATA_KEY)
    );
    SharedPreferences sharedPreferences = getContext()
      .getSharedPreferences(call.getString(DATA_KEY), Context.MODE_PRIVATE);
    SharedPreferences.Editor editor = sharedPreferences.edit();
    editor.putString(
      call.getString(DATA),
      Base64.encodeToString(encryptedData, Base64.DEFAULT)
    );
    editor.apply();
  }

  private byte[] getEncryptedData(PluginCall call) {
    Log.d(
      "BiometricAuthNative",
      "Retrieving encrypted data with key: " + call.getString(DATA_KEY)
    );
    SharedPreferences sharedPreferences = getContext()
      .getSharedPreferences(call.getString(DATA_KEY), Context.MODE_PRIVATE);
    String encryptedDataString = sharedPreferences.getString(
      call.getString(DATA),
      null
    );
    if (encryptedDataString != null) {
      return Base64.decode(encryptedDataString, Base64.DEFAULT);
    } else {
      Log.e(
        "BiometricAuthNative",
        "No encrypted data found for key: " + call.getString(DATA_KEY)
      );
      throw new RuntimeException("No encrypted data found");
    }
  }

  private void storeIV(byte[] iv, PluginCall call) {
    String ivKey = call.getString(IV_KEY, "defaultIVKey");
    Log.d("BiometricAuthNative", "Storing IV with key: " + ivKey);
    SharedPreferences sharedPreferences = getContext()
      .getSharedPreferences(ivKey, Context.MODE_PRIVATE);
    SharedPreferences.Editor editor = sharedPreferences.edit();
    editor.putString(ivKey, Base64.encodeToString(iv, Base64.DEFAULT));
    editor.apply();
  }

  private byte[] getStoredIV(PluginCall call) {
    String ivKey = call.getString(IV_KEY, "defaultIVKey");
    Log.d("BiometricAuthNative", "Retrieving IV with key: " + ivKey);
    SharedPreferences sharedPreferences = getContext()
      .getSharedPreferences(ivKey, Context.MODE_PRIVATE);
    String ivString = sharedPreferences.getString(ivKey, null);
    if (ivString != null) {
      return Base64.decode(ivString, Base64.DEFAULT);
    } else {
      Log.e("BiometricAuthNative", "No IV found for key: " + ivKey);
      throw new RuntimeException("No IV found");
    }
  }
}
