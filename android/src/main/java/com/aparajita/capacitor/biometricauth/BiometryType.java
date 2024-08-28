package com.aparajita.capacitor.biometricauth;

public enum BiometryType {
  NONE(0),
  FINGERPRINT(1),
  FACE(2),
  IRIS(3);

  private final int type;

  BiometryType(int type) {
    this.type = type;
  }

  public int getType() {
    return type;
  }
}
