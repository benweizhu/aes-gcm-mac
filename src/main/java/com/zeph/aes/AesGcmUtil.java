package com.zeph.aes;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

public class AesGcmUtil {

  private SecretKey getSecretKey(byte[] key) {
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(key);
    SecretKey secretKey = new SecretKeySpec(key, "AES");
    return secretKey;
  }

  private Cipher initCipher(SecretKey secretKey, byte[] iv) throws Exception {
    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
    return cipher;
  }

  private byte[] getCipherText(Cipher cipher, String plainText) throws Exception {
    return cipher.doFinal(plainText.getBytes());
  }

  private String contactAndBase64Encoding(byte[] iv, byte[] cipherText) {
    ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + cipherText.length);
    byteBuffer.putInt(iv.length);
    byteBuffer.put(iv);
    byteBuffer.put(cipherText);
    byte[] cipherMessage = byteBuffer.array();
    return Base64.getEncoder().encodeToString(cipherMessage);
  }

  private String encryptPlainText(String plainText, SecretKey secretKey) throws Exception {
    byte[] iv = new byte[12];
    Cipher cipher = initCipher(secretKey, iv);
    byte[] cipherText = getCipherText(cipher, plainText);
    return contactAndBase64Encoding(iv, cipherText);
  }

  private String decryptSecretText(String secretText, SecretKey aes) throws Exception {
    byte[] cipherMessage = Base64.getDecoder().decode(secretText);
    ByteBuffer byteBuffer = ByteBuffer.wrap(cipherMessage);
    int ivLength = byteBuffer.getInt();
    if (ivLength < 12 || ivLength >= 16) {
      throw new IllegalArgumentException("invalid iv length");
    }
    byte[] iv = new byte[ivLength];
    byteBuffer.get(iv);
    byte[] cipherText = new byte[byteBuffer.remaining()];
    byteBuffer.get(cipherText);
    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, aes, new GCMParameterSpec(128, iv));
    byte[] plainText = cipher.doFinal(cipherText);
    return new String(plainText);
  }

  public static void main(String[] args) throws Exception {
    AesGcmUtil aesGcmUtil = new AesGcmUtil();
    SecretKey secretKey = aesGcmUtil.getSecretKey(new byte[16]);
    String plainText = "Hello World";
    System.out.println(plainText);
    String secretText = aesGcmUtil.encryptPlainText(plainText, secretKey);
    System.out.println(secretText);
    String decryptPlainText = aesGcmUtil.decryptSecretText(secretText, secretKey);
    System.out.println(decryptPlainText);
  }
}
