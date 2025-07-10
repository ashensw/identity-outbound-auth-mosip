/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.mosip.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.mosip.exception.MOSIPAuthenticationException;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Utility class that provides cryptographic operations for MOSIP authentication.
 * This class handles encryption, decryption, hashing, signing, and encoding operations
 * required for secure communication with MOSIP identity services.
 * <p>
 * Key features:
 * - AES-GCM symmetric encryption
 * - RSA-OAEP asymmetric encryption
 * - SHA-256 hashing
 * - Digital signatures with RS256
 * - Base64URL encoding/decoding
 * - Certificate thumbprint generation
 * <p>
 * This class is thread-safe and all static methods can be safely called from multiple threads.
 */
public class CryptoUtil implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(CryptoUtil.class);

    private static final String SYMMETRIC_ALGORITHM = "AES";
    private static final int SYMMETRIC_KEY_LENGTH = 256;
    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
    private static final String AES_GCM_CIPHER = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS_128 = 128;

    private static final DateTimeFormatter UTC_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
                    .withZone(ZoneOffset.UTC);

    private static final MessageDigest SHA256_DIGEST;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    static {
        try {
            SHA256_DIGEST = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new ExceptionInInitializerError("SHA-256 not supported: " + e.getMessage());
        }
    }

    private static final Base64.Encoder URL_ENCODER =
            Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER =
            Base64.getUrlDecoder();

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private CryptoUtil() { /* prevent instantiation */ }

    /**
     * Gets current UTC timestamp in ISO-8601 format.
     *
     * @return Current UTC time as formatted string (yyyy-MM-dd'T'HH:mm:ss.SSS'Z')
     */
    public static String getUTCDateTime() {

        return UTC_FORMATTER.format(Instant.now());
    }

    /**
     * Encodes a string to Base64URL format.
     *
     * @param val String to encode
     * @return Base64URL encoded string without padding
     * @throws IllegalArgumentException if input is null
     */
    public static String b64Encode(String val) {

        if (val == null) {
            throw new IllegalArgumentException("value must not be null");
        }
        return URL_ENCODER.encodeToString(val.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encodes a byte array to Base64URL format.
     *
     * @param bytes Byte array to encode
     * @return Base64URL encoded string without padding
     * @throws IllegalArgumentException if input is null
     */
    public static String b64Encode(byte[] bytes) {

        if (bytes == null) {
            throw new IllegalArgumentException("bytes must not be null");
        }
        return URL_ENCODER.encodeToString(bytes);
    }

    /**
     * Decodes a Base64URL encoded string to byte array.
     *
     * @param val Base64URL encoded string
     * @return Decoded byte array
     * @throws IllegalArgumentException if input is null
     */
    public static byte[] b64Decode(String val) {

        if (val == null) {
            throw new IllegalArgumentException("value must not be null");
        }
        return URL_DECODER.decode(val);
    }

    /**
     * Converts a byte array to a hexadecimal string.
     *
     * @param bytes Byte array to convert
     * @return Hexadecimal string representation (uppercase)
     */
    private static String bytesToHex(byte[] bytes) {

        char[] hex = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hex[i * 2] = HEX_ARRAY[v >>> 4];
            hex[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hex);
    }

    /**
     * Calculates SHA-256 hash of a string input and returns as hexadecimal string.
     *
     * @param input String to hash
     * @return Hexadecimal representation of the hash (uppercase)
     * @throws IllegalArgumentException if input is null or empty
     */
    public static String calculateSHA256Hash(String input) {

        if (StringUtils.isEmpty(input)) {
            throw new IllegalArgumentException("input must not be empty");
        }
        byte[] hash = SHA256_DIGEST.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    /**
     * Calculates SHA-256 hash of a byte array.
     *
     * @param input Byte array to hash
     * @return SHA-256 hash as byte array
     * @throws IllegalArgumentException if input is null
     */
    public static byte[] calculateSHA256(byte[] input) {

        if (input == null) {
            throw new IllegalArgumentException("input must not be null");
        }
        return SHA256_DIGEST.digest(input);
    }

    /**
     * Generates a SHA-256 thumbprint from an X.509 certificate.
     *
     * @param cert X.509 certificate
     * @return SHA-256 thumbprint of the certificate as byte array
     */
    public static byte[] getCertificateThumbprint(X509Certificate cert) {

        try {
            return calculateSHA256(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            log.error("Failed to compute certificate thumbprint", e);
            return new byte[0];
        }
    }

    /**
     * Generates a new random AES-256 key for symmetric encryption.
     *
     * @return New AES-256 secret key
     * @throws MOSIPAuthenticationException if key generation fails
     */
    public static SecretKey generateSymmetricKey() throws MOSIPAuthenticationException {

        try {
            KeyGenerator gen = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
            gen.init(SYMMETRIC_KEY_LENGTH, SECURE_RANDOM);
            return gen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            log.error("Error generating AES key", e);
            throw new MOSIPAuthenticationException("Error generating symmetric key", e);
        }
    }

    /**
     * Appends initialization vector to the ciphertext.
     *
     * @param ct Ciphertext
     * @param iv Initialization vector
     * @return Combined array of ciphertext followed by IV
     */
    private static byte[] appendIV(byte[] ct, byte[] iv) {

        byte[] out = Arrays.copyOf(ct, ct.length + iv.length);
        System.arraycopy(iv, 0, out, ct.length, iv.length);
        return out;
    }

    /**
     * Encrypts data using AES-GCM and appends the IV to the ciphertext.
     * Uses 128-bit authentication tag and random IV.
     *
     * @param key AES key for encryption
     * @param data Data to encrypt
     * @return Encrypted data with IV appended
     * @throws MOSIPAuthenticationException if encryption fails
     * @throws IllegalArgumentException if key or data is null
     */
    public static byte[] symmetricEncryptWithAppendedIV(SecretKey key, byte[] data)
            throws MOSIPAuthenticationException {

        if (key == null || data == null) {
            throw new IllegalArgumentException("key/data must not be null");
        }
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM_CIPHER);
            byte[] iv = new byte[cipher.getBlockSize()];
            SECURE_RANDOM.nextBytes(iv);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS_128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] enc = cipher.doFinal(data);
            return appendIV(enc, iv);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                 InvalidKeyException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException e) {
            log.error("AES/GCM encryption failed", e);
            throw new MOSIPAuthenticationException("Symmetric encryption failed", e);
        }
    }

    /**
     * Encrypts data using RSA-OAEP with SHA-256.
     *
     * @param pub RSA public key
     * @param data Data to encrypt
     * @return Encrypted data
     * @throws MOSIPAuthenticationException if encryption fails
     * @throws IllegalArgumentException if key or data is null
     */
    public static byte[] asymmetricEncrypt(PublicKey pub, byte[] data)
            throws MOSIPAuthenticationException {

        if (pub == null || data == null) {
            throw new IllegalArgumentException("publicKey/data must not be null");
        }
        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            OAEPParameterSpec oaep = new OAEPParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
            );
            cipher.init(Cipher.ENCRYPT_MODE, pub, oaep);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                 InvalidKeyException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException e) {
            log.error("RSA-OAEP encryption failed", e);
            throw new MOSIPAuthenticationException("Asymmetric encryption failed", e);
        }
    }

    /**
     * Generates a detached JWS signature for MOSIP request using the authentication
     * certificate and private key. The signature follows the non-encoded payload
     * option (RFC 7797) with RS256 algorithm.
     *
     * @param dataToSign Data to sign
     * @return Detached JWS signature (header..signature)
     * @throws MOSIPAuthenticationException If signature generation fails
     * @throws IllegalArgumentException if data is null or empty
     */
    public static String generateMOSIPRequestSignatureAuthKey(String dataToSign)
            throws MOSIPAuthenticationException {

        if (StringUtils.isEmpty(dataToSign)) {
            throw new IllegalArgumentException("dataToSign must not be empty");
        }

        KeyStoreManager km = KeyStoreManager.getInstance();
        RSAPrivateKey privKey = km.getAuthPrivateKey();
        List<X509Certificate> chain = km.getAuthCertChain();
        if (privKey == null || chain == null || chain.isEmpty()) {
            throw new MOSIPAuthenticationException("Missing authentication key or certificate chain");
        }

        try {
            // 1) leaf cert → Base64URL
            Base64URL leafB64 = Base64URL.encode(chain.get(0).getEncoded());

            // 2) build header
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .customParam("b64", false)
                    .criticalParams(Collections.singleton("b64"))
                    .x509CertChain(Collections.singletonList(leafB64))
                    .build();

            // 3) encode header
            String headerB64 = header.toBase64URL().toString();

            // 4) raw payload bytes
            byte[] payloadBytes = dataToSign.getBytes(StandardCharsets.UTF_8);

            // 5) stitch header + "." + payload
            byte[] headerBytes = headerB64.getBytes(StandardCharsets.UTF_8);
            byte[] signingInput = new byte[headerBytes.length + 1 + payloadBytes.length];
            System.arraycopy(headerBytes, 0, signingInput, 0, headerBytes.length);
            signingInput[headerBytes.length] = (byte) '.';
            System.arraycopy(payloadBytes, 0, signingInput, headerBytes.length + 1, payloadBytes.length);

            // 6) sign
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privKey);
            signer.update(signingInput);
            byte[] sigBytes = signer.sign();

            // 7) Base64URL‐encode signature
            String sigB64Url = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(sigBytes);

            // 8) return detached JWS
            return headerB64 + ".." + sigB64Url;

        } catch (CertificateEncodingException e) {
            log.warn("Certificate encoding failed; omitting x5c header", e);
            throw new MOSIPAuthenticationException("Certificate encoding failed", e);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            log.error("Error signing MOSIP request", e);
            throw new MOSIPAuthenticationException("Error generating MOSIP request signature", e);
        }
    }

    /**
     * Encrypts a request for MOSIP using the default IDA partner certificate.
     *
     * @param request Request data to encrypt
     * @return Encrypted request information
     * @throws MOSIPAuthenticationException If encryption fails
     */
    public static EncryptedRequestInfo encryptRequest(String request)
            throws MOSIPAuthenticationException {

        X509Certificate cert = KeyStoreManager.getInstance().getIdaPartnerCertificate();
        return encryptRequest(request, cert);
    }

    /**
     * Encrypts a request for MOSIP using the specified certificate.
     * The encryption process follows MOSIP's hybrid encryption scheme:
     * 1. Generate random AES session key
     * 2. Encrypt request data with session key (AES-GCM)
     * 3. Calculate and encrypt request hash with session key
     * 4. Encrypt session key with recipient's public key (RSA-OAEP)
     * 5. Calculate certificate thumbprint
     *
     * @param request Request data to encrypt
     * @param cert X.509 certificate of the recipient
     * @return Encrypted request information
     * @throws MOSIPAuthenticationException If encryption fails
     * @throws IllegalArgumentException if request or cert is null
     */
    public static EncryptedRequestInfo encryptRequest(String request, X509Certificate cert)
            throws MOSIPAuthenticationException {

        if (StringUtils.isEmpty(request) || cert == null) {
            throw new IllegalArgumentException("request/cert must not be null");
        }
        try {
            SecretKey sessionKey = generateSymmetricKey();
            byte[] requestBytes = request.getBytes(StandardCharsets.UTF_8);
            byte[] hashRaw = calculateSHA256(requestBytes);
            String hashHex = bytesToHex(hashRaw);

            byte[] encReq = symmetricEncryptWithAppendedIV(sessionKey, requestBytes);
            byte[] encHash = symmetricEncryptWithAppendedIV(
                    sessionKey, hashHex.getBytes(StandardCharsets.UTF_8));
            byte[] encKey = asymmetricEncrypt(cert.getPublicKey(), sessionKey.getEncoded());
            byte[] thumb = getCertificateThumbprint(cert);

            return new EncryptedRequestInfo(
                    b64Encode(encReq),
                    b64Encode(encHash),
                    b64Encode(encKey),
                    b64Encode(thumb)
            );
        } catch (MOSIPAuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error during MOSIP encryption", e);
            throw new MOSIPAuthenticationException("Failed to encrypt MOSIP request", e);
        }
    }

    /**
     * Container class for MOSIP encrypted request information.
     * Holds all the components needed for a complete MOSIP encrypted request:
     * - Encrypted request data
     * - Encrypted request hash
     * - Encrypted session key
     * - Certificate thumbprint
     */
    public static class EncryptedRequestInfo {

        private final String request;
        private final String hash;
        private final String sessionKey;
        private final String thumb;

        /**
         * Constructor for encrypted request information.
         *
         * @param request Base64URL encoded encrypted request
         * @param hash Base64URL encoded encrypted request hash
         * @param sessionKey Base64URL encoded encrypted session key
         * @param thumb Base64URL encoded certificate thumbprint
         */
        public EncryptedRequestInfo(String request, String hash, String sessionKey, String thumb) {

            this.request = request;
            this.hash = hash;
            this.sessionKey = sessionKey;
            this.thumb = thumb;
        }

        /**
         * Gets the Base64URL encoded encrypted request.
         *
         * @return Encoded encrypted request
         */
        public String getBase64UrlEncodedRequest() {

            return request;
        }

        /**
         * Gets the Base64URL encoded encrypted hash.
         *
         * @return Encoded encrypted hash
         */
        public String getBase64UrlEncodedHash() {

            return hash;
        }

        /**
         * Gets the Base64URL encoded encrypted session key.
         *
         * @return Encoded encrypted session key
         */
        public String getBase64UrlEncodedSessionKey() {

            return sessionKey;
        }

        /**
         * Gets the Base64URL encoded certificate thumbprint.
         *
         * @return Encoded certificate thumbprint
         */
        public String getBase64UrlEncodedThumbprint() {

            return thumb;
        }

        /**
         * Gets the encrypted hash (alias for getBase64UrlEncodedHash).
         * Provided for compatibility with MOSIP API expectations.
         *
         * @return Encoded encrypted hash
         */
        public String getHmac() {

            return hash;
        }

        /**
         * Gets the encrypted session key (alias for getBase64UrlEncodedSessionKey).
         * Provided for compatibility with MOSIP API expectations.
         *
         * @return Encoded encrypted session key
         */
        public String getEncryptedSessionKey() {

            return sessionKey;
        }
    }
}
