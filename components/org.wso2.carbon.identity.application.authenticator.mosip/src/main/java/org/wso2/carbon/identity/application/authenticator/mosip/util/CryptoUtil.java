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
import org.apache.commons.codec.digest.DigestUtils;
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
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
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
import javax.crypto.spec.SecretKeySpec;

/**
 * Cryptographic utility class for MOSIP authentication.
 * This class handles encryption, decryption, hashing, and signature generation.
 */
public class CryptoUtil implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(CryptoUtil.class);

    // ========== Algorithm and key constants ==========
    private static final String SYMMETRIC_ALGORITHM = "AES";
    private static final int SYMMETRIC_KEY_LENGTH = 256;
    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
    private static final String AES_GCM_CIPHER = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS_128 = 128;

    // ========== Date format constants ==========
    private static final String UTC_DATETIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

    // ========== Encoding and utility constants ==========
    private static final java.util.Base64.Encoder urlSafeEncoder = java.util.Base64.getUrlEncoder().withoutPadding();
    private static final java.util.Base64.Decoder urlSafeDecoder = java.util.Base64.getUrlDecoder();
    private static final char[] HEX_ARRAY_UPPERCASE = "0123456789ABCDEF".toCharArray();

    // ========== Shared secure random instance ==========
    private static SecureRandom sharedSecureRandom;

    /**
     * Private constructor to prevent instantiation
     */
    private CryptoUtil() {
        // Private constructor to prevent instantiation
    }

    //--------------------------------------------------------------------------
    // SECTION 1: Core Utility Methods
    //--------------------------------------------------------------------------

    /**
     * Get current UTC date/time in MOSIP format
     *
     * @return Formatted UTC date/time string
     */
    public static String getUTCDateTime() {

        return ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern(UTC_DATETIME_PATTERN));
    }

    /**
     * Base64URL encode a string
     *
     * @param value String to encode
     * @return Base64URL-encoded string
     */
    public static String b64Encode(String value) {

        return urlSafeEncoder.encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Base64URL encode byte array
     *
     * @param bytes Byte array to encode
     * @return Base64URL-encoded string
     */
    public static String b64Encode(byte[] bytes) {

        return urlSafeEncoder.encodeToString(bytes);
    }

    /**
     * Decode a Base64URL-encoded string
     *
     * @param value Base64URL-encoded string
     * @return Decoded byte array
     */
    public static byte[] b64Decode(String value) {

        return urlSafeDecoder.decode(value);
    }

    /**
     * Convert byte array to uppercase hexadecimal string
     *
     * @param bytes Byte array to convert
     * @return Uppercase hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {

        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY_UPPERCASE[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY_UPPERCASE[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Get a shared SecureRandom instance
     *
     * @return Initialized SecureRandom instance
     */
    private static SecureRandom getSecureRandom() {

        if (sharedSecureRandom == null) {
            sharedSecureRandom = new SecureRandom();
        }
        return sharedSecureRandom;
    }

    //--------------------------------------------------------------------------
    // SECTION 2: Hash Functions
    //--------------------------------------------------------------------------

    /**
     * Calculate SHA-256 hash of a string
     *
     * @param input Input string
     * @return Hexadecimal SHA-256 hash
     */
    public static String calculateSHA256Hash(String input) {

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to calculate SHA-256 hash", e);
            return "";
        }
    }

    /**
     * Calculate SHA-256 hash of byte array
     *
     * @param input Input byte array
     * @return SHA-256 hash as byte array
     */
    public static byte[] calculateSHA256(byte[] input) {

        return DigestUtils.sha256(input);
    }

    /**
     * Calculate certificate thumbprint (SHA-256)
     *
     * @param certificate X.509 certificate
     * @return SHA-256 thumbprint
     */
    public static byte[] getCertificateThumbprint(Certificate certificate) {

        try {
            return calculateSHA256(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            log.error("Failed to get certificate thumbprint", e);
            return new byte[]{};
        }
    }

    //--------------------------------------------------------------------------
    // SECTION 3: Symmetric Encryption (AES)
    //--------------------------------------------------------------------------

    /**
     * Generate a new AES symmetric key for session encryption
     *
     * @return Generated secret key
     * @throws MOSIPAuthenticationException If key generation fails
     */
    public static SecretKey generateSymmetricKey() throws MOSIPAuthenticationException {

        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
            keyGen.init(SYMMETRIC_KEY_LENGTH);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            log.error("Error generating symmetric key", e);
            throw new MOSIPAuthenticationException("Error generating symmetric key", e);
        }
    }

    /**
     * Generate initialization vector for GCM encryption
     *
     * @param blockSize The block size for the cipher
     * @return Randomly generated IV bytes
     */
    private static byte[] generateIVForGCMEncryption(int blockSize) {

        byte[] byteIV = new byte[blockSize];
        getSecureRandom().nextBytes(byteIV);
        return byteIV;
    }

    /**
     * Perform symmetric encryption using AES/GCM and append the IV to the encrypted data
     *
     * @param key  The secret key
     * @param data The data to encrypt
     * @return Encrypted data with appended IV
     * @throws MOSIPAuthenticationException If encryption fails
     */
    public static byte[] symmetricEncryptWithAppendedIV(SecretKey key, byte[] data)
            throws MOSIPAuthenticationException {
        // 1. Get a Cipher for AES/GCM/NoPadding
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(AES_GCM_CIPHER);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new MOSIPAuthenticationException(
                    "Failed to get Cipher instance for " + AES_GCM_CIPHER, e);
        }

        try {
            // 2. Generate a random IV of the cipher's block size
            byte[] randomIV = generateIVForGCMEncryption(cipher.getBlockSize());

            // 3. Prepare the AES key specification
            SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), SYMMETRIC_ALGORITHM);

            // 4. Configure GCM with a 128-bit authentication tag and the random IV
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS_128, randomIV);

            // 5. Initialize cipher for encryption with key + GCM parameters
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            // 6. Encrypt the input data
            byte[] encryptedData = cipher.doFinal(data);

            // 7. Combine the ciphertext and IV for transport
            byte[] output = new byte[encryptedData.length + randomIV.length];
            System.arraycopy(encryptedData, 0, output, 0, encryptedData.length);
            System.arraycopy(randomIV, 0, output, encryptedData.length, randomIV.length);

            return output;
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new MOSIPAuthenticationException(
                    "Symmetric encryption failed (" + AES_GCM_CIPHER + " with appended IV)", e);
        }
    }

    //--------------------------------------------------------------------------
    // SECTION 4: Asymmetric Encryption (RSA)
    //--------------------------------------------------------------------------

    /**
     * Encrypt data using asymmetric encryption (RSA-OAEP)
     *
     * @param publicKey Public key for encryption
     * @param data      Data to encrypt
     * @return Encrypted data
     * @throws MOSIPAuthenticationException If encryption fails
     */
    public static byte[] asymmetricEncrypt(PublicKey publicKey, byte[] data) throws MOSIPAuthenticationException {

        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            OAEPParameterSpec oaepParams =
                    new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
            return cipher.doFinal(data);
        } catch (Exception e) {
            log.error("Error encrypting data with asymmetric key", e);
            throw new MOSIPAuthenticationException("Error encrypting data with asymmetric key", e);
        }
    }

    //--------------------------------------------------------------------------
    // SECTION 5: Digital Signatures
    //--------------------------------------------------------------------------

    /**
     * Generate MOSIP request signature using the AUTH certificate and private key
     *
     * @param dataToSign Data to sign
     * @return Detached JWS signature
     * @throws MOSIPAuthenticationException If signature generation fails
     */
    public static String generateMosipRequestSignatureAuthKey(String dataToSign) throws MOSIPAuthenticationException {

        try {
            // Get resources from KeyStoreManager
            KeyStoreManager keyManager = KeyStoreManager.getInstance();
            RSAPrivateKey authPrivateKey = keyManager.getAuthPrivateKey();
            List<X509Certificate> authCertChain = keyManager.getAuthCertChain();

            if (log.isDebugEnabled()) {
                log.debug("Generating signature for request data");
            }

            // Build the JWS header
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256);

            // Set detached payload flag (requirement for MOSIP)
            headerBuilder.customParam("b64", false);
            headerBuilder.criticalParams(new HashSet<>(Collections.singletonList("b64")));

            // Add x5c certificate chain if available
            if (authCertChain != null && !authCertChain.isEmpty()) {
                try {
                    // Use only the first certificate (end-entity) for x5c
                    X509Certificate endEntityCert = authCertChain.get(0);
                    List<com.nimbusds.jose.util.Base64> x5cCerts = new ArrayList<>();
                    x5cCerts.add(com.nimbusds.jose.util.Base64.encode(endEntityCert.getEncoded()));
                    headerBuilder.x509CertChain(x5cCerts);
                } catch (CertificateEncodingException e) {
                    log.warn("Certificate encoding issue - proceeding without x5c header", e);
                }
            }

            // Build the header and prepare input for signing
            JWSHeader header = headerBuilder.build();
            byte[] dataToSignBytes = dataToSign.getBytes(StandardCharsets.UTF_8);

            // Create the JWS signing input (header.payload)
            byte[] jwsHeaderBytes = header.toBase64URL().toString().getBytes(StandardCharsets.UTF_8);
            byte[] jwsSignInput = new byte[jwsHeaderBytes.length + 1 + dataToSignBytes.length];
            System.arraycopy(jwsHeaderBytes, 0, jwsSignInput, 0, jwsHeaderBytes.length);
            jwsSignInput[jwsHeaderBytes.length] = (byte) '.';
            System.arraycopy(dataToSignBytes, 0, jwsSignInput, jwsHeaderBytes.length + 1, dataToSignBytes.length);

            // Sign using the private key
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(authPrivateKey);
            signer.update(jwsSignInput);
            byte[] signatureBytes = signer.sign();

            // Create the detached JWS format (header..signature)
            String signatureBase64Url = urlSafeEncoder.encodeToString(signatureBytes);
            String detachedSignature = header.toBase64URL().toString() + ".." + signatureBase64Url;

            if (log.isDebugEnabled()) {
                log.debug("Generated MOSIP detached JWS signature");
            }

            return detachedSignature;
        } catch (Exception e) {
            log.error("Error generating MOSIP request signature", e);
            throw new MOSIPAuthenticationException("Error generating MOSIP request signature", e);
        }
    }

    //--------------------------------------------------------------------------
    // SECTION 6: MOSIP Integrated Encryption
    //--------------------------------------------------------------------------

    /**
     * Encrypt a request for MOSIP authentication
     *
     * @param request The request to encrypt
     * @return EncryptedRequestInfo containing the encrypted parts
     * @throws MOSIPAuthenticationException If encryption fails
     */
    public static EncryptedRequestInfo encryptRequest(String request) throws MOSIPAuthenticationException {

        try {
            // Get IDA certificate for encryption
            X509Certificate cert = KeyStoreManager.getInstance().getIdaPartnerCertificate();
            return encryptRequest(request, cert);
        } catch (Exception e) {
            log.error("Error during MOSIP encryption", e);
            if (e instanceof MOSIPAuthenticationException) {
                throw (MOSIPAuthenticationException) e;
            }
            throw new MOSIPAuthenticationException("Failed to encrypt MOSIP request", e);
        }
    }

    /**
     * Encrypt a request for MOSIP authentication
     *
     * @param request The request to encrypt
     * @param cert    The certificate to use for encryption
     * @return EncryptedRequestInfo containing the encrypted parts
     * @throws MOSIPAuthenticationException If encryption fails
     */
    public static EncryptedRequestInfo encryptRequest(String request, X509Certificate cert)
            throws MOSIPAuthenticationException {

        try {
            // Generate a new AES-256 session key
            final SecretKey sessionKey = generateSymmetricKey();

            // Convert the plaintext request to UTF-8 bytes
            byte[] requestBytes = request.getBytes(StandardCharsets.UTF_8);

            // Compute SHA-256 hash of the request for integrity
            byte[] requestHashRaw = calculateSHA256(requestBytes);
            String hash = bytesToHex(requestHashRaw);

            // Encrypt payload with AES/GCM (IV appended)
            byte[] encryptedRequest = symmetricEncryptWithAppendedIV(sessionKey, requestBytes);
            byte[] encryptedHmac = symmetricEncryptWithAppendedIV(sessionKey, hash.getBytes(StandardCharsets.UTF_8));

            // Encrypt the session key with RSA/OAEP
            byte[] encryptedKey = asymmetricEncrypt(cert.getPublicKey(), sessionKey.getEncoded());

            // Compute the certificate's SHA-256 thumbprint
            byte[] thumbprint = getCertificateThumbprint(cert);

            // Base64URL-encode all parts
            String req64 = b64Encode(encryptedRequest);
            String hmac64 = b64Encode(encryptedHmac);
            String key64 = b64Encode(encryptedKey);
            String thumb64 = b64Encode(thumbprint);

            return new EncryptedRequestInfo(req64, hmac64, key64, thumb64);
        } catch (Exception e) {
            log.error("Error during MOSIP encryption", e);
            if (e instanceof MOSIPAuthenticationException) {
                throw (MOSIPAuthenticationException) e;
            }
            throw new MOSIPAuthenticationException("Failed to encrypt MOSIP request", e);
        }
    }

    /**
     * Class to store encrypted request information
     */
    public static class EncryptedRequestInfo {

        private final String base64UrlEncodedRequest;
        private final String base64UrlEncodedHash;
        private final String base64UrlEncodedSessionKey;
        private final String base64UrlEncodedThumbprint;

        public EncryptedRequestInfo(String request, String hash, String sessionKey, String thumbprint) {

            this.base64UrlEncodedRequest = request;
            this.base64UrlEncodedHash = hash;
            this.base64UrlEncodedSessionKey = sessionKey;
            this.base64UrlEncodedThumbprint = thumbprint;
        }

        public String getBase64UrlEncodedRequest() {

            return base64UrlEncodedRequest;
        }

        public String getBase64UrlEncodedHash() {

            return base64UrlEncodedHash;
        }

        public String getBase64UrlEncodedSessionKey() {

            return base64UrlEncodedSessionKey;
        }

        public String getBase64UrlEncodedThumbprint() {

            return base64UrlEncodedThumbprint;
        }

        // Additional accessor methods to match method calls in MOSIPAuthService
        public String getHmac() {

            return base64UrlEncodedHash;
        }

        public String getEncryptedSessionKey() {

            return base64UrlEncodedSessionKey;
        }
    }
}
