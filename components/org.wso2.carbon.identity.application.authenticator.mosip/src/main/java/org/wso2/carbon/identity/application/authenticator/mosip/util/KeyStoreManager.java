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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.mosip.constant.MOSIPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.mosip.exception.MOSIPAuthenticationException;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Manages keystore and certificate operations for MOSIP authentication.
 * This class handles loading certificates and keys required for MOSIP authentication operations.
 */
public class KeyStoreManager {

    private static final Log log = LogFactory.getLog(KeyStoreManager.class);

    // Directory constants - relative to CARBON_HOME
    private static final String SECURITY_DIR = "repository" + File.separator + "resources" + File.separator +
            "security";
    private static final String MOSIP_DIR = "mosip";
    private static final String MOSIP_KEYSTORE_TYPE = "PKCS12";

    // Missing constants for partner key format
    private static final String AUTH_PARTNER = "auth";

    // Files needed in security/mosip directory:
    // 1. mosip_auth.p12 - keystore containing the auth partner private key
    // 2. mpartner-default-wso2-auth.pem - (optional) auth partner certificate in PEM format
    // 3. ida-partner.cer - IDA certificate for encryption

    // Cached resources
    private X509Certificate authCertificate;
    private RSAPrivateKey authPrivateKey;
    private List<X509Certificate> authCertChain;
    private X509Certificate idaPartnerCertificate;

    // Configuration properties - using a single properties object
    private Properties config;
    private final String mosipSecurityPath;

    // Singleton instance
    private static volatile KeyStoreManager instance;

    /**
     * Get the singleton instance of KeyStoreManager
     *
     * @return KeyStoreManager instance
     */
    public static KeyStoreManager getInstance() {

        return getInstance(null);
    }

    /**
     * Get the singleton instance of KeyStoreManager with authenticator properties
     *
     * @param properties The authenticator properties
     * @return KeyStoreManager instance
     */
    public static KeyStoreManager getInstance(Map<String, String> properties) {

        if (instance == null) {
            synchronized (KeyStoreManager.class) {
                if (instance == null) {
                    instance = new KeyStoreManager(properties);
                }
            }
        } else if (properties != null) {
            // If instance exists but new properties are provided, reload the configuration
            synchronized (KeyStoreManager.class) {
                instance.loadConfiguration(properties);

                // Reset the cached resources to force reload with new config
                instance.authCertificate = null;
                instance.authPrivateKey = null;
                instance.authCertChain = null;
                instance.idaPartnerCertificate = null;

                if (log.isDebugEnabled()) {
                    log.debug("KeyStoreManager configuration reloaded with new properties");
                }
            }
        }

        return instance;
    }

    /**
     * Private constructor that initializes the manager and loads configuration
     */
    private KeyStoreManager(Map<String, String> properties) {

        String carbonHome = CarbonUtils.getCarbonHome();
        this.mosipSecurityPath = carbonHome + File.separator + SECURITY_DIR + File.separator + MOSIP_DIR;

        // Create the MOSIP directory if it doesn't exist
        File mosipDir = new File(this.mosipSecurityPath);
        if (!mosipDir.exists()) {
            if (mosipDir.mkdirs()) {
                log.info("Created MOSIP security directory: " + this.mosipSecurityPath);
            } else {
                log.warn("Failed to create MOSIP security directory: " + this.mosipSecurityPath);
            }
        }

        // Initialize configuration
        this.config = new Properties();
        loadConfiguration(properties);
    }

    /**
     * Load configuration properties from authenticator properties or use defaults
     *
     * @param properties The authenticator properties
     */
    private void loadConfiguration(Map<String, String> properties) {

        // Set default values
        config.setProperty(MOSIPAuthenticatorConstants.AUTH_KEYSTORE_FILE,
                MOSIPAuthenticatorConstants.DEFAULT_AUTH_KEYSTORE_FILE);
        config.setProperty(MOSIPAuthenticatorConstants.AUTH_KEYSTORE_ALIAS,
                MOSIPAuthenticatorConstants.DEFAULT_AUTH_KEYSTORE_ALIAS);
        config.setProperty(MOSIPAuthenticatorConstants.AUTH_PEM_FILE,
                MOSIPAuthenticatorConstants.DEFAULT_AUTH_PEM_FILE);
        config.setProperty(MOSIPAuthenticatorConstants.IDA_CERT_FILE,
                MOSIPAuthenticatorConstants.DEFAULT_IDA_CERT_FILE);

        // Use authenticator properties if available
        if (properties != null) {
            if (StringUtils.isNotEmpty(properties.get(MOSIPAuthenticatorConstants.AUTH_KEYSTORE_FILE))) {
                config.setProperty(MOSIPAuthenticatorConstants.AUTH_KEYSTORE_FILE,
                        properties.get(MOSIPAuthenticatorConstants.AUTH_KEYSTORE_FILE));
            }

            if (StringUtils.isNotEmpty(properties.get(MOSIPAuthenticatorConstants.AUTH_KEYSTORE_ALIAS))) {
                config.setProperty(MOSIPAuthenticatorConstants.AUTH_KEYSTORE_ALIAS,
                        properties.get(MOSIPAuthenticatorConstants.AUTH_KEYSTORE_ALIAS));
            }

            if (StringUtils.isNotEmpty(properties.get(MOSIPAuthenticatorConstants.AUTH_PEM_FILE))) {
                config.setProperty(MOSIPAuthenticatorConstants.AUTH_PEM_FILE,
                        properties.get(MOSIPAuthenticatorConstants.AUTH_PEM_FILE));
            }

            if (StringUtils.isNotEmpty(properties.get(MOSIPAuthenticatorConstants.IDA_CERT_FILE))) {
                config.setProperty(MOSIPAuthenticatorConstants.IDA_CERT_FILE,
                        properties.get(MOSIPAuthenticatorConstants.IDA_CERT_FILE));
            }

            if (StringUtils.isNotEmpty(properties.get(MOSIPAuthenticatorConstants.KEYSTORE_PASSWORD))) {
                config.setProperty(MOSIPAuthenticatorConstants.KEYSTORE_PASSWORD,
                        properties.get(MOSIPAuthenticatorConstants.KEYSTORE_PASSWORD));
            }
        }
    }

    /**
     * Load a certificate from a file (PEM or DER format)
     *
     * @param certFilePath Path to the certificate file
     * @return X509Certificate loaded from the file
     * @throws MOSIPAuthenticationException If certificate loading fails
     */
    private X509Certificate loadCertificateFromFile(String certFilePath) throws MOSIPAuthenticationException {

        try (FileInputStream fis = new FileInputStream(certFilePath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
            log.info("Loaded certificate from: " + certFilePath +
                    ", Subject: " + cert.getSubjectX500Principal().getName());
            return cert;
        } catch (Exception e) {
            log.error("Failed to load certificate from file: " + certFilePath, e);
            throw new MOSIPAuthenticationException("Failed to load certificate from file", e);
        }
    }

    /**
     * Get the AUTH certificate
     *
     * @return X509Certificate for AUTH operations
     * @throws MOSIPAuthenticationException If loading fails
     */
    public synchronized X509Certificate getAuthCertificate() throws MOSIPAuthenticationException {

        if (authCertificate == null) {
            loadAuthResources();
        }
        return authCertificate;
    }

    /**
     * Get the AUTH private key
     *
     * @return RSAPrivateKey for AUTH operations
     * @throws MOSIPAuthenticationException If loading fails
     */
    public synchronized RSAPrivateKey getAuthPrivateKey() throws MOSIPAuthenticationException {

        if (authPrivateKey == null) {
            loadAuthResources();
        }
        return authPrivateKey;
    }

    /**
     * Get the AUTH certificate chain
     *
     * @return List of X509Certificate for AUTH certificate chain
     * @throws MOSIPAuthenticationException If loading fails
     */
    public synchronized List<X509Certificate> getAuthCertChain() throws MOSIPAuthenticationException {

        if (authCertChain == null) {
            loadAuthResources();
        }
        return authCertChain;
    }

    /**
     * Load the AUTH partner resources (certificate and private key)
     *
     * @throws MOSIPAuthenticationException If loading fails
     */
    private void loadAuthResources() throws MOSIPAuthenticationException {

        try {
            // Get configuration
            String authPemFile = config.getProperty(MOSIPAuthenticatorConstants.AUTH_PEM_FILE);
            String authKeystoreFile = config.getProperty(MOSIPAuthenticatorConstants.AUTH_KEYSTORE_FILE);
            String authKeystoreAlias = config.getProperty(MOSIPAuthenticatorConstants.AUTH_KEYSTORE_ALIAS);

            // Get keystore password securely
            char[] keystorePassword = getKeystorePassword();

            try {
                // First try loading certificate from PEM if it exists
                String authPemPath = mosipSecurityPath + File.separator + authPemFile;
                File pemFile = new File(authPemPath);
                if (pemFile.exists()) {
                    authCertificate = loadCertificateFromFile(authPemPath);
                    authCertChain = new ArrayList<>();
                    authCertChain.add(authCertificate);
                }

                // Load private key from keystore (required)
                String authKeystorePath = mosipSecurityPath + File.separator + authKeystoreFile;
                File keystoreFile = new File(authKeystorePath);
                if (!keystoreFile.exists()) {
                    throw new MOSIPAuthenticationException("AUTH keystore not found: " + authKeystorePath);
                }

                try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                    KeyStore keyStore = KeyStore.getInstance(MOSIP_KEYSTORE_TYPE);
                    keyStore.load(fis, keystorePassword);

                    if (!keyStore.containsAlias(authKeystoreAlias)) {
                        throw new MOSIPAuthenticationException("Alias not found in keystore: " + authKeystoreAlias);
                    }

                    // Get private key
                    authPrivateKey = (RSAPrivateKey) keyStore.getKey(authKeystoreAlias, keystorePassword);

                    // If certificate not loaded from PEM, get it from keystore
                    if (authCertificate == null) {
                        authCertificate = (X509Certificate) keyStore.getCertificate(authKeystoreAlias);

                        // Create certificate chain from keystore
                        Certificate[] certs = keyStore.getCertificateChain(authKeystoreAlias);
                        authCertChain = new ArrayList<>();
                        for (Certificate cert : certs) {
                            authCertChain.add((X509Certificate) cert);
                        }
                    }
                }

                log.info("Successfully loaded AUTH resources: " + authCertificate.getSubjectX500Principal().getName());

            } finally {
                // Clear the password from memory as soon as we're done with it
                if (keystorePassword != null) {
                    java.util.Arrays.fill(keystorePassword, '\u0000');
                }
            }

        } catch (Exception e) {
            log.error("Error loading AUTH resources", e);
            throw new MOSIPAuthenticationException("Error loading AUTH resources", e);
        }
    }

    /**
     * Get the keystore password securely
     *
     * @return The keystore password as a char array
     */
    private char[] getKeystorePassword() {

        String configuredPassword = config.getProperty(MOSIPAuthenticatorConstants.KEYSTORE_PASSWORD);

        if (StringUtils.isNotBlank(configuredPassword)) {
            // If password is configured, use it (as a char array, not a String)
            return configuredPassword.toCharArray();
        }

        // For production systems, implement a secure password retrieval method
        // This could include:
        // 1. Reading from environment variables
        // 2. Using a secure vault
        // 3. Using a password callback handler

        // For development/testing only - this should be replaced in production
        log.warn("No keystore password configured. Using default password for development. " +
                "This is INSECURE for production environments.");

        // Using a char array rather than a String, so it can be explicitly cleared
        return "changeit".toCharArray();
    }

    /**
     * Get the IDA partner certificate for encryption
     *
     * @return X509Certificate for IDA
     * @throws MOSIPAuthenticationException If loading fails
     */
    public synchronized X509Certificate getIdaPartnerCertificate() throws MOSIPAuthenticationException {

        if (idaPartnerCertificate != null) {
            return idaPartnerCertificate;
        }

        try {
            String idaPartnerCertFile = config.getProperty(MOSIPAuthenticatorConstants.IDA_CERT_FILE);
            String certPath = mosipSecurityPath + File.separator + idaPartnerCertFile;
            File certFile = new File(certPath);

            if (!certFile.exists()) {
                throw new MOSIPAuthenticationException("IDA certificate not found: " + certPath);
            }

            idaPartnerCertificate = loadCertificateFromFile(certPath);
            return idaPartnerCertificate;

        } catch (Exception e) {
            log.error("Error loading IDA certificate", e);
            throw new MOSIPAuthenticationException("Error loading IDA certificate", e);
        }
    }
}
