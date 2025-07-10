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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Manages keystore and certificate operations for MOSIP authentication.
 * Implements Initialization-on-demand holder for thread-safe singleton.
 */
public class KeyStoreManager {

    private static final Log log = LogFactory.getLog(KeyStoreManager.class);

    private static final String SECURITY_DIR = "repository/resources/security";
    private static final String MOSIP_DIR = "mosip";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final char[] DEFAULT_PASSWORD = "changeit".toCharArray();

    private final Path mosipSecurityPath;
    private final Properties config = new Properties();

    // Cached certificate and key references
    private final AtomicReference<X509Certificate> authCertRef = new AtomicReference<>();
    private final AtomicReference<RSAPrivateKey> authKeyRef = new AtomicReference<>();
    private final AtomicReference<List<X509Certificate>> authChainRef = new AtomicReference<>();
    private final AtomicReference<X509Certificate> idaCertRef = new AtomicReference<>();

    /**
     * Private constructor: sets up paths and initial configuration.
     */
    private KeyStoreManager(Map<String, String> properties) {

        this.mosipSecurityPath = Paths.get(CarbonUtils.getCarbonHome(), SECURITY_DIR, MOSIP_DIR);
        ensureDirectoryExists(mosipSecurityPath);
        loadConfiguration(properties);
    }

    /**
     * Holder class for lazy-loaded singleton instance.
     */
    private static class Holder {

        private static final KeyStoreManager INSTANCE = new KeyStoreManager(null);
    }

    /**
     * Retrieve the singleton instance.
     */
    public static KeyStoreManager getInstance() {

        return Holder.INSTANCE;
    }

    /**
     * Retrieve or reload singleton with given properties.
     */
    public static KeyStoreManager getInstance(Map<String, String> properties) {

        KeyStoreManager manager = getInstance();
        if (properties != null) {
            synchronized (manager) {
                manager.loadConfiguration(properties);
                manager.clearCachedResources();
                if (log.isDebugEnabled()) {
                    log.debug("Configuration reloaded with new properties");
                }
            }
        }
        return manager;
    }

    /**
     * Ensure security directory exists, creating it if necessary.
     */
    private void ensureDirectoryExists(Path path) {

        try {
            if (Files.notExists(path)) {
                Files.createDirectories(path);
                log.info("Created MOSIP security directory: " + path);
            }
        } catch (IOException e) {
            log.warn("Failed to create MOSIP security directory: " + path, e);
        }
    }

    /**
     * Load configuration defaults and override with provided properties.
     */
    private void loadConfiguration(Map<String, String> properties) {

        // Default filenames and aliases
        config.setProperty(MOSIPAuthenticatorConstants.AUTH_KEYSTORE_FILE,
                MOSIPAuthenticatorConstants.DEFAULT_AUTH_KEYSTORE_FILE);
        config.setProperty(MOSIPAuthenticatorConstants.AUTH_KEYSTORE_ALIAS,
                MOSIPAuthenticatorConstants.DEFAULT_AUTH_KEYSTORE_ALIAS);
        config.setProperty(MOSIPAuthenticatorConstants.AUTH_PEM_FILE,
                MOSIPAuthenticatorConstants.DEFAULT_AUTH_PEM_FILE);
        config.setProperty(MOSIPAuthenticatorConstants.IDA_CERT_FILE,
                MOSIPAuthenticatorConstants.DEFAULT_IDA_CERT_FILE);
        config.setProperty(MOSIPAuthenticatorConstants.KEYSTORE_PASSWORD, DEFAULT_PASSWORD.toString());

        // Override defaults with any provided properties
        if (properties != null) {
            properties.forEach((key, value) -> {
                if (StringUtils.isNotBlank(value) && config.containsKey(key)) {
                    config.setProperty(key, value);
                }
            });
        }
    }

    /**
     * Clear cached certificates and keys to force reload.
     */
    private void clearCachedResources() {

        authCertRef.set(null);
        authKeyRef.set(null);
        authChainRef.set(null);
        idaCertRef.set(null);
    }

    /**
     * Get the AUTH certificate, loading resources if needed.
     */
    public X509Certificate getAuthCertificate() throws MOSIPAuthenticationException {

        if (authCertRef.get() == null) {
            loadAuthResources();
        }
        return authCertRef.get();
    }

    /**
     * Get the AUTH private key, loading resources if needed.
     */
    public RSAPrivateKey getAuthPrivateKey() throws MOSIPAuthenticationException {

        if (authKeyRef.get() == null) {
            loadAuthResources();
        }
        return authKeyRef.get();
    }

    /**
     * Get the certificate chain for AUTH, loading resources if needed.
     */
    public List<X509Certificate> getAuthCertChain() throws MOSIPAuthenticationException {

        if (authChainRef.get() == null) {
            loadAuthResources();
        }
        return authChainRef.get();
    }

    /**
     * Load AUTH certificates and private key from PEM or keystore.
     * Clears keystorePassword after use to prevent memory retention.
     */
    private synchronized void loadAuthResources() throws MOSIPAuthenticationException {

        char[] keystorePassword = null;
        try {
            Path basePath = mosipSecurityPath;
            keystorePassword = retrieveKeystorePassword();

            // Attempt to load PEM certificate if present
            Path pemPath = basePath.resolve(config.getProperty(MOSIPAuthenticatorConstants.AUTH_PEM_FILE));
            if (Files.exists(pemPath)) {
                X509Certificate cert = loadCertificate(pemPath);
                authCertRef.set(cert);
                authChainRef.set(List.of(cert));
            }

            // Load keystore and extract key/cert
            Path keystorePath = basePath.resolve(config.getProperty(MOSIPAuthenticatorConstants.AUTH_KEYSTORE_FILE));
            if (Files.notExists(keystorePath)) {
                throw new MOSIPAuthenticationException("AUTH keystore not found at " + keystorePath);
            }
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            try (InputStream ksStream = Files.newInputStream(keystorePath)) {
                keyStore.load(ksStream, keystorePassword);
            }
            String alias = config.getProperty(MOSIPAuthenticatorConstants.AUTH_KEYSTORE_ALIAS);
            if (!keyStore.containsAlias(alias)) {
                throw new MOSIPAuthenticationException("Alias not found in keystore: " + alias);
            }

            authKeyRef.set((RSAPrivateKey) keyStore.getKey(alias, keystorePassword));

            if (authCertRef.get() == null) {
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                authCertRef.set(cert);
                Certificate[] chain = keyStore.getCertificateChain(alias);
                List<X509Certificate> certList = new ArrayList<>();
                for (Certificate c : chain) {
                    certList.add((X509Certificate) c);
                }
                authChainRef.set(certList);
            }

            log.info("Loaded AUTH resources for subject " + authCertRef.get().getSubjectX500Principal());
        } catch (Exception e) {
            log.error("Error loading AUTH resources", e);
            throw new MOSIPAuthenticationException("Error loading AUTH resources", e);
        } finally {
            if (keystorePassword != null) {
                Arrays.fill(keystorePassword, '\u0000');
            }
        }
    }

    /**
     * Load an X.509 certificate from given path.
     */
    private X509Certificate loadCertificate(Path certPath) throws MOSIPAuthenticationException {

        try (InputStream inStream = Files.newInputStream(certPath)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(inStream);
            log.info("Loaded certificate from " + certPath + " with subject " +
                    certificate.getSubjectX500Principal());
            return certificate;
        } catch (Exception e) {
            log.error("Failed to load certificate from " + certPath, e);
            throw new MOSIPAuthenticationException("Failed to load certificate from " + certPath, e);
        }
    }

    /**
     * Retrieve keystore password from config or default (development only).
     * Production code should integrate with a secure vault.
     */
    private char[] retrieveKeystorePassword() {

        String configured = config.getProperty(MOSIPAuthenticatorConstants.KEYSTORE_PASSWORD);
        if (StringUtils.isNotBlank(configured)) {
            return configured.toCharArray();
        }
        log.warn("No keystore password configured; using default (insecure) password. " +
                "Integrate with secure vault in production.");
        return DEFAULT_PASSWORD.clone();
    }

    /**
     * Get the IDA partner certificate for encryption, loading if needed.
     */
    public X509Certificate getIdaPartnerCertificate() throws MOSIPAuthenticationException {

        if (idaCertRef.get() == null) {
            synchronized (idaCertRef) {
                if (idaCertRef.get() == null) {
                    Path idaPath = mosipSecurityPath.resolve(
                            config.getProperty(MOSIPAuthenticatorConstants.IDA_CERT_FILE));
                    if (Files.notExists(idaPath)) {
                        throw new MOSIPAuthenticationException("IDA certificate not found at " + idaPath);
                    }
                    idaCertRef.set(loadCertificate(idaPath));
                }
            }
        }
        return idaCertRef.get();
    }
}
