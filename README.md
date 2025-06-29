# WSO2 Identity Server MOSIP Authenticator

This is a federated authenticator for WSO2 Identity Server that enables authentication through the MOSIP (Modular Open Source Identity Platform) ID Authentication API. It allows WSO2 IS to integrate with MOSIP as an identity provider, enabling various MOSIP authentication methods.

## Features

- **MOSIP Digital ID Authentication**: Authenticate users using their MOSIP Unique Identification Number (UIN)
- **Multi-Factor Authentication**: Support for multiple authentication methods:
  - UIN-based authentication
  - OTP authentication (via email and phone)
- **KYC Data Retrieval**: Fetch user profile information during authentication
- **Just-in-Time Provisioning**: Automatically provision users in WSO2 IS during authentication
- **Flexible Configuration**: Easily configure the authenticator through the WSO2 IS admin console

## Prerequisites

- WSO2 Identity Server 7.x or higher
- Java 11 or higher
- Maven 3.8.x or higher
- MOSIP ID Authentication (IDA) service access credentials:
  - MISP License Key
  - Authentication Partner ID
  - Partner ID
  - OIDC Client ID (API Key for MOSIP)
  - Domain URI

## Building from Source

1. Clone the repository:
   ```
   git clone https://github.com/wso2-extensions/identity-outbound-auth-mosip.git
   ```

2. Build the project using Maven:
   ```
   cd identity-outbound-auth-mosip
   mvn clean install
   ```

3. The built JAR file can be found at `target/identity-outbound-auth-mosip-1.0.0.jar`

## Deployment

1. Copy the built JAR file to the `<IS_HOME>/repository/components/dropins` directory.

2. Create the required keystore directory structure:
   ```
   mkdir -p <IS_HOME>/repository/resources/security/mosip
   ```

3. Place the following files in the `<IS_HOME>/repository/resources/security/mosip` directory:
   - `mosip_auth.p12`: Keystore containing the authentication partner's private key
   - `mpartner-default-wso2-auth.pem`: (Optional) Authentication partner certificate in PEM format
   - `ida-partner.cer`: IDA certificate for encryption

4. Copy the JSP files to the authentication endpoint webapp:
   ```
   cp src/main/resources/jsp/mosip_login.jsp <IS_HOME>/repository/deployment/server/webapps/authenticationendpoint/
   cp src/main/resources/jsp/mosip_otp.jsp <IS_HOME>/repository/deployment/server/webapps/authenticationendpoint/
   ```

5. Copy the connection templates to the identity extensions folder:
   ```
   mkdir -p <IS_HOME>/repository/resources/identity/extensions/connections/mosip
   cp -r src/main/resources/artifacts/mosip/* <IS_HOME>/repository/resources/identity/extensions/connections/mosip/
   ```

6. Configure the authenticator parameters (see Configuration section).

7. Restart the WSO2 Identity Server.

## Configuration

### 1. Configuring the authenticator in deployment.toml

Add the following configuration to your `<IS_HOME>/repository/conf/deployment.toml` file to enable the authenticator and configure the keystore parameters:

```toml
[authentication.authenticator.mosip]
name = "MOSIPAuthenticator"
enable = true

# KeyStore configurations (secured via deployment.toml, not exposed in UI)
parameters.authKeystoreFile = "mosip_auth.p12"
parameters.authKeystoreAlias = "mosip-auth"
parameters.authPemFile = "mpartner-default-wso2-auth.pem"
parameters.idaCertFile = "ida-partner.cer"
parameters.keystorePassword = "your-keystore-password"
```

**Important Notes:**
- The keystore-related parameters (`authKeystoreFile`, `authKeystoreAlias`, etc.) are only configurable through the deployment.toml file and are not exposed in the UI for security reasons.
- All keystore files must be placed in the `<IS_HOME>/repository/resources/security/mosip` directory.
- Business-related parameters like baseUrl, mispLicenseKey, etc. are configured through the Management Console UI, not in deployment.toml.

### 2. Configuring the MOSIP Authenticator in the Management Console

1. Log in to the WSO2 IS Management Console.

2. Navigate to **Identity Providers** > **Add**.

3. Enter a name for the identity provider (e.g., "MOSIP") and expand the **Federated Authenticators** section.

4. Find and expand the **MOSIP Authenticator** configuration.

5. Provide the following mandatory configuration parameters:
   - **Base URL**: Base URL of the MOSIP ID Authentication API endpoint
   - **MISP License Key**: MISP License Key for authentication
   - **Partner ID**: Your organization's Partner ID
   - **OIDC Client ID**: Client ID for OIDC authentication
   - **Domain URI**: URI of your domain
   - **Environment**: MOSIP environment (default: Staging)

6. Click **Register** to save the configuration.

### 3. Adding MOSIP as an Identity Provider in Authentication Flows

1. Navigate to **Service Providers** > **List** and select your service provider.

2. Go to **Local & Outbound Authentication Configuration**.

3. Configure the authentication step to use the MOSIP identity provider.

4. Save the configuration.

## Certificate and Keystore Management

### Required Certificates and Keys

1. **Authentication Partner Certificate and Private Key**:
   - Format: PKCS12 keystore (`.p12` file)
   - Default filename: `mosip_auth.p12`
   - Purpose: Used for signing requests to MOSIP IDA services

2. **IDA Partner Certificate**:
   - Format: X.509 certificate (`.cer` file)
   - Default filename: `ida-partner.cer`
   - Purpose: Used for encrypting requests to MOSIP IDA services

### Generating and Managing Certificates

1. **Creating the Authentication Partner Keystore**:
   ```
   keytool -genkeypair -alias mosip-auth -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore mosip_auth.p12 -validity 3650
   ```

2. **Exporting the Authentication Partner Certificate** (if needed):
   ```
   keytool -exportcert -alias mosip-auth -keystore mosip_auth.p12 -file mpartner-default-wso2-auth.pem -rfc
   ```

3. **Importing the IDA Certificate** (provided by MOSIP):
   ```
   keytool -importcert -alias ida-partner -file ida-partner.cer -keystore truststore.jks
   ```

## Authentication Flow

The MOSIP Authenticator follows this general flow:

1. User is redirected to the MOSIP login page.
2. User enters their MOSIP UIN.
3. The authenticator communicates with the MOSIP IDA service for verification.
4. For OTP authentication:
   - The system sends OTP to the user's registered email or phone
   - User enters the received OTP
   - The authenticator verifies the OTP with MOSIP IDA
5. Upon successful authentication, user profile data is retrieved via KYC exchange.
6. User is authenticated in WSO2 IS and redirected to the service provider.

## Claim Mapping Configuration

To map MOSIP user attributes to local claims:

1. Navigate to the identity provider configuration.
2. Expand the **Claim Configuration** section.
3. Set **Claim mapping dialect** to **Define Custom Claim Dialect**.
4. Add mappings for MOSIP attributes to local claims. Common mappings include:
   - `fullName` → `http://wso2.org/claims/fullname`
   - `email` → `http://wso2.org/claims/emailaddress`
   - `phone` → `http://wso2.org/claims/telephone`
   - `gender` → `http://wso2.org/claims/gender`
   - `dateOfBirth` → `http://wso2.org/claims/dob`
   - `address` → `http://wso2.org/claims/addresses`

## Troubleshooting

### Common Issues and Solutions

1. **Certificate Errors**:
   - Ensure certificates are in the correct format and location
   - Verify the keystore password in the deployment.toml file

2. **Authentication Failures**:
   - Check the MOSIP IDA service endpoint is accessible
   - Verify the MISP License Key and Partner IDs are correct

3. **OTP Issues**:
   - Confirm that the user's email and phone are registered in MOSIP
   - Check if OTP channels are properly configured

### Enabling Debug Logs

Add the following to `<IS_HOME>/repository/conf/log4j2.properties`:

```
logger.org-wso2-carbon-identity-outbound-auth-mosip.name = org.wso2.carbon.identity.application.authenticator.mosip
logger.org-wso2-carbon-identity-outbound-auth-mosip.level = DEBUG
```

## Security Considerations

1. **Keystore Password Protection**:
   - The keystore password is stored in the deployment.toml file
   - Ensure proper file permissions to restrict access to deployment.toml
   - Consider using a secure vault for production environments

2. **Certificate Management**:
   - Regularly rotate certificates according to your security policy
   - Keep private keys secure and limit access to the security directory

3. **Data Protection**:
   - All communications with MOSIP IDA services use encrypted channels
   - Sensitive user data is encrypted during transmission

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
