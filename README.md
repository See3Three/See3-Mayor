# Simple Play Integrity Checker Server Component

## Attribution

We forked Henrik Herzig's SPIC, re-factoring it and porting it to TypeScript to make our this tooling possible. Without SPIC, we'd have spent ages trying to figure out the peculiarities of the Google Play Integrity APIs. Thanks, Henrik!


Mayor is a tool for issuing Camera Trust Signatures, from the perspective of a Trusted Authority. As of currently, it verifies the device and app integrity of an Android App using Google's Play Integrity APIs before issuing a Camera Trust Signature.

## Usage

1. Set-up a `config.json` file with the following fields:

```json
{ "errorLevel": "log",
  "validCertificateSha256Digest": ["VALID_CERTIFICATE_SHA256_DIGEST_HERE"],
  "taPrivateKeyHex": "TA_PRIVATE_KEY_HEX_HERE", // 0xHexString
  "googleCredentials": {
    "type": "service_account",
    "project_id": "PROJECT_ID_HERE",
    "private_key_id": "PRIVATE_KEY_ID_HERE",
    "private_key": "PRIVATE_KEY_HERE",
    "client_email": "CLIENT_EMAIL_HERE",
    "client_id": "CLIENT_ID_HERE",
    "auth_uri": "AUTH_URI_HERE",
    "token_uri": "TOKEN_URI_HERE",
    "auth_provider_x509_cert_url": "AUTH_PROVIDER_X509_CERT_URL_HERE",
    "client_x509_cert_url": "CLIENT_X509_CERT_URL_HERE",
    "universe_domain": "UNIVERSE_DOMAIN_HERE"
  },
  "packageName": "PACKAGE_NAME_HERE",
  "encodedDecryptionKey": "ENCODED_DECRYPTION_KEY_HERE",
  "encodedVerificationKey": "ENCODED_VERIFICATION_KEY_HERE"
}
```
2. `npm run dev`
3. The server should now serve an endpoint for verifying device attestations and producing corresponding trust signatures. The endpoint is `/api/playintegrity/check`.

It uses the standard cryptography defined in the [Specification](../../Specification/Specification.md).

## Data Types

It expects 

```JSON
CertificateRequest = {
    'ta-public-key': string,
    'camera-public-key': {
        x: string, // 0xHexString,
        y: string // 0xHexString
    },
    'request-body': {
        token: string,
        mode?: string,
        nonce?: string
    }
};
```

and returns 

```JSON
trustedAuthoritySignature: {
    "signature-R": {
        x: string, // 0xHexString;
        y: string // 0xHexString;
    };
    "signature-s": string; // 0xHexString;
};
```

## Set up a Google Play Console Project
- Create a new Google Play Console Project
- to obtain the decryption and verification key, navigate within th Google Play Console to **Release** -> **Setup** -> **AppIntegrity** -> **Response encryption**
- click on **Change** and choose **Manage and download my response encryption keys**.
- follow the instructions to create a private-public key pair in order to download the encrypted keys.

## Set up a Google Cloud Project
- Create a new Google Cloud Project
- within Google Play Console, link the new Google Cloud Project to it
- Navigate to **APIs & Services** -> **Enabled APIs & Services** -> **Enable APIs & Services** and enable the Play Integrity API there
- within the Play Integrity API page navigate to **Credentials** -> **Create Credentials** -> **Service Account**. Set a name there and leave the rest on default values
- Navigate to **Keys** -> **Add Key** -> **Create New Key**
Go to Keys -> Add Key -> Create new key. The json that downloads automactially is the json you need for the Environment Variable.

After everything has been set up, run `npm run` to start the server. The server will listen on port 8080 by default.

# Server Console Output
The server will log any incoming requests and the validation it does on them. It will also log any errors that occur.

Example of a valid SafetyNet Request:
```
11/23/2022 9:13:33 PM [INFO] - (SafetyNet) Generated Nonce: 'KKRxe...uisUX'
11/23/2022 9:13:34 PM [INFO] - (SafetyNet) New Client Request (1) processed
11/23/2022 9:13:34 PM [INFO] - Correct Nonce: Correct nonce 'KKRxe...uisUX' received
11/23/2022 9:13:34 PM [INFO] - Attestation: Using BASIC,HARDWARE_BACKED to evaluate device integrity
11/23/2022 9:13:34 PM [INFO] - Attestation: SafetyNet Checks passed
```

Example of an invalid PlayIntegrity Request:
```
11/23/2022 7:45:22 PM [INFO]    - (Play Integrity) Generated Nonce: 'bzZYN...p5TGo'
11/23/2022 7:45:24 PM [INFO]    - (PlayIntegrity) New Client Request (0) processed
11/23/2022 7:45:22 PM [INFO]    - Correct Nonce: Correct nonce 'bzZYN...p5TGo' received
11/23/2022 7:45:22 PM [INFO]    - Attestation: Attested Device has valid requestDetails
11/23/2022 7:45:22 PM [WARNING] - Parsing: appRecognitionVerdict is UNEVALUATED.
11/23/2022 7:45:22 PM [WARNING] - Parsing: Package name is missing
11/23/2022 7:45:22 PM [WARNING] - Parsing: CertificateSha256Digest is missing
11/23/2022 7:45:22 PM [WARNING] - Parsing: Attested Device does not meet requirements: deviceRecognitionVerdict field is empty
11/23/2022 7:45:22 PM [WARNING] - Parsing: appLicensingVerdict is UNEVALUATED
11/23/2022 7:45:22 PM [WARNING] - Attestation: PlayIntegrity Checks failed
```
