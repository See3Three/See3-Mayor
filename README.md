# Simple Play Integrity Checker Server Component

## Attribution

We forked Henrik Herzig's SPIC, re-factoring it and porting it to TypeScript to make our this tooling possible. Without SPIC, we'd have spent ages trying to figure out the peculiarities of the Google Play Integrity APIs. Thanks, Henrik!

Henrik's SPIC was <a href="https://opensource.org/licenses/MIT">licensed under MIT.</a>

Server component for SPIC - Simple Play Integrity Checker which receives the encrypted json verdicts, decrypts and verifies them locally on the server or sends them to a Google API for decryption and verification and sends the response back to the client. It is also used for nonce generation as the initial step of attestation.

# Disclaimer
If you plan on using the Play Integrity / SafetyNet Attestation API in your own app, you should propably use a encrypted connection between the server and the client. Local checks on the Android Devices shouldn't be implemented either. Ideally you should pair this API with another authentication method. Be warned: This implementation is just a proof of concept!
# Setup

This server is written in JavaScript using the node package manager. first run `npm install` to install all necessary dependencies. Next you should define the follwing environment variables in a `.env` file at the root of the project:

```
PACKAGE_NAME="org.see3.wink"
GOOGLE_APPLICATION_CREDENTIALS="{
  "project_info": {
    "project_number": "696668379254",
    "project_id": "wink-ab247",
    "storage_bucket": "wink-ab247.appspot.com"
  },
  "client": [
    {
      "client_info": {
        "mobilesdk_app_id": "1:696668379254:android:e05266c43f302191e02757",
        "android_client_info": {
          "package_name": "org.see3.wink"
        }
      },
      "oauth_client": [],
      "api_key": [
        {
          "current_key": "AIzaSyBVAibjj53dkxUbmEIKF1VTiSNVLbX_8gU"
        }
      ],
      "services": {
        "appinvite_service": {
          "other_platform_oauth_client": []
        }
      }
    }
  ],
  "configuration_version": "1"
}"
BASE64_OF_ENCODED_DECRYPTION_KEY="4Lwo/ap5LyA89kY7fRjQAEKJJbu59lfWx1dCzpBdMxI="
BASE64_OF_ENCODED_VERIFICATION_KEY="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH3U6clhbRpUSJonCVIPUg7E9wB3HjaOXEYRsmNzGpCGx4nKxjLSiU5TLctUXalVIQRHjQ+oA7STVmz92qj5sgA=="
```

- `PACKAGE_NAME` android app package name
- `GOOGLE_APPLICATION_CREDENTIALS` JSON contents of the service account from Google Cloud Project. Should be the samed linked to the play console where the android app is maintained (instructions to download the file: See **Set up a google cloud project** below)
- `BASE64_OF_ENCODED_DECRYPTION_KEY` playIntegrity decryption key which can be obtained from the Google Play Console
- `BASE64_OF_ENCODED_VERIFICATION_KEY`playIntegrity verification key which can be obtained from the Google Play Console

A `config.json` file should also be created at the root of the project wit the following entries set:

```json
{
  "errorLevel": "log",
  "validCertificateSha256Digest": [
    "CERTIFICATE1",
    "CERTIFICATE2",
    "..."
  ]
}
```
- `errorLevel` defines the behaviour of the server if a request from an unsecure device is detected
  - `log`: only logs the invalid fields in the verdict and send the verdict back to the client as it is
  - `error`: also logs the invalid fields but returnes an error code to the client

- `validCertificateSha256Digest` tells the server the known Sha256 Certificate so they can be checked against the ones found in the verdict from the client
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


# See3-Mayor
