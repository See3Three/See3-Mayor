import * as jose from "jose";
import crypto from "crypto";
import { google } from "googleapis";
import { Request, Response } from 'express';

import {
  count,
  validCertificateSha256Digest,
  playintegrity,
  googleCredentials,
  packageName,
  encodedVerificationKey,
  encodedDecryptionKey
} from "../index.ts";
import { logEvent, isNonceValid, errorAndExit } from "./shared.ts";

export async function decryptPlayIntegrity(token: string, mode: string, res: Response): Promise<any> {
  if (mode == "server") {
    return await decryptPlayIntegrityServer(token);
  } else if (mode == "google") {
    return await decryptPlayIntegrityGoogle(token).catch((e) => {
      console.log(e);
      res
        .status(400)
        .send({ error: "Google API Error: " + e.message });
      return;
    });
  } else {
    logEvent(
      `WARNING`,
      `Unknown mode (Play Integrity)`,
      `unknown mode '${mode}' requested`
    );
    res.status(400).send({ Error: `Unknown mode ${mode}` });
    return;
  }
}

async function decryptPlayIntegrityGoogle(integrityToken: string): Promise<any> {
  let jwtClient = new google.auth.JWT(
    googleCredentials.client_email,
    undefined,
    googleCredentials.private_key,
    ["https://www.googleapis.com/auth/playintegrity"]
  );

  google.options({ auth: jwtClient });

  const response = await playintegrity.v1.decodeIntegrityToken({
    packageName: packageName,
    requestBody: {
      integrityToken: integrityToken,
    },
  });
  logEvent(
    `INFO`,
    `New Client Request (${count()}) processed`,
    JSON.stringify(response.data.tokenPayloadExternal)
  );

  return response.data.tokenPayloadExternal;
}

async function decryptPlayIntegrityServer(token: string): Promise<any> {
  const decryptionKey = Buffer.from(encodedDecryptionKey, "base64");
  const { plaintext, protectedHeader } = await jose.compactDecrypt(
    token,
    decryptionKey
  );
  const { payload, protectedHeader: Header } = await jose.compactVerify(
    plaintext,
    crypto.createPublicKey(
      "-----BEGIN PUBLIC KEY-----\n" +
        encodedVerificationKey +
        "\n-----END PUBLIC KEY-----"
    )
  );
  const payloadText = new TextDecoder().decode(payload);
  const payloadJson = JSON.parse(payloadText);
  logEvent(
    `INFO`,
    `(PlayIntegrity) New Client Request (${count()}) processed`,
    payloadJson
  );
  return payloadJson;
}

export async function verifyPlayIntegrity(
  decryptedToken: any,
  checkNonce: string,
  res: Response
): Promise<boolean> {
  var requestDetails = decryptedToken?.requestDetails
  if (requestDetails == null) {
    if (errorAndExit(res, `requestDetails not found in received token`))
      return false;
  } else {
    var error = false;
    var nonce = Buffer.from(requestDetails?.nonce, "base64")
      .toString()
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    if (
      checkNonce == "server" &&
      !(await isNonceValid(nonce))
    ) {
      if (errorAndExit(res, `Invalid Nonce`)) return false;
      error = true;
    }

    // Check That Request Is Submitted From The Correct Package
    if (packageName != requestDetails?.requestPackageName) {
      if (errorAndExit(res, `Invalid package name`)) return false;
      error = true;
    }

    // Check That Request Isn't Older Than 10 Seconds 
    if (Date.now() - requestDetails?.timestampMs > 10000) {
      if (errorAndExit(res, `Request too old`)) return false;
      error = true;
    }

    // All Checks Successful, Log This In Console
    if (!error) {
      logEvent(
        `INFO`,
        `Attestation`,
        `Attested Device has valid requestDetails`
      );
    }
  }

  // Check If AppIntegrity Exists In Decrypted Token
  var appIntegrity = decryptedToken?.appIntegrity;
  if (appIntegrity == null) {
    if (errorAndExit(res, `appIntegrity not found in received token`))
      return false;
  } else {
    var error = false;
    var appRecognitionVerdict = appIntegrity?.appRecognitionVerdict;
    if (appRecognitionVerdict != "PLAY_RECOGNIZED") {
      if (
        errorAndExit(res, `appRecognitionVerdict is ${appRecognitionVerdict}.`)
      )
        return false;
      error = true;
    }

    // Check That Package Name Is Correct
    if (packageName != appIntegrity?.packageName) {
      if (errorAndExit(res, `Invalid package name`)) return false;
      error = true;
    }

    // Check That Certificate Sha256 Digest Is Valid
    if (
      appIntegrity?.certificateSha256Digest == null ||
      appIntegrity.certificateSha256Digest.some((e: string) =>
        validCertificateSha256Digest.includes(e)
      )
    ) {
      if (errorAndExit(res, `Invalid certificateSha256Digest`)) return false;
      error = true;
    }
    if (!error) {
      // All Checks Successful, Log This In Console
      logEvent(
        `INFO`,
        `Attestation`,
        `Attested Device has valid requestDetails`
      );
    }
  }

  var deviceIntegrity = decryptedToken?.deviceIntegrity;
  if (deviceIntegrity == null) {
    if (errorAndExit(res, `deviceIntegrity not found in received token`))
      return false;
  } else {
    // Check That Device Recognition Verdict Is Valid
    var deviceRecognitionVerdict = deviceIntegrity?.deviceRecognitionVerdict;
    if (deviceRecognitionVerdict?.includes("MEETS_VIRTUAL_INTEGRITY")){
      if (errorAndExit(res, `Emulator got attested`)) return false;
    } else if (
      deviceRecognitionVerdict?.includes("MEETS_DEVICE_INTEGRITY") ||
      deviceRecognitionVerdict?.includes("MEETS_BASIC_INTEGRITY") ||
      deviceRecognitionVerdict?.includes("MEETS_STRONG_INTEGRITY")
    ) {
      logEvent(
        `INFO`,
        `Attestation`,
        `Attested Device has valid deviceRecognitionVerdict: ${deviceRecognitionVerdict}`
      );
    } else {
      if (
        errorAndExit(
          res,
          `Attested Device doesn't meet requirements. deviceRecognitionVerdict field is empty.`
        )
      )
        return false;
    }
  }

  var accountIntegrity = decryptedToken?.accountDetails;
  if (accountIntegrity == null) {
    if (errorAndExit(res, `accountIntegrity not found in received token`))
      return false;
  } else {
    var appLicensingVerdict = accountIntegrity?.appLicensingVerdict;
    if (appLicensingVerdict != "LICENSED") {
      if (errorAndExit(res, `appLicensingVerdict is ${appLicensingVerdict}`))
        return false;
    } else {
      logEvent(
        `INFO`,
        `Attestation`,
        `Attested Device uses a licensed version of the Android App`
      );
    }
  }
  return true;
}
