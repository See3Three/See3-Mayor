import express from "express";
const app = express();
app.use(express.json());

import {
  decryptPlayIntegrity,
  verifyPlayIntegrity,
} from "./utils/playIntegrity";
import { generateNonce, logEvent } from "./utils/shared";
import { parseConfigFile } from "./utils/parseConfig";
import type { GoogleCredentials } from "./utils/parseConfig";
import { validateCertificateRequest } from "./utils/types";
import { hash2, signEddsa, getPublicKey } from "./utils/poseidon";
import { saveNonces, loadNonces } from './utils/storage.ts';

import { google } from "googleapis";
export const playintegrity = google.playintegrity("v1");

// Get Configuration
const filePath = './config.json';
const config = parseConfigFile(filePath);

// Export Configuration
export const certificates: String[] = config.validCertificateSha256Digest;
export const googleCredentials: GoogleCredentials = config.googleCredentials;
export const packageName: string = config.packageName;
export const encodedDecryptionKey: String = config.encodedDecryptionKey;
export const encodedVerificationKey: String = config.encodedVerificationKey;
export const validCertificateSha256Digest: String[] = certificates;
export const errorLevel: String = config.errorLevel;

// Count Requests In Console
let counter = 0;
export function count() {
  return counter++;
}

// Globals
const TRUSTED_AUTHORITY_PRIVATE_KEY = BigInt("0x00");

// Run Server
app.listen(8080, () =>
  console.log(
    "Play Integrity Server Implementation is alive on http://localhost:" + "8080"
  )
);

// Endpoints
app.get("/api/playintegrity/nonce", async (req, res) => {
  const nonce = generateNonce(50);
  const { nonceList, oldNonceList } = await loadNonces();
  nonceList.push(nonce);
  await saveNonces(nonceList, oldNonceList);
  logEvent(`INFO`, `Play Integrity Generated Nonce`, nonce);
  const nonce_base64 = Buffer.from(nonce)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  res.status(200).send(nonce_base64);
  return;
});

/**
 * 'token' is the token the client received from the PlayIntegrity Server in the previous step
 * 'mode' is optional and defaults to 'server'. Can be set to 'google' as well.
 * 'nonce' is optional and defaults to 'server'. Can be set to 'device' when nonce got generated on the device and shouldn't be evaluated on the server.
 */
app.post("/api/playintegrity/check", async (req, res) => {
  const requestBody = validateCertificateRequest(req.body);
  if (!requestBody) {
    res.status(400).send({ Error: "Invalid Request Body" });
    return;
  }

  const token: string = String(requestBody?.['request-body'].token ?? "none");
  const mode: string = String(requestBody?.['request-body'].mode ?? "google");
  const checkNonce: string = String(requestBody?.['request-body'].nonce ?? "server");

  if (token == "none") {
    res.status(400).send({ Error: "No Token Was Provided" });
    return;
  }

  const reportedTaKey = requestBody?.['ta-public-key'];
  const actualTaKey = getPublicKey(TRUSTED_AUTHORITY_PRIVATE_KEY)[0];

  if (reportedTaKey != actualTaKey) {
    res.status(400).send({ Error: "Trusted Authority Public Key Does Not Match" });
    return;
  }

  const decryptedToken = await decryptPlayIntegrity(token, mode, res);
  const isTokenValid = await verifyPlayIntegrity(decryptedToken, checkNonce, res);

  if (isTokenValid) {
    const cameraPublicKey = requestBody?.['camera-public-key']!;
    const cameraPublicKeyHash = hash2([BigInt(cameraPublicKey.x), BigInt(cameraPublicKey.y)]);
    const trustedAuthoritySignature = signEddsa(cameraPublicKeyHash, TRUSTED_AUTHORITY_PRIVATE_KEY);
    res.status(200).send(trustedAuthoritySignature);
  }
});
