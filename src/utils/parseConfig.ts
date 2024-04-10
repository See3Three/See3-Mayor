import { z } from 'zod';
import fs from 'fs';
import path from 'path';

export const googleCredentialsSchema = z.object({
  type: z.string(),
  project_id: z.string(),
  private_key_id: z.string(),
  private_key: z.string(),
  client_email: z.string(),
  client_id: z.string(),
  auth_uri: z.string().url(),
  token_uri: z.string().url(),
  auth_provider_x509_cert_url: z.string().url(),
  client_x509_cert_url: z.string().url(),
  universe_domain: z.string(),
});

export const configSchema = z.object({
  errorLevel: z.enum(["log", "warn", "error"]),
  validCertificateSha256Digest: z.array(z.string()),
  googleCredentials: googleCredentialsSchema,
  packageName: z.string(),
  encodedDecryptionKey: z.string(),
  encodedVerificationKey: z.string(),
});

export interface GoogleCredentials {
  type: string;
  project_id: string;
  private_key_id: string;
  private_key: string;
  client_email: string;
  client_id: string;
  auth_uri: string;
  token_uri: string;
  auth_provider_x509_cert_url: string;
  client_x509_cert_url: string;
  universe_domain: string;
}

export const parseConfigFile = (filePath: string) => {
  try {
    const fileContent = fs.readFileSync(path.resolve(filePath), 'utf8');
    const configObject = JSON.parse(fileContent);
    const parsedConfig = configSchema.parse(configObject);
    console.log("Config parsed successfully:", parsedConfig);
    return parsedConfig;
  } catch (error) {
    console.error("Failed to parse config file:", error);
    throw error;
  }
};
