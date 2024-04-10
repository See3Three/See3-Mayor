import { z } from 'zod';

export const hexStringSchema = z.string().regex(/^0x[a-fA-F0-9]{64}$/, "Must be a 32-byte hex string starting with 0x");

export type CertificateRequest = {
    'ta-public-key': string,
    'camera-public-key': {
        x: string,
        y: string
    },
    'request-body': {
        token: string,
        mode?: string,
        nonce?: string
    }
};
  
export const certificateRequestSchema = z.object({
      'ta-public-key': hexStringSchema,
      'camera-public-key': z.object({
          x: hexStringSchema,
          y: hexStringSchema
      }),
      'request-body': z.object({
          token: z.string(),
          mode: z.string().optional(),
          nonce: z.string().optional()
      })
});
  
export type CertificateRequestZod = z.infer<typeof certificateRequestSchema>;
  
export function validateCertificateRequest(data: object): CertificateRequest | null {
    try {
        return certificateRequestSchema.parse(data);
    } catch (error) {
        if (error instanceof z.ZodError) {
            console.error("Validation failed:", error.errors);
        } else {
            console.error("An unexpected error occurred:", error);
        }
        return null;
    }
}