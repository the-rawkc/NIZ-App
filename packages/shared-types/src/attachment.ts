/**
 * Attachment Protocol & Metadata Contracts
 * Zero server plaintext: Server stores only opaque binary ciphertext.
 * Symmetric keys and integrity hashes are strictly exchanged inside E2EE message envelopes.
 */

export interface EncryptedAttachmentMetadata {
  mediaKey: string;     // Hex-encoded 256-bit symmetric key
  nonce: string;        // Hex-encoded 192-bit nonce
  sha256: string;       // Hex-encoded SHA-256 digest of ciphertext
  mimeType: string;     // Original MIME type (e.g. image/png, application/pdf)
  filename: string;     // Original filename
  byteSize: number;     // Plaintext byte size
}

export interface AttachmentRecord {
  attachmentId: string;
  uploaderPublicId: string;
  recipientPublicId: string;
  sizeBytes: number;
  sha256Ciphertext: string;
  createdAt: string;
  expiresAt: string;
}

export interface AttachmentUploadResponse {
  attachmentId: string;
  downloadUrl: string;
  expiresAt: string;
  sizeBytes: number;
}
