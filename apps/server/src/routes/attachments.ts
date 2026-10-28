import type { FastifyPluginAsync } from 'fastify';
import crypto from 'node:crypto';
import type { IStorageAdapter } from '../storage/interface.js';
import type { AttachmentUploadResponse } from '@niz/shared-types';
import { logger } from '../utils/logger.js';

export const MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024; // 25 MB

export function attachmentRoutes(storage: IStorageAdapter): FastifyPluginAsync {
  return async function (fastify) {
    // POST /v1/attachments/upload
    // INVARIANT: Stores only opaque ciphertext blobs. Zero server knowledge of media keys.
    fastify.post('/v1/attachments/upload', async (req, reply) => {
      const senderPublicId = req.headers['x-sender-public-id'] as string | undefined;
      const recipientPublicId = req.headers['x-recipient-public-id'] as string | undefined;
      const ciphertextSha256 = req.headers['x-ciphertext-sha256'] as string | undefined;

      if (!senderPublicId || !recipientPublicId || !ciphertextSha256) {
        return reply.status(400).send({
          error: 'MISSING_HEADERS',
          message: 'Headers x-sender-public-id, x-recipient-public-id, and x-ciphertext-sha256 are required.',
        });
      }

      if (!Buffer.isBuffer(req.body)) {
        return reply.status(400).send({
          error: 'INVALID_BODY',
          message: 'Attachment body must be application/octet-stream raw binary buffer.',
        });
      }

      const blob = req.body as Buffer;

      // 1. Enforce Max Upload Size Limit (25MB cap)
      if (blob.length > MAX_ATTACHMENT_SIZE) {
        logger.warn('Attachment upload rejected: size cap exceeded', {
          sizeBytes: blob.length,
          maxAllowed: MAX_ATTACHMENT_SIZE,
        });
        return reply.status(413).send({
          error: 'PAYLOAD_TOO_LARGE',
          message: `Attachment exceeds maximum size limit of 25MB (received ${blob.length} bytes).`,
        });
      }

      if (blob.length === 0) {
        return reply.status(400).send({
          error: 'EMPTY_PAYLOAD',
          message: 'Attachment payload cannot be empty.',
        });
      }

      // 2. Transport Integrity Check: SHA-256 of uploaded blob
      const actualSha256 = crypto.createHash('sha256').update(blob).digest('hex');
      if (actualSha256.toLowerCase() !== ciphertextSha256.toLowerCase()) {
        logger.warn('Attachment upload rejected: SHA-256 mismatch');
        return reply.status(400).send({
          error: 'HASH_MISMATCH',
          message: 'Uploaded ciphertext hash does not match x-ciphertext-sha256 header.',
        });
      }

      // 3. Security Invariant: Mutual Approval Default
      // Senders cannot upload attachments for unapproved recipients
      const areConnected = await storage.areConnected(senderPublicId, recipientPublicId);
      if (!areConnected) {
        logger.warn('Attachment upload rejected: unapproved contact relationship', {
          senderPublicId,
          recipientPublicId,
        });
        return reply.status(403).send({
          error: 'RECIPIENT_APPROVAL_REQUIRED',
          message: 'Cannot upload attachments to a contact without mutual approval.',
        });
      }

      const attachmentId = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString();

      await storage.saveAttachment(
        {
          attachmentId,
          uploaderPublicId: senderPublicId,
          recipientPublicId: recipientPublicId,
          sizeBytes: blob.length,
          sha256Ciphertext: actualSha256,
          createdAt: new Date().toISOString(),
          expiresAt,
        },
        blob
      );

      logger.info('Encrypted attachment blob stored', {
        attachmentId,
        sizeBytes: blob.length,
        uploaderPublicId: senderPublicId,
        recipientPublicId: recipientPublicId,
      });

      const response: AttachmentUploadResponse = {
        attachmentId,
        downloadUrl: `/v1/attachments/${attachmentId}`,
        expiresAt,
        sizeBytes: blob.length,
      };

      return reply.status(201).send(response);
    });

    // GET /v1/attachments/:attachmentId
    // Download opaque ciphertext blob with strict participant authorization check
    fastify.get<{ Params: { attachmentId: string } }>(
      '/v1/attachments/:attachmentId',
      async (req, reply) => {
        const { attachmentId } = req.params;
        const requesterPublicId = req.headers['x-requester-public-id'] as string | undefined;

        if (!requesterPublicId) {
          return reply.status(400).send({
            error: 'MISSING_REQUESTER_ID',
            message: 'Header x-requester-public-id is required to download attachments.',
          });
        }

        const item = await storage.getAttachment(attachmentId);
        if (!item) {
          return reply.status(404).send({
            error: 'NOT_FOUND',
            message: 'Attachment not found or expired.',
          });
        }

        // Security check: Only uploader or recipient can download
        if (
          item.record.uploaderPublicId !== requesterPublicId &&
          item.record.recipientPublicId !== requesterPublicId
        ) {
          logger.warn('Attachment download rejected: unauthorized requester', {
            attachmentId,
            requesterPublicId,
          });
          return reply.status(403).send({
            error: 'FORBIDDEN',
            message: 'You are not authorized to download this encrypted attachment.',
          });
        }

        reply.header('Content-Type', 'application/octet-stream');
        reply.header('Content-Length', item.data.length);
        reply.header('X-Ciphertext-Sha256', item.record.sha256Ciphertext);

        return reply.status(200).send(item.data);
      }
    );

    // DELETE /v1/attachments/:attachmentId
    // Participant-driven immediate deletion
    fastify.delete<{ Params: { attachmentId: string } }>(
      '/v1/attachments/:attachmentId',
      async (req, reply) => {
        const { attachmentId } = req.params;
        const requesterPublicId = req.headers['x-requester-public-id'] as string | undefined;

        if (!requesterPublicId) {
          return reply.status(400).send({
            error: 'MISSING_REQUESTER_ID',
            message: 'Header x-requester-public-id is required.',
          });
        }

        const item = await storage.getAttachment(attachmentId);
        if (!item) {
          return reply.status(404).send({
            error: 'NOT_FOUND',
            message: 'Attachment not found.',
          });
        }

        if (
          item.record.uploaderPublicId !== requesterPublicId &&
          item.record.recipientPublicId !== requesterPublicId
        ) {
          return reply.status(403).send({
            error: 'FORBIDDEN',
            message: 'Unauthorized to delete this attachment.',
          });
        }

        await storage.deleteAttachment(attachmentId);
        logger.info('Encrypted attachment deleted', { attachmentId });

        return reply.status(204).send();
      }
    );
  };
}
