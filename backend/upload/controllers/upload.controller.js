const File = require('../models/file.model');
const { encryptBuffer, decryptBuffer } = require('../services/encrypt.service');
const { saveFile, readFile } = require('../services/storage.service');
const { queueFileForScan } = require('../services/scan.service');
const { auditLog } = require('../../audit/audit.service');
const { verifySignedLink } = require('../../links/signedLink.service');
const { success } = require('../../shared/response');
const { AppError } = require('../../shared/errors');

/**
 * POST /api/files/upload
 */
const uploadFile = async (req, res) => {
  if (!req.file) {
    throw new AppError('No file provided', 'NO_FILE', 400);
  }

  // 1. Encrypt the file buffer in memory
  const { encryptedBuffer, iv } = encryptBuffer(req.file.buffer);

  // 2. Save encrypted buffer to disk
  const encryptedPath = await saveFile(encryptedBuffer);

  // 3. Create database record
  const file = await File.create({
    originalName: req.file.originalname,
    encryptedPath,
    iv,
    mimeType: req.file.mimetype,
    size: req.file.size,
    status: 'pending',
    uploadedBy: req.user.id,
  });

  // 4. Trigger malware scan (async)
  queueFileForScan(file._id).catch(err => console.error('Scan queue error:', err));

  // 5. Audit Log
  await auditLog({ 
    event: 'FILE_UPLOADED', 
    userId: req.user.id, 
    ip: req.ip, 
    meta: { fileId: file._id, name: file.originalName, size: file.size } 
  });

  return success(res, { 
    file: { 
      id: file._id, 
      name: file.originalName, 
      status: file.status 
    } 
  });
};

/**
 * GET /api/files/:id/status
 */
const getStatus = async (req, res) => {
  const file = await File.findOne({ _id: req.params.id, uploadedBy: req.user.id });
  if (!file) throw new AppError('File not found', 'NOT_FOUND', 404);

  return res.json({ status: file.status });
};

/**
 * GET /api/files
 */
const getFiles = async (req, res) => {
  // Only return files that have passed the security scan
  const files = await File.find({ uploadedBy: req.user.id, status: 'approved' }).sort({ createdAt: -1 });
  
  const formattedFiles = files.map(f => ({
    id: f._id,
    name: f.originalName,
    size: f.size,
    status: f.status,
    createdAt: f.createdAt,
    // Add dummy uploadedBy since the frontend table displays it
    uploadedBy: req.user.username || req.user.email, 
  }));

  return success(res, { files: formattedFiles });
};

/**
 * GET /api/files/:id/download
 * Public route (authenticated via HMAC signature in query)
 */
const downloadFile = async (req, res) => {
  const { id } = req.params;
  const { expires, sig, ip } = req.query;

  // 1. Verify signed link
  const result = verifySignedLink(id, { expires, sig, ip }, req.ip);
  if (!result.valid) {
    throw new AppError(`Invalid link: ${result.reason}`, 403, 'LINK_INVALID');
  }

  // 2. Fetch file from DB
  const file = await File.findById(id);
  if (!file) {
    throw new AppError('File not found', 404, 'NOT_FOUND');
  }

  if (file.status !== 'approved') {
    throw new AppError('File is not approved for download', 403, 'FILE_NOT_APPROVED');
  }

  // 3. Read encrypted buffer
  const encryptedBuffer = await readFile(file.encryptedPath);

  // 4. Decrypt
  const decryptedBuffer = decryptBuffer(encryptedBuffer, file.iv);

  // 5. Send file
  res.setHeader('Content-Type', file.mimeType || 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${file.originalName}"`);
  res.send(decryptedBuffer);
};

module.exports = { uploadFile, getStatus, getFiles, downloadFile };
