import { useState, useCallback } from 'react';
import client from '../api/client.js';

export function useUpload() {
  const [progress, setProgress] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');

  const reset = useCallback(() => {
    setProgress(0);
    setUploading(false);
    setError('');
  }, []);

  const upload = useCallback(async (file) => {
    setUploading(true);
    setProgress(0);
    setError('');

    const formData = new FormData();
    formData.append('file', file); // 'file' is the field name expected by the backend

    try {
      // Sends to the backend, which currently returns 501 Not Implemented 
      // based on our placeholder router.
      const response = await client.post('/api/files/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        onUploadProgress: (progressEvent) => {
          if (progressEvent.total) {
            const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
            setProgress(percentCompleted);
          }
        },
      });
      return response.data;
    } catch (err) {
      // The error message comes from client.js response interceptor
      setError(err.message || 'Upload failed');
      throw err;
    } finally {
      setUploading(false);
    }
  }, []);

  return { upload, progress, uploading, error, reset };
}