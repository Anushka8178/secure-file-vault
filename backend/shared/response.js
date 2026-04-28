const success = (res, data = null, message = 'Success', statusCode = 200) => {
  return res.status(statusCode).json({ ok: true, message, data });
};

const created = (res, data = null, message = 'Created') => {
  return success(res, data, message, 201);
};

const error = (res, message = 'Error', statusCode = 500, code = 'ERROR', details = null) => {
  const payload = { ok: false, code, message };
  if (details) payload.details = details;
  return res.status(statusCode).json(payload);
};

module.exports = { success, created, error };
