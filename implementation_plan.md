# Connect Frontend to Backend

This plan outlines the steps to resolve the routing and connectivity mismatch between the frontend React application and the backend Node.js application.

## Open Questions

> [!WARNING]
> While investigating the connectivity, I noticed that the backend's file upload functionality (`backend/upload/routes/upload.routes.js` and `upload.controller.js`) is currently completely empty, despite the frontend having API calls mapped for it (`/api/files`).
> **Do you want me to just fix the routing connectivity between the existing components, or should I also implement the missing file upload endpoints as part of this integration?**

## Proposed Changes

### Frontend Proxy & API Client Integration

The frontend proxy (`vite.config.js`) splits requests into `/api` and `/auth`. However, the frontend API client is incorrectly prepending `/api` to all requests.

#### [MODIFY] `frontend/src/api/client.js`
- Change `API_BASE_URL` from `'/api'` to `''`. This ensures `/auth/login` uses the `/auth` proxy, and `/api/admin/files` uses the `/api` proxy.

### Backend Router Configuration

The frontend expects data endpoints to be under the `/api` prefix, but the backend is mounting them directly at the root.

#### [MODIFY] `backend/app.js`
- Create an `/api` router group.
- Move `/admin` to `/api/admin`.
- Move `/links` to `/api/links`.
- Leave `/auth` at the root `/auth` to match the frontend proxy behavior.
- Import and mount the (currently empty) upload routes under `/api/files` to match the frontend's `files.api.js` expectations.

## Verification Plan

### Automated/Manual Verification
- Verify that `frontend/src/api/client.js` correctly formats URLs for both `auth` and `api` endpoints.
- Verify that `backend/app.js` listens on the expected `/api/...` and `/auth/...` paths.
- (If approved) Test that file uploading and listing works end-to-end.
