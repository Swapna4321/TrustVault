# API authorization

All routes other than `/`, `/health`, `/app`, `/static/*`, `/register`, and `/login` require `Authorization: Bearer <token>`. Authenticated requests reload the account and active status from PostgreSQL.

| Method and path | Allowed caller | Server-side rule |
|---|---|---|
| `GET /`, `GET /health`, `GET /app` | Public | Health/UI only |
| `POST /register` | Public | Always creates a viewer |
| `POST /login` | Public | Active account and valid password required |
| `GET /users/me` | Any active role | Current database identity |
| `GET /dashboard` | Admin, owner, viewer | Authenticated only |
| `GET /admin/dashboard` | Admin | Admin role |
| `GET /owner/dashboard` | Owner | Owner role |
| `GET /viewer/dashboard` | Viewer | Viewer role |
| `POST /documents/upload` | Owner | New document owned by caller; validates extension, category, emptiness, size |
| `GET /documents` | Any active role | Owned documents and current `READ`/`EDIT` grants only |
| `GET /documents/search` | Any active role | Same access scope; optional `name`, `category`, `owner`, `date_from`, `date_to` |
| `GET /documents/{id}/download` | Any active role | Owner or current `READ`/`EDIT` grant |
| `PUT /documents/{id}` | Any active role | Owner or current `EDIT` grant |
| `PUT /documents/{id}/file` | Any active role | Owner or current `EDIT` grant; validates extension, emptiness, size |
| `DELETE /documents/{id}` | Owner role | Caller must own the document |
| `GET /documents/{id}/permissions` | Owner role | Caller must own the document |
| `POST /documents/{id}/permissions` | Owner role | Caller must own document; active recipient resolved by email; `READ` or `EDIT` |
| `DELETE /documents/{id}/permissions/{user_id}` | Owner role | Caller must own document; removes that recipient's grant |
| `GET /admin/audit-logs` | Admin | Activity records and chain hashes |
| `GET /admin/users` | Admin | Account status; directory access is logged |
| `PATCH /admin/users/{user_id}/status` | Admin | Activate/deactivate; cannot deactivate self |

`READ` grants listing/search/download. `EDIT` adds metadata/file replacement. Only the owner can share or delete. Admin status does not bypass a document grant. Removing a grant or deactivating an account takes effect on the next request, without waiting for token expiry.