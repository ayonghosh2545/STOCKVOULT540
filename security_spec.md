# Security Specification & Payload-First TDD

## 1. Data Invariants
1. **Master Gate**: No subcollection document (`/products`, `/payments`, `/notifications`, `/backups`, `/members`, `/staffProfiles`) may be created, read, or modified unless the parent `/workspaces/{workspaceId}` exists and the caller is either the workspace owner, an active member in `/members/{uid}`, or a verified global admin (`ayonghosh549@gmail.com` with `email_verified == true` or `/admins/{uid}`).
2. **Path Variable Hardening**: Every single-document ID (`workspaceId`, `memberUid`, `profileId`, `productId`, `paymentId`, `notificationId`, `backupId`, `adminId`) must match `^[a-zA-Z0-9_\-]+$` and be `<= 128` characters.
3. **PII Isolation**: `/workspaces/{workspaceId}/members/{memberUid}` contains `email` and `displayName`. Only the member themselves, the workspace owner, or a verified admin may `get` or `list` member records.
4. **Tiered RBAC Updates**:
   - **Admin / Owner**: May update all non-immutable workspace settings, members, staffProfiles, products, payments, backups, and notifications.
   - **Manager**: May create/update products, payments, notifications, and backups; cannot edit workspace settings, members, or staffProfiles.
   - **Staff**: May ONLY update product stock fields (`quantity`, `boxNumber`, `rackLocation`, `notes`, `updatedBy`, `updatedAt`) and mark notifications read (`read`, `updatedAt`).
   - **Viewer**: Read-only access; zero write permissions.
5. **Terminal Payment Locking**: Once a payment has `status == 'paid'` and `paidAmount >= amount`, non-admin users cannot downgrade or mutate its `amount` or `status`.
6. **Temporal Integrity & Immutability**: `createdAt` and `ownerId` are immutable after creation; `createdAt == request.time` on create; `updatedAt == request.time` on update.

## 2. The "Dirty Dozen" Attack Payloads
1. **Unauthenticated Product Create**: `request.auth == null` attempting to create `/workspaces/main_vault/products/p1` -> `PERMISSION_DENIED`.
2. **Email Spoofing Admin Bypass**: `request.auth.token.email == 'ayonghosh549@gmail.com'` with `email_verified: false` -> `PERMISSION_DENIED`.
3. **Self-Assigned Admin Escalation**: Regular user creating `/admins/{uid}` or setting `role: 'admin'` on `/members/{uid}` -> `PERMISSION_DENIED`.
4. **Shadow Field Injection**: Creating a `StockProduct` with extra ghost field `isVerified: true` -> `PERMISSION_DENIED`.
5. **Value Poisoning on Update**: Staff updating `StockProduct.quantity` with a string `"999"` or negative `-50` -> `PERMISSION_DENIED`.
6. **ID Poisoning**: Creating `/products/..%2F..%2Fadmins` or a 250-char document ID -> `PERMISSION_DENIED`.
7. **Orphaned Subcollection Write**: Creating a product under a non-existent `/workspaces/ghost_ws/products/p1` -> `PERMISSION_DENIED`.
8. **Immutable Field Tampering**: Updating `StockProduct.ownerId` or `createdAt` -> `PERMISSION_DENIED`.
9. **Client Timestamp Forgery**: Creating a document with backdated `createdAt` (`2020-01-01T00:00:00Z`) instead of `request.time` -> `PERMISSION_DENIED`.
10. **PII Blanket Read**: Viewer or Staff attempting to `list` or `get` another user's `/members/{otherUid}` document -> `PERMISSION_DENIED`.
11. **Terminal Payment Tampering**: Non-admin attempting to edit a `'paid'` payment back to `'pending'` -> `PERMISSION_DENIED`.
12. **Unbounded Array Exhaustion**: Creating a product with `authorizedUids` array of 25 strings (> 20 max) -> `PERMISSION_DENIED`.
