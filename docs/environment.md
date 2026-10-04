# Environment configuration

Production reads these Railway service variables: DATABASE_URL, SECRET_KEY, CSRF_SECRET, SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, FRONTEND_URL. Keep DATABASE_URL=/data/inventory.db on the mounted volume.

For local development, copy .env.example to .env and fill the placeholders. Generate independent application keys with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Real environment files must remain untracked.

The previously committed .env remains in Git history. Replace exposed SECRET_KEY and CSRF_SECRET in Railway and revoke/reissue the exposed SMTP credential with the email provider. Application-key changes can require users to sign in again or refresh forms. This does not change user passwords or stock data.

Removing a file in a new commit does not erase old commits, clones, or forks. History cleanup must be coordinated separately; credential replacement is required even after history cleanup.
