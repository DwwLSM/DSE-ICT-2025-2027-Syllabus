# DSE-ICT-2025-2027-Syllabus

## Run locally

Install dependencies with `npm install`, then configure the session and admin credentials in your shell:

```sh
export SESSION_SECRET="$(openssl rand -hex 32)"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="choose-a-strong-password"
# Optional: use a persistent writable directory when deploying
export DATABASE_DIR="/path/to/persistent/database"
npm start
```

The app runs at `http://localhost:3000`. SQLite databases default to the project root and are not tracked by Git. The server process needs read/write access to existing database files and read/write/execute access to their directory.