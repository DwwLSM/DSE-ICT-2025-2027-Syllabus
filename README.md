# DSE-ICT-2025-2027-Syllabus

## Run locally

Install dependencies with `npm install`, then configure the session and admin credentials in your shell:

```sh
export SESSION_SECRET="$(openssl rand -hex 32)"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="choose-a-strong-password"
npm start
```

The app runs at `http://localhost:3000`. SQLite databases are created locally and are not tracked by Git.