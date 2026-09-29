const express = require('express');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = process.env.PORT || 3000;
const sessionSecret = process.env.SESSION_SECRET;
const adminUsername = process.env.ADMIN_USERNAME;
const adminPassword = process.env.ADMIN_PASSWORD;
const db = new sqlite3.Database('./app.db');
const practiceDb = new sqlite3.Database('./student_practice.db');
const homePagePath = path.join(__dirname, 'index.html');
const homePage = fs.readFileSync(homePagePath, 'utf8');
let sqlQueue = Promise.resolve();

if (!sessionSecret || !adminUsername || !adminPassword) {
  console.error('Set SESSION_SECRET, ADMIN_USERNAME, and ADMIN_PASSWORD before starting the server.');
  process.exit(1);
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(__dirname));
app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax' }
  })
);

function requireLogin(req, res, next) {
  if (req.session.user) {
    return next();
  }

  return res.redirect('/login');
}

function requireApiLogin(req, res, next) {
  if (req.session.user) {
    return next();
  }

  return res.status(401).json({ error: 'Please log in to use the database checker.' });
}

function requireAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'Admin') {
    return next();
  }

  return res.status(403).send('Admin access only.');
}

function getDatabaseTables(database) {
  return new Promise((resolve, reject) => {
    database.all("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name", (err, rows) => {
      if (err) {
        return reject(err);
      }
      resolve((rows || []).map((row) => row.name));
    });
  });
}

function getTableRows(database, tableName) {
  return new Promise((resolve, reject) => {
    const safeName = String(tableName).replace(/"/g, '""');
    database.all(`SELECT * FROM "${safeName}"`, (err, rows) => {
      if (err) {
        return reject(err);
      }
      resolve(rows || []);
    });
  });
}

function renderTableHtml(tableName, rows) {
  if (!rows || !rows.length) {
    return `
      <section style="margin-top: 24px;">
        <h3>${tableName}</h3>
        <p style="color:#475569;">No rows found.</p>
      </section>
    `;
  }

  const columns = Object.keys(rows[0]);
  const rowsHtml = rows.map((row) => {
    const cells = columns.map((col) => `<td style="padding:8px 10px;border:1px solid #e2e8f0;vertical-align:top;">${String(row[col] ?? 'NULL')}</td>`).join('');
    return `<tr>${cells}</tr>`;
  }).join('');

  const header = columns.map((col) => `<th style="padding:8px 10px;border:1px solid #e2e8f0;background:#f8fafc;text-align:left;">${col}</th>`).join('');

  return `
    <section style="margin-top: 24px;">
      <h3>${tableName}</h3>
      <div style="overflow:auto;border:1px solid #e2e8f0;border-radius:8px;background:#fff;">
        <table style="width:100%;border-collapse:collapse;min-width:360px;">
          <thead>
            <tr>${header}</tr>
          </thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>
    </section>
  `;
}

function renderAdminDatabasePage(databaseSections) {
  const sectionHtml = databaseSections.map(({ label, tables }) => {
    const tableHtml = tables.map(({ name, rows }) => renderTableHtml(name, rows)).join('\n');
    return `
      <section style="margin-top: 32px;">
        <h2 style="margin-bottom: 12px;">${label}</h2>
        ${tableHtml}
      </section>
    `;
  }).join('\n');

  return `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Admin Database Viewer</title>
        <style>
          body { font-family: Arial, sans-serif; background: #f4f7fb; color: #1f2937; margin: 0; padding: 32px 20px 48px; }
          .wrap { max-width: 1200px; margin: 0 auto; }
          .topbar { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 20px; }
          a { color: #4f46e5; text-decoration: none; }
          .card { background: white; border-radius: 12px; box-shadow: 0 10px 30px rgba(15,23,42,0.08); padding: 20px 24px; }
          h1 { margin: 0; }
          h2, h3 { margin-top: 0; }
        </style>
      </head>
      <body>
        <div class="wrap">
          <div class="topbar">
            <h1>Admin Database Viewer</h1>
            <div>
              <a href="/dashboard">Dashboard</a> | <a href="/logout">Logout</a>
            </div>
          </div>
          <div class="card">
            ${sectionHtml}
          </div>
        </div>
      </body>
    </html>
  `;
}

function renderAuthPage(title, formAction, message = '', secondaryText = '') {
  return `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>${title}</title>
        <style>
          body { font-family: Arial, sans-serif; background: #f4f7fb; color: #1f2937; margin: 0; padding: 40px 20px; }
          .card { max-width: 420px; margin: 0 auto; background: #fff; border-radius: 12px; padding: 28px; box-shadow: 0 10px 28px rgba(15, 23, 42, 0.08); }
          h1 { margin-top: 0; }
          label { display: block; margin: 14px 0 8px; font-weight: 600; }
          input { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid #cbd5e1; font-size: 16px; }
          button { width: 100%; margin-top: 18px; padding: 12px; border: none; border-radius: 10px; background: #4f46e5; color: white; font-size: 16px; cursor: pointer; }
          .message { margin-bottom: 12px; color: #b91c1c; font-weight: 600; min-height: 20px; }
          .alt { text-align: center; margin-top: 18px; }
          a { color: #4f46e5; text-decoration: none; }
        </style>
      </head>
      <body>
        <div class="card">
          <h1>${title}</h1>
          <div class="message">${message}</div>
          <form method="POST" action="${formAction}">
            <label for="username">Username</label>
            <input id="username" name="username" type="text" required />

            <label for="password">Password</label>
            <input id="password" name="password" type="password" required />

            <button type="submit">${title}</button>
          </form>
          <div class="alt">${secondaryText}</div>
        </div>
      </body>
    </html>
  `;
}

function ensureAdminUser(callback) {
  db.get('SELECT * FROM users WHERE username = ?', [adminUsername], (err, existingUser) => {
    if (err) {
      return callback(err);
    }

    if (existingUser) {
      return callback(null, existingUser);
    }

    const hashed = bcrypt.hashSync(adminPassword, 10);
    db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [adminUsername, hashed, 'Admin'], function (insertErr) {
      if (insertErr) {
        return callback(insertErr);
      }

      return callback(null, { id: this.lastID, username: adminUsername, password: hashed, role: 'Admin' });
    });
  });
}

function initializeDatabase() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      db.run('DROP TABLE IF EXISTS users', (dropErr) => {
        if (dropErr) {
          return reject(dropErr);
        }

        db.run(`
          CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'User'
          )
        `, (createErr) => {
          if (createErr) {
            return reject(createErr);
          }

          ensureAdminUser((seedErr) => {
            if (seedErr) {
              return reject(seedErr);
            }

            return resolve();
          });
        });
      });
    });
  });
}

function initializePracticeDatabase() {
  return new Promise((resolve, reject) => {
    practiceDb.serialize(() => {
      const statements = [
        `DROP TABLE IF EXISTS Enrolment`,
        `DROP TABLE IF EXISTS Subject`,
        `DROP TABLE IF EXISTS Student`,
        `CREATE TABLE Student (
          StudentID TEXT PRIMARY KEY,
          Name TEXT NOT NULL,
          Class TEXT NOT NULL,
          Score INTEGER NOT NULL
        )`,
        `CREATE TABLE Subject (
          SubjectID TEXT PRIMARY KEY,
          SubjectName TEXT NOT NULL,
          Teacher TEXT NOT NULL
        )`,
        `CREATE TABLE Enrolment (
          StudentID TEXT NOT NULL,
          SubjectID TEXT NOT NULL,
          Grade TEXT NOT NULL,
          PRIMARY KEY (StudentID, SubjectID),
          FOREIGN KEY (StudentID) REFERENCES Student(StudentID),
          FOREIGN KEY (SubjectID) REFERENCES Subject(SubjectID)
        )`,
        `INSERT INTO Student (StudentID, Name, Class, Score) VALUES
          ('S01', 'Peter Chan', '6A', 85),
          ('S02', 'Mary Wong', '6B', 72),
          ('S03', 'John Lee', '6A', 91),
          ('S04', 'Amy Cheung', '6C', 68),
          ('S05', 'Tom Wong', '6B', 78)`,
        `INSERT INTO Subject (SubjectID, SubjectName, Teacher) VALUES
          ('ENG', 'English', 'Ms Lam'),
          ('MATH', 'Mathematics', 'Mr Fong'),
          ('ICT', 'ICT', 'Ms Ho'),
          ('PHY', 'Physics', 'Mr Ng')`,
        `INSERT INTO Enrolment (StudentID, SubjectID, Grade) VALUES
          ('S01', 'ENG', 'B'),
          ('S01', 'ICT', 'A'),
          ('S02', 'ENG', 'C'),
          ('S02', 'MATH', 'B'),
          ('S03', 'ICT', 'A'),
          ('S04', 'MATH', 'C'),
          ('S05', 'ICT', 'B'),
          ('S05', 'PHY', 'B')`
      ];

      practiceDb.exec(statements.join('; '), (execErr) => {
        if (execErr) {
          reject(execErr);
          return;
        }
        resolve();
      });
    });
  });
}

function normalizeCell(value) {
  if (typeof value === 'number') {
    return Number(value.toFixed(4));
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    const numeric = Number(trimmed);
    if (trimmed !== '' && trimmed !== 'null' && !Number.isNaN(numeric) && !isNaN(Number(trimmed)) && !/[A-Za-z]/.test(trimmed)) {
      return Number(numeric.toFixed(4));
    }
    return trimmed;
  }

  return value;
}

function normalizeRows(rows) {
  return (rows || [])
    .map((row) => {
      const out = {};
      const keys = Object.keys(row).sort();
      for (const key of keys) {
        out[key] = normalizeCell(row[key]);
      }
      return out;
    })
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

function normalizeRowValueList(row) {
  return Object.keys(row || {}).map((key) => normalizeCell(row[key]));
}

function compareRows(actualRows, expectedRows) {
  const left = (actualRows || [])
    .map((row) => normalizeRowValueList(row))
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));

  const right = (expectedRows || [])
    .map((row) => normalizeRowValueList(row))
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));

  return JSON.stringify(left) === JSON.stringify(right);
}

function queueSqlTask(task) {
  const next = sqlQueue.then(task, task);
  sqlQueue = next.then(() => undefined, () => undefined);
  return next;
}

function runSqlQuery(sql) {
  return new Promise((resolve, reject) => {
    practiceDb.all(sql, [], (err, rows) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(rows || []);
    });
  });
}

function executePracticeSql(sql) {
  return new Promise((resolve, reject) => {
    practiceDb.exec(sql, (err) => {
      if (err) {
        reject(err);
        return;
      }
      resolve();
    });
  });
}

async function fetchTableRows(tableName) {
  return await runSqlQuery(`SELECT * FROM ${tableName} ORDER BY 1`);
}

async function fetchTableSchema(tableName) {
  return await runSqlQuery(`PRAGMA table_info(${tableName});`);
}

function getModelSql(question) {
  return (question && (question.expectedQuery || question.sample) || '').trim();
}

async function runCanonicalModelResult(question) {
  const modelSql = getModelSql(question);
  if (!modelSql) {
    throw new Error('Model SQL is missing for this Master SQL question.');
  }

  await initializePracticeDatabase();

  if (question.type === 'mutation') {
    await executePracticeSql(modelSql);
    if (question.check === 'schema') {
      return { expectedRows: await fetchTableSchema(question.table), expectedQuery: modelSql, modelSql };
    }
    return { expectedRows: await fetchTableRows(question.table), expectedQuery: modelSql, modelSql };
  }

  const rows = await runSqlQuery(modelSql);
  return { expectedRows: rows, expectedQuery: modelSql, modelSql };
}

function loadQuestionBank() {
  const bankPath = path.join(__dirname, 'question-bank.js');
  const source = fs.readFileSync(bankPath, 'utf8');
  const sandbox = { console };
  vm.runInNewContext(source, sandbox, { filename: bankPath });
  return sandbox.BANK;
}

const BANK = loadQuestionBank();
const MASTER_SQL_QUESTIONS = ([]
  .concat(
    Array.isArray(BANK && BANK.mastersql && BANK.mastersql.basic) ? BANK.mastersql.basic : [],
    Array.isArray(BANK && BANK.mastersql && BANK.mastersql.intermediate) ? BANK.mastersql.intermediate : [],
    Array.isArray(BANK && BANK.mastersql && BANK.mastersql.advanced) ? BANK.mastersql.advanced : [],
    Array.isArray(BANK && BANK.mastersql && BANK.mastersql.mutation) ? BANK.mastersql.mutation : []
  )
  .map((item) => ({
    id: item.id,
    title: item.q,
    type: item.t === 'sql' && /mutation|alter|update|delete|insert/i.test((item.sample || '')) ? 'mutation' : 'select',
    table: item.table || 'all',
    check: item.check || undefined,
    question: item.q,
    description: item.q,
    expectedQuery: item.sample,
    sample: item.sample,
    reason: item.why,
    steps: item.steps || [],
    wrong: item.wrong || [],
    tip: item.tip
  })));

app.get('/', (req, res) => {
  res.set('Content-Type', 'text/html');
  res.send(homePage);
});

app.get('/new-page', (req, res) => {
  res.set('Content-Type', 'text/html');
  res.send(homePage);
});

app.get('/login-page.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login-page.html'));
});

app.get('/login', (req, res) => {
  res.send(renderAuthPage('Login', '/login', '', '<a href="/signup">Create an account</a> | <a href="/">Continue without login</a>'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send(renderAuthPage('Login', '/login', 'Username and password are required.', '<a href="/signup">Create an account</a>'));
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).send(renderAuthPage('Login', '/login', 'Database error.', '<a href="/signup">Create an account</a>'));
    }

    if (!user && username === adminUsername) {
      return ensureAdminUser((seedErr, seededUser) => {
        if (seedErr) {
          return res.status(500).send(renderAuthPage('Login', '/login', 'Unable to initialize Admin user.', '<a href="/signup">Create an account</a>'));
        }

        const valid = bcrypt.compareSync(password, seededUser.password);
        if (!valid) {
          return res.status(401).send(renderAuthPage('Login', '/login', 'Invalid username or password.', '<a href="/signup">Create an account</a>'));
        }

        req.session.user = { id: seededUser.id, username: seededUser.username, role: seededUser.role };
        return res.redirect('/dashboard');
      });
    }

    if (!user) {
      return res.status(401).send(renderAuthPage('Login', '/login', 'Invalid username or password.', '<a href="/signup">Create an account</a>'));
    }

    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) {
      return res.status(401).send(renderAuthPage('Login', '/login', 'Invalid username or password.', '<a href="/signup">Create an account</a>'));
    }

    req.session.user = { id: user.id, username: user.username, role: user.role };
    return res.redirect('/dashboard');
  });
});

app.get('/signup', (req, res) => {
  res.send(renderAuthPage('Sign Up', '/signup', '', '<a href="/login">Already have an account?</a> | <a href="/">Continue without login</a>'));
});

app.post('/signup', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send(renderAuthPage('Sign Up', '/signup', 'Username and password are required.', '<a href="/login">Back to login</a>'));
  }

  if (username.length < 3 || password.length < 6) {
    return res.status(400).send(renderAuthPage('Sign Up', '/signup', 'Username must be at least 3 chars and password at least 6 chars.', '<a href="/login">Back to login</a>'));
  }

  db.get('SELECT id FROM users WHERE username = ?', [username], (err, existingUser) => {
    if (err) {
      return res.status(500).send('Database error');
    }

    if (existingUser) {
      return res.status(409).send(renderAuthPage('Sign Up', '/signup', 'Username already exists. Please choose another.', '<a href="/login">Back to login</a>'));
    }

    const hashed = bcrypt.hashSync(password, 10);
    db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashed, 'User'], function (insertErr) {
      if (insertErr) {
        return res.status(500).send('Unable to create account.');
      }

      req.session.user = { id: this.lastID, username, role: 'User' };
      return res.redirect('/dashboard');
    });
  });
});

app.get('/dashboard', requireLogin, (req, res) => {
  const user = req.session.user;
  const adminBadge = user.role === 'Admin' ? '<span style="background:#4f46e5;color:white;padding:4px 8px;border-radius:999px;font-size:12px;font-weight:700;">Admin</span>' : '<span style="background:#16a34a;color:white;padding:4px 8px;border-radius:999px;font-size:12px;font-weight:700;">User</span>';
  const adminLinks = user.role === 'Admin'
    ? '<div class="link-box"><a href="/admin-db">View database tables</a></div>'
    : '';

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Dashboard</title>
        <style>
          body { font-family: Arial, sans-serif; background: #f4f7fb; margin: 0; padding: 40px 20px; color: #1f2937; }
          .card { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; padding: 28px; box-shadow: 0 10px 30px rgba(15,23,42,.08); }
          h1 { margin-top: 0; }
          p { line-height: 1.7; }
          a { color: #4f46e5; text-decoration: none; }
          .top { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
          .link-box { margin-top: 20px; display: inline-block; background: #eef2ff; color: #3730a3; padding: 10px 14px; border-radius: 10px; font-weight: 700; }
        </style>
      </head>
      <body>
        <div class="card">
          <div class="top">
            <h1>Welcome, ${user.username}</h1>
            ${adminBadge}
          </div>
          <p>You are logged in.</p>
          <p><strong>Role:</strong> ${user.role}</p>
          <p><a href="/">Home page</a> | <a href="/sql-lab">SQL Practice Lab</a> | <a href="/logout">Logout</a></p>
          <div class="link-box"><a href="/sql-lab">Run SQL questions in the database lab</a></div>
          ${adminLinks}
        </div>
      </body>
    </html>
  `);
});

app.get('/admin-db', requireLogin, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin-db.html'));
});

app.get('/api/admin-db-data', requireLogin, requireAdmin, async (req, res) => {
  try {
    const appTables = await getDatabaseTables(db);
    const practiceTables = await getDatabaseTables(practiceDb);

    const appRows = await Promise.all(appTables.map(async (tableName) => ({
      name: tableName,
      rows: await getTableRows(db, tableName)
    })));

    const practiceRows = await Promise.all(practiceTables.map(async (tableName) => ({
      name: tableName,
      rows: await getTableRows(practiceDb, tableName)
    })));

    res.json([
      { label: 'Application database (app.db)', tables: appRows },
      { label: 'Student practice database (student_practice.db)', tables: practiceRows }
    ]);
  } catch (error) {
    res.status(500).json({ error: `Unable to load database data: ${error.message}` });
  }
});

app.post('/api/admin-run-sql', requireLogin, requireAdmin, (req, res) => {
  const sql = (req.body && req.body.sql) ? String(req.body.sql).trim() : '';
  const databaseName = (req.body && req.body.database) ? String(req.body.database).toLowerCase() : 'practice';

  if (!sql) {
    return res.status(400).json({ error: 'SQL query is required.' });
  }

  const allowedPattern = /^\s*(SELECT|WITH|EXPLAIN)\b/i;
  if (!allowedPattern.test(sql)) {
    return res.status(400).json({ error: 'Only SELECT / WITH / EXPLAIN queries are allowed in the admin SQL runner.' });
  }

  const targetDb = databaseName === 'app' ? db : practiceDb;

  queueSqlTask(async () => {
    try {
      const rows = await new Promise((resolve, reject) => {
        targetDb.all(sql, [], (err, resultRows) => {
          if (err) {
            reject(err);
            return;
          }
          resolve(resultRows || []);
        });
      });

      const columns = rows && rows.length ? Object.keys(rows[0]) : [];
      return res.json({ ok: true, database: databaseName, columns, rows, rowCount: rows.length });
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }
  }).catch((error) => {
    return res.status(500).json({ error: error.message });
  });
});

app.get('/sql-lab', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'sql-lab.html'));
});

app.post('/api/sql-practice', requireApiLogin, (req, res) => {
  const sql = (req.body && req.body.sql) ? req.body.sql.trim() : '';

  if (!sql) {
    return res.status(400).json({ error: 'SQL query is required.' });
  }

  const allowedPattern = /^\s*(SELECT|WITH|EXPLAIN)\b/i;
  if (!allowedPattern.test(sql)) {
    return res.status(400).json({
      error: 'Only SELECT / WITH / EXPLAIN queries are allowed in the student SQL lab.'
    });
  }

  queueSqlTask(async () => {
    try {
      await initializePracticeDatabase();
      const rows = await runSqlQuery(sql);
      const columns = rows && rows.length ? Object.keys(rows[0]) : [];
      return res.json({
        ok: true,
        rowCount: rows.length,
        columns,
        rows
      });
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }
  }).catch((error) => {
    return res.status(500).json({ error: error.message });
  });
});

app.post('/api/master-sql-check', requireApiLogin, async (req, res) => {
  const questionId = (req.body && req.body.questionId) ? String(req.body.questionId) : '';
  const sql = (req.body && req.body.sql) ? req.body.sql.trim() : '';

  if (!questionId) {
    return res.status(400).json({ error: 'Master question ID is required.' });
  }

  const question = MASTER_SQL_QUESTIONS.find((item) => item.id === questionId);
  if (!question) {
    return res.status(404).json({ error: 'Question not found.' });
  }

  if (!sql) {
    return res.status(400).json({ error: 'SQL answer is required.' });
  }

  const allowedPattern = /^\s*(SELECT|WITH|EXPLAIN|INSERT|UPDATE|DELETE|ALTER)\b/i;
  if (!allowedPattern.test(sql)) {
    return res.status(400).json({ error: 'Only SELECT / WITH / EXPLAIN / INSERT / UPDATE / DELETE / ALTER queries are allowed.' });
  }

  try {
    const result = await queueSqlTask(async () => {
      const modelResult = await runCanonicalModelResult(question);
      await initializePracticeDatabase();

      if (question.type === 'mutation') {
        await executePracticeSql(sql);

        const actualRows = question.check === 'schema'
          ? await fetchTableSchema(question.table)
          : await fetchTableRows(question.table);

        const isCorrect = compareRows(actualRows, modelResult.expectedRows);

        return {
          isCorrect,
          studentRows: actualRows,
          expectedRows: modelResult.expectedRows,
          expectedQuery: modelResult.expectedQuery,
          question
        };
      }

      const studentRows = await runSqlQuery(sql);
      const isCorrect = compareRows(studentRows, modelResult.expectedRows);
      return {
        isCorrect,
        studentRows,
        expectedRows: modelResult.expectedRows,
        expectedQuery: modelResult.expectedQuery,
        question
      };
    });

    return res.json({
      ok: true,
      correct: result.isCorrect,
      questionId: question.id,
      title: question.title,
      message: result.isCorrect ? 'Correct — the query output matches the expected result.' : 'Incorrect — the query output does not match the expected result.',
      expectedRows: result.expectedRows,
      studentRows: result.studentRows,
      expectedQuery: result.expectedQuery || question.expectedQuery
    });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/admin-only', requireLogin, requireAdmin, (req, res) => {
  res.send(`Admin area for ${req.session.user.username}`);
});

initializeDatabase()
  .then(() => initializePracticeDatabase())
  .then(() => {
    app.listen(port, () => {
      console.log(`Server running on http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error('Database initialization failed:', err.message);
    process.exit(1);
  });
