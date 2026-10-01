const express = require('express');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const { createMasterSqlChecker } = require('./javascripts/master-sql-checker');

const app = express();
const port = process.env.PORT || 3000;
const sessionSecret = process.env.SESSION_SECRET;
const adminUsername = process.env.ADMIN_USERNAME;
const adminPassword = process.env.ADMIN_PASSWORD;
const databaseDirectory = path.resolve(process.env.DATABASE_DIR || __dirname);
const databasePaths = [
  path.join(databaseDirectory, 'app.db'),
  path.join(databaseDirectory, 'student_practice.db')
];

try {
  fs.mkdirSync(databaseDirectory, { recursive: true });
  fs.accessSync(databaseDirectory, fs.constants.R_OK | fs.constants.W_OK | fs.constants.X_OK);
  databasePaths.forEach((databasePath) => {
    if (fs.existsSync(databasePath)) {
      fs.accessSync(databasePath, fs.constants.R_OK | fs.constants.W_OK);
      const descriptor = fs.openSync(databasePath, 'r+');
      fs.closeSync(descriptor);
    }
  });
  const writeProbePath = path.join(databaseDirectory, `.sqlite-write-probe-${process.pid}-${Date.now()}`);
  const writeProbeDescriptor = fs.openSync(writeProbePath, 'wx', 0o600);
  fs.closeSync(writeProbeDescriptor);
  fs.unlinkSync(writeProbePath);
} catch (error) {
  console.error(`SQLite database directory or files are not writable by the server process: ${error.path || databaseDirectory}`);
  console.error(error.message);
  process.exit(1);
}

const db = new sqlite3.Database(databasePaths[0]);
const practiceDb = new sqlite3.Database(databasePaths[1]);
const homePagePath = path.join(__dirname, 'index.html');
const homePage = fs.readFileSync(homePagePath, 'utf8');
let sqlQueue = Promise.resolve();

if (!sessionSecret || !adminUsername || !adminPassword) {
  console.error('Set SESSION_SECRET, ADMIN_USERNAME, and ADMIN_PASSWORD before starting the server.');
  process.exit(1);
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(['/app.db', '/student_practice.db'], (req, res) => res.sendStatus(404));
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
  if (!req.session.user) {
    return res.redirect('/login');
  }

  db.get('SELECT id, username, role FROM users WHERE id = ?', [req.session.user.id], (error, user) => {
    if (error) {
      return res.status(500).send('Unable to verify your account.');
    }
    if (!user) {
      req.session.destroy(() => res.redirect('/login'));
      return;
    }

    req.session.user = user;
    return next();
  });
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

function requireTeacher(req, res, next) {
  if (req.session.user && req.session.user.role === 'Teacher') {
    return next();
  }

  return res.status(403).send('Teacher access only.');
}

async function getCourseSummaryForUser(userId, courseId) {
  const totalQuestionsRow = await getAppRows(
    'SELECT COUNT(*) AS total FROM CourseQuestions WHERE course_id = ?',
    [courseId]
  );
  const progressRows = await getAppRows(
    `SELECT question_id, attempts, is_completed, last_answer_correct, last_attempt_at
     FROM CourseProgress
     WHERE user_id = ? AND course_id = ?`,
    [userId, courseId]
  );

  const totalQuestions = Number(totalQuestionsRow[0]?.total || 0);
  const attemptedCount = progressRows.filter((row) => Number(row.attempts || 0) > 0).length;
  const completedCount = progressRows.filter((row) => Number(row.is_completed || 0) === 1).length;
  const correctCount = progressRows.filter((row) => Number(row.last_answer_correct || 0) === 1).length;
  const latestStatus = progressRows.length ? progressRows.reduce((latest, row) => {
    if (!latest || new Date(row.last_attempt_at || 0) > new Date(latest.last_attempt_at || 0)) {
      return row;
    }
    return latest;
  }, null) : null;

  return {
    totalQuestions,
    attemptedCount,
    completedCount,
    correctCount,
    currentPercentage: totalQuestions ? Math.round((correctCount / totalQuestions) * 100) : 0,
    lastStatus: latestStatus ? { question_id: latestStatus.question_id, is_completed: Number(latestStatus.is_completed || 0), last_answer_correct: Number(latestStatus.last_answer_correct || 0), attempts: Number(latestStatus.attempts || 0) } : null
  };
}

async function userCanAccessCourse(userId, courseId) {
  const rows = await getAppRows(
    `SELECT 1
     FROM CourseClasses cc
     JOIN ClassMembers cm ON cm.cid = cc.class_id
     WHERE cc.course_id = ? AND cm.id = ?
     LIMIT 1`,
    [courseId, userId]
  );
  return rows.length > 0;
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

function runAppSql(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (error) {
      if (error) return reject(error);
      resolve(this);
    });
  });
}

function getAppRows(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => {
      if (error) return reject(error);
      resolve(rows || []);
    });
  });
}

function createQuestionProgressTable(tableName) {
  return `CREATE TABLE ${tableName} (
    user_id INTEGER NOT NULL,
    question_id TEXT NOT NULL,
    is_completed INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 1,
    last_answer_correct INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, question_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (question_id) REFERENCES Questions(question_id)
  )`;
}

async function seedQuestionRegistry() {
  for (const [questionId, question] of QUESTIONS_BY_ID) {
    await runAppSql(`
      INSERT INTO Questions (question_id, question, category, level, question_type)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(question_id) DO UPDATE SET
        question = excluded.question,
        category = excluded.category,
        level = excluded.level,
        question_type = excluded.question_type
    `, [
      questionId,
      question.q || question.question || question.title || questionId,
      question.category,
      question.level,
      question.t || 'unknown'
    ]);
  }
}

async function migrateQuestionProgress() {
  const columns = await getAppRows('PRAGMA table_info(question_progress)');
  if (!columns.length) {
    await runAppSql(createQuestionProgressTable('question_progress'));
    return;
  }

  const foreignKeys = await getAppRows('PRAGMA foreign_key_list(question_progress)');
  if (foreignKeys.some((key) => key.table.toLowerCase() === 'questions' && key.from === 'question_id')) {
    return;
  }

  const legacyRows = await getAppRows('SELECT * FROM question_progress');
  const registeredIds = new Set((await getAppRows('SELECT question_id FROM Questions')).map((row) => row.question_id));
  for (const row of legacyRows) {
    if (registeredIds.has(row.question_id)) continue;
    await runAppSql(`
      INSERT INTO Questions (question_id, question, category, level, question_type)
      VALUES (?, ?, ?, 'legacy', 'legacy')
      ON CONFLICT(question_id) DO NOTHING
    `, [row.question_id, row.question_title || row.question_id, row.category || 'legacy']);
    registeredIds.add(row.question_id);
  }

  await runAppSql('BEGIN IMMEDIATE');
  try {
    await runAppSql('DROP TABLE IF EXISTS question_progress_new');
    await runAppSql(createQuestionProgressTable('question_progress_new'));
    for (const row of legacyRows) {
      await runAppSql(`
        INSERT INTO question_progress_new (
          user_id, question_id, is_completed, attempts, last_answer_correct, last_attempt_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `, [
        row.user_id,
        row.question_id,
        row.is_completed || 0,
        row.attempts || 1,
        row.last_answer_correct || 0,
        row.last_attempt_at || new Date().toISOString()
      ]);
    }
    await runAppSql('DROP TABLE question_progress');
    await runAppSql('ALTER TABLE question_progress_new RENAME TO question_progress');
    await runAppSql('COMMIT');
  } catch (error) {
    await runAppSql('ROLLBACK').catch(() => {});
    throw error;
  }
}

async function initializeDatabase() {
  await runAppSql('PRAGMA foreign_keys = ON');
  await runAppSql(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'User'
    )
  `);
  await runAppSql(`
    CREATE TABLE IF NOT EXISTS Classes (
      cid INTEGER PRIMARY KEY AUTOINCREMENT,
      id INTEGER NOT NULL,
      FOREIGN KEY (id) REFERENCES users(id)
    )
  `);
  await runAppSql(`
    CREATE TABLE IF NOT EXISTS ClassMembers (
      id INTEGER NOT NULL,
      cid INTEGER NOT NULL,
      PRIMARY KEY (id, cid),
      FOREIGN KEY (id) REFERENCES users(id),
      FOREIGN KEY (cid) REFERENCES Classes(cid)
    )
  `);
  await runAppSql(`
    CREATE TABLE IF NOT EXISTS ClassTeachers (
      cid INTEGER NOT NULL,
      id INTEGER NOT NULL,
      PRIMARY KEY (cid, id),
      FOREIGN KEY (cid) REFERENCES Classes(cid),
      FOREIGN KEY (id) REFERENCES users(id)
    )
  `);
  await runAppSql('INSERT OR IGNORE INTO ClassTeachers (cid, id) SELECT cid, id FROM Classes');
  await new Promise((resolve, reject) => {
    ensureAdminUser((error) => error ? reject(error) : resolve());
  });
  await runAppSql(`
    CREATE TABLE IF NOT EXISTS Questions (
      question_id TEXT PRIMARY KEY,
      question TEXT NOT NULL,
      category TEXT NOT NULL,
      level TEXT NOT NULL,
      question_type TEXT NOT NULL
    )
  `);
  await runAppSql(`
    CREATE TABLE IF NOT EXISTS Courses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      visibility TEXT NOT NULL DEFAULT 'private',
      published INTEGER NOT NULL DEFAULT 0,
      owner_user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (owner_user_id) REFERENCES users(id)
    )
  `);
  const courseColumns = await getAppRows('PRAGMA table_info(Courses)');
  if (!courseColumns.some((column) => column.name === 'visibility')) {
    await runAppSql("ALTER TABLE Courses ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private'");
  }
  await runAppSql(`
    CREATE TABLE IF NOT EXISTS CourseQuestions (
      course_id INTEGER NOT NULL,
      question_id TEXT NOT NULL,
      position INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (course_id, question_id),
      FOREIGN KEY (course_id) REFERENCES Courses(id),
      FOREIGN KEY (question_id) REFERENCES Questions(question_id)
    )
  `);
  await runAppSql(`
    CREATE TABLE IF NOT EXISTS CourseClasses (
      course_id INTEGER NOT NULL,
      class_id INTEGER NOT NULL,
      PRIMARY KEY (course_id, class_id),
      FOREIGN KEY (course_id) REFERENCES Courses(id),
      FOREIGN KEY (class_id) REFERENCES Classes(cid)
    )
  `);
  await runAppSql(`
    CREATE TABLE IF NOT EXISTS CourseProgress (
      user_id INTEGER NOT NULL,
      course_id INTEGER NOT NULL,
      question_id TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      is_completed INTEGER NOT NULL DEFAULT 0,
      last_answer_correct INTEGER NOT NULL DEFAULT 0,
      last_attempt_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, course_id, question_id),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (course_id) REFERENCES Courses(id),
      FOREIGN KEY (question_id) REFERENCES Questions(question_id)
    )
  `);
  await seedQuestionRegistry();
  await ensureDemoCourse();
  await migrateQuestionProgress();
}

function initializePracticeDatabase(question) {
  return new Promise((resolve, reject) => {
    practiceDb.serialize(() => {
      const allTables = Object.values(BANK.mastersql.tables);
      const requiredTableNames = typeof question === 'string'
        ? BANK.mastersql.getRequiredTables(question)
        : (question && question.requiredTables) || BANK.mastersql.getRequiredTables(question);
      const requiredTables = BANK.mastersql.getTables(requiredTableNames);
      const statements = [
        ...allTables.slice().reverse().map((table) => table.drop),
        ...requiredTables.flatMap((table) => [table.create, table.seed])
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

const checkMasterSqlAnswer = createMasterSqlChecker({
  initializePracticeDatabase,
  executePracticeSql,
  fetchTableRows,
  fetchTableSchema,
  runSqlQuery
});

function loadQuestionBank() {
  const bankPath = path.join(__dirname, 'javascripts', 'question-bank.js');
  const source = fs.readFileSync(bankPath, 'utf8');
  const sandbox = { console };
  vm.runInNewContext(source, sandbox, { filename: bankPath });
  return sandbox.BANK;
}

const BANK = loadQuestionBank();
const QUESTIONS_BY_ID = new Map();
Object.keys(BANK || {}).forEach((category) => {
  Object.keys(BANK[category] || {}).forEach((level) => {
    const questions = BANK[category][level];
    if (!Array.isArray(questions)) return;
    questions.forEach((question) => {
      if (question && question.id) {
        QUESTIONS_BY_ID.set(question.id, { ...question, category, level });
      }
    });
  });
});

function recordQuestionProgress(userId, questionId, isCorrect) {
  const question = QUESTIONS_BY_ID.get(questionId);
  if (!question) {
    return Promise.reject(new Error('Question not found.'));
  }

  const completed = isCorrect ? 1 : 0;
  return new Promise((resolve, reject) => {
    db.run(`
      INSERT INTO question_progress (
        user_id, question_id, is_completed, attempts, last_answer_correct, last_attempt_at
      ) VALUES (?, ?, ?, 1, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(user_id, question_id) DO UPDATE SET
        is_completed = MAX(question_progress.is_completed, excluded.is_completed),
        attempts = question_progress.attempts + 1,
        last_answer_correct = excluded.last_answer_correct,
        last_attempt_at = CURRENT_TIMESTAMP
    `, [userId, questionId, completed, completed], (error) => {
      if (error) return reject(error);
      resolve();
    });
  });
}

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
    requiredTables: BANK.mastersql.getRequiredTables(item),
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

async function ensureDemoCourse() {
  const existing = await getAppRows('SELECT id FROM Courses WHERE title = ? LIMIT 1', ['Master SQL Demo']);
  if (existing.length) {
    const courseId = existing[0].id;
    const existingQuestions = await getAppRows('SELECT question_id FROM CourseQuestions WHERE course_id = ?', [courseId]);
    const questionIds = existingQuestions.map((row) => row.question_id);
    for (let i = 0; i < MASTER_SQL_QUESTIONS.length; i += 1) {
      const question = MASTER_SQL_QUESTIONS[i];
      if (!question || !question.id || questionIds.includes(question.id)) {
        continue;
      }
      await runAppSql(
        'INSERT INTO CourseQuestions (course_id, question_id, position) VALUES (?, ?, ?)',
        [courseId, question.id, i]
      );
    }
    await runAppSql("UPDATE Courses SET published = 1, visibility = 'public' WHERE id = ?", [courseId]);
    return courseId;
  }

  const owner = await getAppRows('SELECT id FROM users WHERE username = ? LIMIT 1', [adminUsername]);
  const ownerId = owner.length ? owner[0].id : 1;
  const result = await runAppSql(
    "INSERT INTO Courses (title, description, visibility, published, owner_user_id) VALUES (?, ?, 'public', 1, ?)",
    ['Master SQL Demo', 'A demo course covering all Master SQL questions.', ownerId]
  );
  const courseId = result.lastID;
  for (let i = 0; i < MASTER_SQL_QUESTIONS.length; i += 1) {
    const question = MASTER_SQL_QUESTIONS[i];
    if (!question || !question.id) {
      continue;
    }
    await runAppSql(
      'INSERT OR IGNORE INTO CourseQuestions (course_id, question_id, position) VALUES (?, ?, ?)',
      [courseId, question.id, i]
    );
  }
  return courseId;
}

async function recordCourseProgress(userId, courseId, questionId, isCorrect) {
  const courseRows = await getAppRows('SELECT id FROM Courses WHERE id = ?', [courseId]);
  if (!courseRows.length) {
    throw new Error('Course not found.');
  }
  const questionRows = await getAppRows('SELECT question_id FROM Questions WHERE question_id = ?', [questionId]);
  if (!questionRows.length) {
    throw new Error('Question not found in course catalog.');
  }

  return new Promise((resolve, reject) => {
    db.run(`
      INSERT INTO CourseProgress (
        user_id, course_id, question_id, attempts, is_completed, last_answer_correct, last_attempt_at
      ) VALUES (?, ?, ?, 1, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(user_id, course_id, question_id) DO UPDATE SET
        attempts = CourseProgress.attempts + 1,
        is_completed = MAX(CourseProgress.is_completed, excluded.is_completed),
        last_answer_correct = excluded.last_answer_correct,
        last_attempt_at = CURRENT_TIMESTAMP
    `, [userId, courseId, questionId, isCorrect ? 1 : 0, isCorrect ? 1 : 0], (error) => {
      if (error) return reject(error);
      resolve();
    });
  });
}

app.get('/api/questions', requireLogin, async (req, res) => {
  try {
    const rows = Array.from(QUESTIONS_BY_ID.entries()).map(([questionId, question]) => ({
      id: questionId,
      question: question.q || question.question || question.title || questionId,
      category: question.category,
      level: question.level,
      question_type: question.t || 'unknown'
    }));
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/courses', requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const rows = await getAppRows(`
      SELECT DISTINCT c.id, c.title, c.description, c.published, c.owner_user_id, u.username AS owner_name,
        COUNT(DISTINCT cq.question_id) AS total_questions
      FROM Courses c
      JOIN CourseClasses cc ON cc.course_id = c.id
      JOIN ClassMembers cm ON cm.cid = cc.class_id
      LEFT JOIN CourseQuestions cq ON cq.course_id = c.id
      LEFT JOIN users u ON u.id = c.owner_user_id
      WHERE cm.id = ? AND c.published = 1
      GROUP BY c.id, c.title, c.description, c.published, c.owner_user_id, u.username
      ORDER BY c.id DESC
    `, [userId]);

    const enriched = await Promise.all(rows.map(async (course) => {
      const summary = await getCourseSummaryForUser(userId, course.id);
      return {
        id: course.id,
        title: course.title,
        description: course.description || '',
        published: Boolean(course.published),
        owner_user_id: course.owner_user_id,
        owner_name: course.owner_name || 'Unknown',
        totalQuestions: Number(course.total_questions || summary.totalQuestions || 0),
        attemptedCount: summary.attemptedCount,
        completedCount: summary.completedCount,
        correctCount: summary.correctCount,
        currentPercentage: summary.currentPercentage,
        lastStatus: summary.lastStatus
      };
    }));

    res.json(enriched);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/courses/:courseId', requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const courseId = Number(req.params.courseId);
    const courseRows = await getAppRows(`
      SELECT c.*, u.username AS owner_name
      FROM Courses c
      LEFT JOIN users u ON u.id = c.owner_user_id
      WHERE c.id = ? AND c.published = 1
    `, [courseId]);

    if (!courseRows.length) {
      return res.status(404).json({ error: 'Course not found.' });
    }

    if (!(await userCanAccessCourse(userId, courseId))) {
      return res.status(403).json({ error: 'You are not assigned to this course.' });
    }

    const course = courseRows[0];
    const questions = await getAppRows(`
      SELECT cq.question_id, q.question, q.category, q.level, q.question_type,
        COALESCE(cp.is_completed, 0) AS is_completed,
        COALESCE(cp.attempts, 0) AS attempts
      FROM CourseQuestions cq
      JOIN Questions q ON q.question_id = cq.question_id
      LEFT JOIN CourseProgress cp ON cp.course_id = cq.course_id
        AND cp.question_id = cq.question_id AND cp.user_id = ?
      WHERE cq.course_id = ?
      ORDER BY cq.position, cq.question_id
    `, [userId, courseId]);

    const summary = await getCourseSummaryForUser(userId, courseId);
    return res.json({
      ...course,
      totalQuestions: Number(summary.totalQuestions || questions.length || 0),
      attemptedCount: summary.attemptedCount,
      completedCount: summary.completedCount,
      correctCount: summary.correctCount,
      currentPercentage: summary.currentPercentage,
      questions: questions.map((question) => ({
        id: question.question_id,
        question: question.question,
        category: question.category,
        level: question.level,
        question_type: question.question_type,
        is_completed: Number(question.is_completed),
        attempts: Number(question.attempts)
      }))
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post('/api/course-answer', requireApiLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const courseId = Number(req.body && req.body.courseId);
    const questionId = String(req.body && req.body.questionId || '');
    const isCorrect = Boolean(req.body && req.body.isCorrect === true);

    if (!Number.isInteger(courseId) || courseId < 1) {
      return res.status(400).json({ error: 'A valid course ID is required.' });
    }
    if (!questionId || !QUESTIONS_BY_ID.has(questionId)) {
      return res.status(404).json({ error: 'Question not found.' });
    }
    if (!(await userCanAccessCourse(userId, courseId))) {
      return res.status(403).json({ error: 'You are not assigned to this course.' });
    }

    const courseQuestionRows = await getAppRows(
      'SELECT 1 FROM CourseQuestions WHERE course_id = ? AND question_id = ?',
      [courseId, questionId]
    );
    if (!courseQuestionRows.length) {
      return res.status(404).json({ error: 'This question is not part of the selected course.' });
    }

    await recordCourseProgress(userId, courseId, questionId, isCorrect);
    const summary = await getCourseSummaryForUser(userId, courseId);
    return res.json({ ok: true, summary });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get('/api/course-management', requireLogin, async (req, res) => {
  try {
    const user = req.session.user;
    let rows;
    if (user.role === 'Admin') {
      rows = await getAppRows(`
        SELECT c.*, u.username AS owner_name
        FROM Courses c
        LEFT JOIN users u ON u.id = c.owner_user_id
        ORDER BY c.id DESC
      `);
    } else if (user.role === 'Teacher') {
      rows = await getAppRows(`
        SELECT c.*, u.username AS owner_name
        FROM Courses c
        LEFT JOIN users u ON u.id = c.owner_user_id
        WHERE c.owner_user_id = ?
           OR (c.visibility = 'public' AND c.published = 1)
        ORDER BY c.id DESC
      `, [user.id]);
    } else {
      return res.status(403).json({ error: 'Teacher or admin access only.' });
    }

    const populated = await Promise.all(rows.map(async (course) => {
      const questions = await getAppRows(`
        SELECT cq.question_id, cq.position, q.question, q.category, q.level, q.question_type
        FROM CourseQuestions cq
        JOIN Questions q ON q.question_id = cq.question_id
        WHERE cq.course_id = ?
        ORDER BY cq.position, cq.question_id
      `, [course.id]);
      const classRows = await getAppRows(`
        SELECT cc.class_id, Classes.id AS teacher_id, users.username AS teacher_name
        FROM CourseClasses cc
        JOIN Classes ON Classes.cid = cc.class_id
        LEFT JOIN users ON users.id = Classes.id
        WHERE cc.course_id = ?
        ORDER BY cc.class_id
      `, [course.id]);
      return {
        ...course,
        visibility: course.visibility === 'public' ? 'public' : 'private',
        questionCount: questions.length,
        questions,
        classes: classRows,
        canEdit: user.role === 'Admin' || course.owner_user_id === user.id,
        canClone: course.owner_user_id !== user.id && course.visibility === 'public' && Boolean(course.published)
      };
    }));

    res.json(populated);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/course-management', requireLogin, async (req, res) => {
  try {
    const user = req.session.user;
    const title = String(req.body && req.body.title || '').trim();
    const description = String(req.body && req.body.description || '').trim();
    const visibility = req.body && req.body.visibility === 'public' ? 'public' : 'private';

    if (!title) {
      return res.status(400).json({ error: 'Course title is required.' });
    }
    if (user.role !== 'Admin' && user.role !== 'Teacher') {
      return res.status(403).json({ error: 'Teacher or admin access only.' });
    }

    const result = await runAppSql(
      'INSERT INTO Courses (title, description, visibility, published, owner_user_id) VALUES (?, ?, ?, 0, ?)',
      [title, description, visibility, user.id]
    );
    return res.status(201).json({ ok: true, course: { id: result.lastID, title, description, visibility, owner_user_id: user.id } });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post('/api/courses/:courseId/clone', requireLogin, async (req, res) => {
  try {
    const user = req.session.user;
    if (user.role !== 'Teacher' && user.role !== 'Admin') {
      return res.status(403).json({ error: 'Teacher or admin access only.' });
    }
    const courseId = Number(req.params.courseId);
    const sourceRows = await getAppRows(
      `SELECT * FROM Courses
       WHERE id = ? AND published = 1 AND visibility = 'public'`,
      [courseId]
    );
    if (!sourceRows.length) {
      return res.status(404).json({ error: 'Public course not found.' });
    }

    const source = sourceRows[0];
    const requestedTitle = String(req.body && req.body.title || '').trim();
    const title = requestedTitle || `${source.title} (Copy)`;
    const result = await runAppSql(
      `INSERT INTO Courses (title, description, visibility, published, owner_user_id)
       VALUES (?, ?, 'private', 0, ?)`,
      [title, source.description || '', user.id]
    );
    const questions = await getAppRows(
      'SELECT question_id, position FROM CourseQuestions WHERE course_id = ? ORDER BY position, question_id',
      [courseId]
    );
    for (const question of questions) {
      await runAppSql(
        'INSERT INTO CourseQuestions (course_id, question_id, position) VALUES (?, ?, ?)',
        [result.lastID, question.question_id, question.position]
      );
    }
    return res.status(201).json({
      ok: true,
      course: { id: result.lastID, title, description: source.description || '', visibility: 'private', published: false, owner_user_id: user.id, questionCount: questions.length }
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post('/api/courses/:courseId/questions', requireLogin, async (req, res) => {
  try {
    const user = req.session.user;
    const courseId = Number(req.params.courseId);
    const questionIds = Array.isArray(req.body && req.body.questionIds) ? req.body.questionIds : [];

    const courseRows = await getAppRows('SELECT * FROM Courses WHERE id = ?', [courseId]);
    if (!courseRows.length) {
      return res.status(404).json({ error: 'Course not found.' });
    }
    if (user.role !== 'Admin' && courseRows[0].owner_user_id !== user.id) {
      return res.status(403).json({ error: 'You cannot edit this course.' });
    }

    if (!questionIds.length) {
      return res.status(400).json({ error: 'At least one question is required.' });
    }

    for (let i = 0; i < questionIds.length; i += 1) {
      const questionId = String(questionIds[i]);
      if (!QUESTIONS_BY_ID.has(questionId)) {
        return res.status(400).json({ error: `Question not found in the registry: ${questionId}` });
      }
      await runAppSql(
        'INSERT OR IGNORE INTO CourseQuestions (course_id, question_id, position) VALUES (?, ?, ?)',
        [courseId, questionId, i]
      );
    }

    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.delete('/api/courses/:courseId/questions/:questionId', requireLogin, async (req, res) => {
  try {
    const user = req.session.user;
    const courseId = Number(req.params.courseId);
    const questionId = String(req.params.questionId);
    const courseRows = await getAppRows('SELECT owner_user_id FROM Courses WHERE id = ?', [courseId]);
    if (!courseRows.length) {
      return res.status(404).json({ error: 'Course not found.' });
    }
    if (user.role !== 'Admin' && courseRows[0].owner_user_id !== user.id) {
      return res.status(403).json({ error: 'You cannot edit this course.' });
    }

    const result = await runAppSql(
      'DELETE FROM CourseQuestions WHERE course_id = ? AND question_id = ?',
      [courseId, questionId]
    );
    if (!result.changes) {
      return res.status(404).json({ error: 'Question is not in this course.' });
    }

    const remaining = await getAppRows(
      'SELECT question_id FROM CourseQuestions WHERE course_id = ? ORDER BY position, question_id',
      [courseId]
    );
    for (let i = 0; i < remaining.length; i += 1) {
      await runAppSql('UPDATE CourseQuestions SET position = ? WHERE course_id = ? AND question_id = ?', [i, courseId, remaining[i].question_id]);
    }
    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.put('/api/courses/:courseId/questions', requireLogin, async (req, res) => {
  try {
    const user = req.session.user;
    const courseId = Number(req.params.courseId);
    const questionIds = Array.isArray(req.body && req.body.questionIds) ? req.body.questionIds.map(String) : null;
    const courseRows = await getAppRows('SELECT owner_user_id FROM Courses WHERE id = ?', [courseId]);
    if (!courseRows.length) {
      return res.status(404).json({ error: 'Course not found.' });
    }
    if (user.role !== 'Admin' && courseRows[0].owner_user_id !== user.id) {
      return res.status(403).json({ error: 'You cannot edit this course.' });
    }
    if (!questionIds || new Set(questionIds).size !== questionIds.length) {
      return res.status(400).json({ error: 'A unique ordered question list is required.' });
    }

    const existing = (await getAppRows('SELECT question_id FROM CourseQuestions WHERE course_id = ?', [courseId]))
      .map((row) => row.question_id)
      .sort();
    const requested = questionIds.slice().sort();
    if (existing.length !== requested.length || existing.some((questionId, index) => questionId !== requested[index])) {
      return res.status(400).json({ error: 'The reorder list must contain exactly the selected course questions.' });
    }

    for (let i = 0; i < questionIds.length; i += 1) {
      await runAppSql('UPDATE CourseQuestions SET position = ? WHERE course_id = ? AND question_id = ?', [i, courseId, questionIds[i]]);
    }
    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post('/api/courses/:courseId/classes', requireLogin, async (req, res) => {
  try {
    const user = req.session.user;
    const courseId = Number(req.params.courseId);
    const classIds = Array.isArray(req.body && req.body.classIds) ? req.body.classIds.map(Number) : [];
    const courseRows = await getAppRows('SELECT * FROM Courses WHERE id = ?', [courseId]);
    if (!courseRows.length) {
      return res.status(404).json({ error: 'Course not found.' });
    }
    if (user.role !== 'Admin' && courseRows[0].owner_user_id !== user.id) {
      return res.status(403).json({ error: 'You cannot edit this course.' });
    }

    for (const classId of classIds) {
      if (!Number.isInteger(classId) || classId < 1) {
        return res.status(400).json({ error: 'Each class must be a valid ID.' });
      }
      if (user.role !== 'Admin') {
        const teacherPermission = await getAppRows('SELECT 1 FROM ClassTeachers WHERE cid = ? AND id = ?', [classId, user.id]);
        if (!teacherPermission.length) {
          return res.status(403).json({ error: 'You can only assign a course to a class you teach.' });
        }
      }
      await runAppSql('INSERT OR IGNORE INTO CourseClasses (course_id, class_id) VALUES (?, ?)', [courseId, classId]);
    }

    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post('/api/courses/:courseId/publish', requireLogin, async (req, res) => {
  try {
    const user = req.session.user;
    const courseId = Number(req.params.courseId);
    const courseRows = await getAppRows('SELECT * FROM Courses WHERE id = ?', [courseId]);
    if (!courseRows.length) {
      return res.status(404).json({ error: 'Course not found.' });
    }
    if (user.role !== 'Admin' && courseRows[0].owner_user_id !== user.id) {
      return res.status(403).json({ error: 'You cannot publish this course.' });
    }

    const questionRows = await getAppRows('SELECT COUNT(*) AS total FROM CourseQuestions WHERE course_id = ?', [courseId]);
    const classRows = await getAppRows('SELECT COUNT(*) AS total FROM CourseClasses WHERE course_id = ?', [courseId]);
    if (!Number(questionRows[0]?.total)) {
      return res.status(400).json({ error: 'Add at least one question before publishing.' });
    }
    if (courseRows[0].visibility !== 'public' && !Number(classRows[0]?.total)) {
      return res.status(400).json({ error: 'Assign at least one class before publishing.' });
    }

    await runAppSql('UPDATE Courses SET published = 1 WHERE id = ?', [courseId]);
    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get('/api/teacher-class-data', requireLogin, async (req, res) => {
  try {
    const user = req.session.user;
    let classRows;
    if (user.role === 'Admin') {
      classRows = await getAppRows(`
        SELECT Classes.cid, Classes.id AS teacher_id, users.username AS teacher_name
        FROM Classes
        LEFT JOIN users ON users.id = Classes.id
        ORDER BY Classes.cid
      `);
    } else if (user.role === 'Teacher') {
      classRows = await getAppRows(`
        SELECT Classes.cid, Classes.id AS teacher_id, users.username AS teacher_name
        FROM Classes
        JOIN ClassTeachers ON ClassTeachers.cid = Classes.cid
        LEFT JOIN users ON users.id = Classes.id
        WHERE ClassTeachers.id = ?
        ORDER BY Classes.cid
      `, [user.id]);
    } else {
      return res.status(403).json({ error: 'Teacher or admin access only.' });
    }

    res.json({ classes: classRows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/teacher-course-progress', requireLogin, requireTeacher, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const courseId = Number(req.query.courseId);
    if (!Number.isInteger(courseId) || courseId < 1) {
      return res.status(400).json({ error: 'A valid course ID is required.' });
    }

    const courseRows = await getAppRows('SELECT * FROM Courses WHERE id = ? AND owner_user_id = ?', [courseId, userId]);
    if (!courseRows.length) {
      return res.status(403).json({ error: 'You do not have access to this course.' });
    }

    const students = await getAppRows(`
      SELECT DISTINCT users.id AS student_id, users.username AS student_name,
        (SELECT COUNT(*) FROM CourseQuestions WHERE course_id = ?) AS total_questions,
        (SELECT COUNT(*) FROM CourseProgress cp WHERE cp.user_id = users.id AND cp.course_id = ? AND cp.is_completed = 1) AS completed_questions,
        (SELECT COUNT(*) FROM CourseProgress cp WHERE cp.user_id = users.id AND cp.course_id = ? AND cp.attempts > 0) AS attempted_questions,
        (SELECT COUNT(*) FROM CourseProgress cp WHERE cp.user_id = users.id AND cp.course_id = ? AND cp.last_answer_correct = 1) AS correct_answers
      FROM ClassMembers
      JOIN users ON users.id = ClassMembers.id
      JOIN CourseClasses ON CourseClasses.class_id = ClassMembers.cid
      WHERE CourseClasses.course_id = ?
      ORDER BY users.username
    `, [courseId, courseId, courseId, courseId, courseId]);

    const progressRows = await getAppRows(`
      SELECT cp.user_id AS student_id, users.username AS student_name, cp.question_id,
        Questions.question, cp.attempts, cp.is_completed, cp.last_answer_correct, cp.last_attempt_at
      FROM CourseProgress cp
      JOIN users ON users.id = cp.user_id
      JOIN Questions ON Questions.question_id = cp.question_id
      WHERE cp.course_id = ?
      ORDER BY users.username, cp.last_attempt_at DESC
    `, [courseId]);

    return res.json({
      course: courseRows[0],
      students,
      progress: progressRows
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post('/api/question-progress', requireApiLogin, (req, res) => {
  const questionId = (req.body && req.body.questionId) ? String(req.body.questionId) : '';
  if (!questionId || !QUESTIONS_BY_ID.has(questionId)) {
    return res.status(404).json({ error: 'Question not found.' });
  }

  const isCorrect = Boolean(req.body && req.body.isCorrect === true);
  recordQuestionProgress(req.session.user.id, questionId, isCorrect)
    .then(() => res.json({ ok: true }))
    .catch((error) => res.status(500).json({ error: error.message }));
});

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
    ? '<div class="link-box"><a href="/admin-db">View database tables</a></div><div class="link-box"><a href="/admin-users">Manage users and classes</a></div>'
    : '';
  const teacherLinks = user.role === 'Teacher'
    ? '<div class="link-box"><a href="/teacher-progress">View class question progress</a></div><div class="link-box"><a href="/course-management">Manage courses</a></div>'
    : '';
  const courseManagementLink = (user.role === 'Teacher' || user.role === 'Admin')
    ? '<div class="link-box"><a href="/course-management">Manage courses</a></div>'
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
          ${courseManagementLink}
          ${teacherLinks}
          ${adminLinks}
        </div>
      </body>
    </html>
  `);
});

app.get('/course-management', requireLogin, (req, res) => {
  if (req.session.user.role !== 'Teacher' && req.session.user.role !== 'Admin') {
    return res.status(403).send('Teacher or admin access only.');
  }
  res.sendFile(path.join(__dirname, 'course-management.html'));
});

app.get('/teacher-progress', requireLogin, requireTeacher, (req, res) => {
  res.sendFile(path.join(__dirname, 'teacher-progress.html'));
});

app.get('/api/teacher-progress', requireLogin, requireTeacher, async (req, res) => {
  const teacherId = req.session.user.id;

  try {
    const classes = await getAppRows(
      'SELECT cid FROM ClassTeachers WHERE id = ? ORDER BY cid',
      [teacherId]
    );
    if (!classes.length) {
      return res.json({ classes: [], selectedClassId: null, totalQuestions: QUESTIONS_BY_ID.size, students: [], completedQuestions: [] });
    }

    const requestedClassId = req.query.classId ? Number(req.query.classId) : classes[0].cid;
    const selectedClass = classes.find((classRow) => classRow.cid === requestedClassId);
    if (!Number.isInteger(requestedClassId) || !selectedClass) {
      return res.status(404).json({ error: 'Class not found for this teacher.' });
    }

    const students = await getAppRows(`
      SELECT users.id, users.username,
        COUNT(DISTINCT question_progress.question_id) AS attempted_count,
        COUNT(DISTINCT CASE WHEN question_progress.is_completed = 1 THEN question_progress.question_id END) AS completed_count
      FROM ClassMembers
      JOIN users ON users.id = ClassMembers.id
      LEFT JOIN question_progress ON question_progress.user_id = users.id
      WHERE ClassMembers.cid = ?
      GROUP BY users.id, users.username
      ORDER BY users.username
    `, [requestedClassId]);

    const completedQuestions = await getAppRows(`
      SELECT users.id AS student_id, users.username AS student,
        Questions.question_id, Questions.question, Questions.category, Questions.level,
        question_progress.last_attempt_at
      FROM ClassMembers
      JOIN users ON users.id = ClassMembers.id
      JOIN question_progress ON question_progress.user_id = users.id AND question_progress.is_completed = 1
      JOIN Questions ON Questions.question_id = question_progress.question_id
      WHERE ClassMembers.cid = ?
      ORDER BY users.username, Questions.category, Questions.level, Questions.question_id
    `, [requestedClassId]);

    res.json({
      classes,
      selectedClassId: requestedClassId,
      totalQuestions: QUESTIONS_BY_ID.size,
      students,
      completedQuestions
    });
  } catch (error) {
    res.status(500).json({ error: `Unable to load class progress: ${error.message}` });
  }
});

app.get('/admin-db', requireLogin, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin-db.html'));
});

app.get('/admin-users', requireLogin, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin-users.html'));
});

app.get('/api/admin-users-data', requireLogin, requireAdmin, async (req, res) => {
  try {
    const users = await getAppRows('SELECT id, username, role FROM users ORDER BY username');
    const classes = await getAppRows(`
      SELECT Classes.cid, Classes.id AS teacher_id, users.username AS teacher
      FROM Classes
      JOIN users ON users.id = Classes.id
      ORDER BY Classes.cid
    `);
    const members = await getAppRows(`
      SELECT ClassMembers.cid, ClassMembers.id, users.username
      FROM ClassMembers
      JOIN users ON users.id = ClassMembers.id
      ORDER BY ClassMembers.cid, users.username
    `);
    const classTeachers = await getAppRows(`
      SELECT ClassTeachers.cid, ClassTeachers.id AS teacher_id, users.username AS teacher
      FROM ClassTeachers
      JOIN users ON users.id = ClassTeachers.id
      ORDER BY ClassTeachers.cid, users.username
    `);
    res.json({ users, classes, members, classTeachers });
  } catch (error) {
    res.status(500).json({ error: `Unable to load users and classes: ${error.message}` });
  }
});

app.post('/api/admin-users', requireLogin, requireAdmin, async (req, res) => {
  const username = req.body && typeof req.body.username === 'string' ? req.body.username.trim() : '';
  const password = req.body && typeof req.body.password === 'string' ? req.body.password : '';
  const role = req.body && typeof req.body.role === 'string' ? req.body.role : 'User';

  if (username.length < 3 || password.length < 6) {
    return res.status(400).json({ error: 'Username must be at least 3 characters and password at least 6 characters.' });
  }
  if (!['User', 'Teacher', 'Admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid user role.' });
  }

  try {
    const hashedPassword = bcrypt.hashSync(password, 10);
    const result = await runAppSql(
      'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
      [username, hashedPassword, role]
    );
    res.status(201).json({ ok: true, user: { id: result.lastID, username, role } });
  } catch (error) {
    const status = error.code === 'SQLITE_CONSTRAINT' ? 409 : 500;
    res.status(status).json({ error: status === 409 ? 'That username already exists.' : error.message });
  }
});

app.put('/api/admin-users/:id', requireLogin, requireAdmin, async (req, res) => {
  const userId = Number(req.params.id);
  const username = req.body && typeof req.body.username === 'string' ? req.body.username.trim() : '';
  const role = req.body && typeof req.body.role === 'string' ? req.body.role : '';

  if (!Number.isInteger(userId) || userId < 1) {
    return res.status(400).json({ error: 'A valid user is required.' });
  }
  if (username.length < 3) {
    return res.status(400).json({ error: 'Username must be at least 3 characters.' });
  }
  if (!['User', 'Teacher', 'Admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid user role.' });
  }

  try {
    const existingUsers = await getAppRows('SELECT id, role FROM users WHERE id = ?', [userId]);
    if (!existingUsers.length) {
      return res.status(404).json({ error: 'User not found.' });
    }

    if (existingUsers[0].role === 'Admin' && role !== 'Admin') {
      const admins = await getAppRows("SELECT COUNT(*) AS count FROM users WHERE role = 'Admin'");
      if (admins[0].count <= 1) {
        return res.status(409).json({ error: 'The last Admin account cannot be changed to another role.' });
      }
    }

    await runAppSql('UPDATE users SET username = ?, role = ? WHERE id = ?', [username, role, userId]);
    res.json({ ok: true, user: { id: userId, username, role } });
  } catch (error) {
    const status = error.code === 'SQLITE_CONSTRAINT' ? 409 : 500;
    res.status(status).json({ error: status === 409 ? 'That username is already in use.' : error.message });
  }
});

app.post('/api/admin-classes', requireLogin, requireAdmin, async (req, res) => {
  const teacherId = Number(req.body && req.body.teacherId);
  if (!Number.isInteger(teacherId) || teacherId < 1) {
    return res.status(400).json({ error: 'A valid teacher is required.' });
  }

  try {
    const teacher = await getAppRows("SELECT id, username FROM users WHERE id = ? AND role = 'Teacher'", [teacherId]);
    if (!teacher.length) {
      return res.status(404).json({ error: 'Teacher not found. Choose a user with the Teacher role.' });
    }
    const result = await runAppSql('INSERT INTO Classes (id) VALUES (?)', [teacherId]);
    await runAppSql('INSERT INTO ClassTeachers (cid, id) VALUES (?, ?)', [result.lastID, teacherId]);
    res.status(201).json({ ok: true, class: { cid: result.lastID, teacher_id: teacherId, teacher: teacher[0].username } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin-class-teachers', requireLogin, requireAdmin, async (req, res) => {
  const teacherId = Number(req.body && req.body.teacherId);
  const classId = Number(req.body && req.body.classId);
  if (!Number.isInteger(teacherId) || teacherId < 1 || !Number.isInteger(classId) || classId < 1) {
    return res.status(400).json({ error: 'A valid teacher and class are required.' });
  }

  try {
    const teacher = await getAppRows("SELECT id, username FROM users WHERE id = ? AND role = 'Teacher'", [teacherId]);
    if (!teacher.length) {
      return res.status(404).json({ error: 'Teacher not found.' });
    }
    const classRows = await getAppRows('SELECT cid FROM Classes WHERE cid = ?', [classId]);
    if (!classRows.length) {
      return res.status(404).json({ error: 'Class not found.' });
    }
    await runAppSql('INSERT INTO ClassTeachers (cid, id) VALUES (?, ?)', [classId, teacherId]);
    res.status(201).json({ ok: true, assignment: { cid: classId, teacher_id: teacherId, teacher: teacher[0].username } });
  } catch (error) {
    const status = error.code === 'SQLITE_CONSTRAINT' ? 409 : 500;
    res.status(status).json({ error: status === 409 ? 'That teacher is already assigned to this class.' : error.message });
  }
});

app.post('/api/admin-class-members', requireLogin, requireAdmin, async (req, res) => {
  const userId = Number(req.body && req.body.userId);
  const classId = Number(req.body && req.body.classId);
  if (!Number.isInteger(userId) || userId < 1 || !Number.isInteger(classId) || classId < 1) {
    return res.status(400).json({ error: 'A valid user and class are required.' });
  }

  try {
    const user = await getAppRows("SELECT id, username FROM users WHERE id = ? AND role = 'User'", [userId]);
    if (!user.length) {
      return res.status(404).json({ error: 'Student user not found.' });
    }
    const classRows = await getAppRows('SELECT cid FROM Classes WHERE cid = ?', [classId]);
    if (!classRows.length) {
      return res.status(404).json({ error: 'Class not found.' });
    }
    await runAppSql('INSERT INTO ClassMembers (id, cid) VALUES (?, ?)', [userId, classId]);
    res.status(201).json({ ok: true, member: { id: userId, username: user[0].username, cid: classId } });
  } catch (error) {
    const status = error.code === 'SQLITE_CONSTRAINT' ? 409 : 500;
    res.status(status).json({ error: status === 409 ? 'That user is already in this class.' : error.message });
  }
});

app.get('/api/admin-db-data', requireLogin, requireAdmin, async (req, res) => {
  try {
    const appTables = (await getDatabaseTables(db)).filter((tableName) => tableName !== 'question_progress');
    const practiceTables = await getDatabaseTables(practiceDb);

    const appRows = await Promise.all(appTables.map(async (tableName) => ({
      name: tableName,
      rows: await getTableRows(db, tableName)
    })));

    const practiceRows = await Promise.all(practiceTables.map(async (tableName) => ({
      name: tableName,
      rows: await getTableRows(practiceDb, tableName)
    })));
    const progressRows = await new Promise((resolve, reject) => {
      db.all(`
        SELECT users.username AS student,
          Questions.question_id,
          Questions.question,
          Questions.category,
          Questions.level,
          CASE WHEN question_progress.is_completed = 1 THEN 'Completed' ELSE 'Attempted' END AS status,
          question_progress.attempts,
          CASE WHEN question_progress.last_answer_correct = 1 THEN 'Correct' ELSE 'Incorrect' END AS latest_result,
          question_progress.last_attempt_at
        FROM question_progress
        JOIN users ON users.id = question_progress.user_id
        JOIN Questions ON Questions.question_id = question_progress.question_id
        ORDER BY users.username, question_progress.last_attempt_at DESC
      `, (error, rows) => {
        if (error) return reject(error);
        resolve(rows || []);
      });
    });
    appRows.push({ name: 'question_progress', rows: progressRows });

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
      await initializePracticeDatabase(sql);
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
    await recordQuestionProgress(req.session.user.id, question.id, false);
    return res.status(400).json({ error: 'Only SELECT / WITH / EXPLAIN / INSERT / UPDATE / DELETE / ALTER queries are allowed.' });
  }

  try {
    const result = await queueSqlTask(() => checkMasterSqlAnswer(question, sql));
    await recordQuestionProgress(req.session.user.id, question.id, result.isCorrect);

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
    await recordQuestionProgress(req.session.user.id, question.id, false);
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
  .then(() => {
    app.listen(port, () => {
      console.log(`Server running on http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error('Database initialization failed:', err.message);
    process.exit(1);
  });
