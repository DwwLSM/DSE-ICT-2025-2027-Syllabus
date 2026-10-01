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

function createMasterSqlChecker({
  initializePracticeDatabase,
  executePracticeSql,
  fetchTableRows,
  fetchTableSchema,
  runSqlQuery
}) {
  async function runCanonicalModelResult(question) {
    const modelSql = (question && (question.expectedQuery || question.sample) || '').trim();
    if (!modelSql) {
      throw new Error('Model SQL is missing for this Master SQL question.');
    }

    await initializePracticeDatabase(question);

    if (question.type === 'mutation') {
      await executePracticeSql(modelSql);
      const expectedRows = question.check === 'schema'
        ? await fetchTableSchema(question.table)
        : await fetchTableRows(question.table);

      return { expectedRows, expectedQuery: modelSql, modelSql };
    }

    const expectedRows = await runSqlQuery(modelSql);
    return { expectedRows, expectedQuery: modelSql, modelSql };
  }

  return async function checkMasterSqlAnswer(question, sql) {
    const modelResult = await runCanonicalModelResult(question);
    await initializePracticeDatabase(question);

    if (question.type === 'mutation') {
      await executePracticeSql(sql);
      const studentRows = question.check === 'schema'
        ? await fetchTableSchema(question.table)
        : await fetchTableRows(question.table);

      return {
        isCorrect: compareRows(studentRows, modelResult.expectedRows),
        studentRows,
        expectedRows: modelResult.expectedRows,
        expectedQuery: modelResult.expectedQuery,
        question
      };
    }

    const studentRows = await runSqlQuery(sql);
    return {
      isCorrect: compareRows(studentRows, modelResult.expectedRows),
      studentRows,
      expectedRows: modelResult.expectedRows,
      expectedQuery: modelResult.expectedQuery,
      question
    };
  };
}

module.exports = { createMasterSqlChecker };