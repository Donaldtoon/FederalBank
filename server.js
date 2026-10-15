const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT) || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'accounts.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// --------------------------------------------------
// APPLICATION CONFIGURATION
// --------------------------------------------------

app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({
  limit: '20kb'
}));

app.use(express.urlencoded({
  extended: false,
  limit: '20kb'
}));

if (IS_PRODUCTION) {
  app.set('trust proxy', 1);
}

// --------------------------------------------------
// SESSION CONFIGURATION
// --------------------------------------------------

app.use(session({
  name: 'fcb.sid',
  secret: process.env.SESSION_SECRET ||
    'local-simulation-secret-change-before-deployment',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PRODUCTION,
    maxAge: 1000 * 60 * 60
  }
}));

// Limit repeated login and logout requests.
app.use('/api/auth', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

// --------------------------------------------------
// DATABASE FUNCTIONS
// --------------------------------------------------

function ensureDataFile() {
  fs.mkdirSync(DATA_DIR, {
    recursive: true
  });

  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(
      DATA_FILE,
      JSON.stringify({
        accounts: [],
        transactions: []
      }, null, 2),
      'utf8'
    );
  }
}

function readDatabase() {
  ensureDataFile();

  const db = JSON.parse(
    fs.readFileSync(DATA_FILE, 'utf8')
  );

  if (
    !db ||
    !Array.isArray(db.accounts) ||
    !Array.isArray(db.transactions)
  ) {
    throw new Error(
      'accounts.json must contain accounts and transactions arrays.'
    );
  }

  return db;
}

function writeDatabase(db) {
  ensureDataFile();

  const tempFile = DATA_FILE + '.tmp';

  fs.writeFileSync(
    tempFile,
    JSON.stringify(db, null, 2),
    'utf8'
  );

  fs.renameSync(tempFile, DATA_FILE);
}

// --------------------------------------------------
// ACCOUNT DATA
// --------------------------------------------------

function publicAccount(account) {
  return {
    id: account.id,
    username: account.username,
    name: account.name,
    accountNumber: account.accountNumber,

    accountType:
      account.accountType || 'Everyday Checking',

    checkingBalance: Number(
      account.checkingBalance ??
      account.balance ??
      0
    ).toFixed(2),

    savingsBalance: Number(
      account.savingsBalance ?? 0
    ).toFixed(2),

    savingsAccountNumber:
      account.savingsAccountNumber ||
      account.accountNumber
  };
}

function getCurrentAccount(req, db) {
  return db.accounts.find(
    account => account.id === req.session.accountId
  );
}

function requireAuth(req, res, next) {
  if (!req.session.accountId) {
    return res.status(401).json({
      success: false,
      message: 'Please sign in to continue.'
    });
  }

  next();
}

function validAmount(value) {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    value > 0 &&
    value <= 1000000 &&
    Math.round(value * 100) === value * 100
  );
}

// --------------------------------------------------
// INITIALIZE EXISTING ACCOUNTS
// --------------------------------------------------

function initializeAccounts() {
  const db = readDatabase();

  let changed = false;

  const initialPassword =
    process.env.INITIAL_ACCOUNT_PASSWORD;

  for (const account of db.accounts) {

    // Migrate an older single balance to checking.
    // Existing checking and savings balances remain separate.
    if (account.checkingBalance === undefined) {
      account.checkingBalance = Number(
        account.balance || 0
      );

      delete account.balance;

      changed = true;
    }

    if (account.savingsBalance === undefined) {
      account.savingsBalance = 0;
      changed = true;
    }

    // Set a password hash only if one is missing and
    // INITIAL_ACCOUNT_PASSWORD has explicitly been configured.
    if (!account.passwordHash && initialPassword) {
      account.passwordHash = bcrypt.hashSync(
        initialPassword,
        12
      );

      changed = true;
    }
  }

  if (changed) {
    writeDatabase(db);
  }

  if (
    db.accounts.some(account => !account.passwordHash)
  ) {
    console.warn(
      'Account setup required: configure INITIAL_ACCOUNT_PASSWORD ' +
      'in your terminal and restart the server.'
    );
  }
}

initializeAccounts();

// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    app: 'Local Banking Simulation API',
    simulation: true
  });
});

// --------------------------------------------------
// LOGIN
// --------------------------------------------------

app.post('/api/auth/login', async (req, res) => {
  try {
    const username = String(
      req.body.username || ''
    ).trim().toLowerCase();

    const password = String(
      req.body.password || ''
    );

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Enter your username and password.'
      });
    }

    const db = readDatabase();

    const account = db.accounts.find(
      item =>
        String(item.username || '').toLowerCase() ===
        username
    );

    if (account && !account.passwordHash) {
      return res.status(503).json({
        success: false,
        message:
          'Initial setup is incomplete. Configure ' +
          'INITIAL_ACCOUNT_PASSWORD and restart the server.'
      });
    }

    if (
      !account ||
      !(await bcrypt.compare(
        password,
        account.passwordHash
      ))
    ) {
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password.'
      });
    }

    // Regenerate the session after successful authentication.
    req.session.regenerate(err => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: 'Could not start your session.'
        });
      }

      req.session.accountId = account.id;

      req.session.save(saveError => {
        if (saveError) {
          return res.status(500).json({
            success: false,
            message: 'Could not save your session.'
          });
        }

        return res.json({
          success: true,
          account: publicAccount(account)
        });
      });
    });

  } catch (err) {
    console.error('Login error:', err.message);

    res.status(500).json({
      success: false,
      message: 'Unable to sign in right now.'
    });
  }
});

// --------------------------------------------------
// LOGOUT
// --------------------------------------------------

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: 'Could not sign out.'
      });
    }

    res.clearCookie('fcb.sid');

    res.json({
      success: true
    });
  });
});

// --------------------------------------------------
// CURRENT ACCOUNT
// --------------------------------------------------

app.get('/api/me', requireAuth, (req, res) => {
  const db = readDatabase();

  const account = getCurrentAccount(req, db);

  if (!account) {
    return res.status(401).json({
      success: false,
      message: 'Session account not found. Please sign in again.'
    });
  }

  res.json({
    success: true,
    account: publicAccount(account)
  });
});

// --------------------------------------------------
// TRANSACTION HISTORY
// --------------------------------------------------

app.get('/api/transactions', requireAuth, (req, res) => {
  const db = readDatabase();

  const account = getCurrentAccount(req, db);

  if (!account) {
    return res.status(401).json({
      success: false,
      message: 'Please sign in again.'
    });
  }

  const transactions = db.transactions
    .filter(tx => tx.accountId === account.id)
    .slice()
    .reverse()
    .slice(0, 50);

  res.json({
    success: true,
    transactions
  });
});

// --------------------------------------------------
// ACCOUNT TYPE HELPERS
// --------------------------------------------------

function normalizeAccountType(value) {
  if (value === 'savings') {
    return 'savings';
  }

  if (
    value === 'checking' ||
    value === undefined ||
    value === ''
  ) {
    return 'checking';
  }

  return null;
}

function balanceKey(accountType) {
  return accountType === 'savings'
    ? 'savingsBalance'
    : 'checkingBalance';
}

function recordTransaction(
  db,
  account,
  type,
  amount,
  description,
  accountType
) {
  db.transactions.push({
    id:
      'TX' +
      Date.now() +
      Math.random().toString(36).slice(2, 7).toUpperCase(),

    accountId: account.id,
    accountType,
    type,
    amount: amount.toFixed(2),
    description,
    createdAt: new Date().toISOString()
  });
}

// --------------------------------------------------
// DEPOSIT
// --------------------------------------------------

app.post(
  '/api/transactions/deposit',
  requireAuth,
  (req, res) => {

    const amount = Number(req.body.amount);

    const accountType = normalizeAccountType(
      req.body.accountType
    );

    if (!validAmount(amount) || !accountType) {
      return res.status(400).json({
        success: false,
        message:
          'Choose Checking or Savings and enter a valid amount.'
      });
    }

    const db = readDatabase();

    const account = getCurrentAccount(req, db);

    if (!account) {
      return res.status(401).json({
        success: false,
        message: 'Please sign in again.'
      });
    }

    const key = balanceKey(accountType);

    account[key] = Math.round(
      (Number(account[key] || 0) + amount) * 100
    ) / 100;

    const label =
      accountType.charAt(0).toUpperCase() +
      accountType.slice(1);

    recordTransaction(
      db,
      account,
      'Deposit',
      amount,
      `Deposit — ${label}`,
      accountType
    );

    writeDatabase(db);

    res.json({
      success: true,
      account: publicAccount(account),
      message:
        `Deposit recorded in ${accountType} account.`
    });
  }
);

// --------------------------------------------------
// WITHDRAWAL
// --------------------------------------------------

app.post(
  '/api/transactions/withdraw',
  requireAuth,
  (req, res) => {

    const amount = Number(req.body.amount);

    const accountType = normalizeAccountType(
      req.body.accountType
    );

    if (!validAmount(amount) || !accountType) {
      return res.status(400).json({
        success: false,
        message:
          'Choose Checking or Savings and enter a valid amount.'
      });
    }

    const db = readDatabase();

    const account = getCurrentAccount(req, db);

    if (!account) {
      return res.status(401).json({
        success: false,
        message: 'Please sign in again.'
      });
    }

    const key = balanceKey(accountType);

    account[key] = Number(account[key] || 0);

    if (amount > account[key]) {
      return res.status(400).json({
        success: false,
        message:
          `Insufficient ${accountType} balance.`
      });
    }

    account[key] = Math.round(
      (account[key] - amount) * 100
    ) / 100;

    const label =
      accountType.charAt(0).toUpperCase() +
      accountType.slice(1);

    recordTransaction(
      db,
      account,
      'Withdrawal',
      -amount,
      `Withdrawal — ${label}`,
      accountType
    );

    writeDatabase(db);

    res.json({
      success: true,
      account: publicAccount(account),
      message:
        `Withdrawal recorded in ${accountType} account.`
    });
  }
);

// --------------------------------------------------
// TRANSFER
// --------------------------------------------------

app.post(
  '/api/transactions/transfer',
  requireAuth,
  (req, res) => {

    const amount = Number(req.body.amount);

    const recipientNo = String(
      req.body.accountNumber || ''
    ).trim();

    const accountType = normalizeAccountType(
      req.body.accountType
    );

    if (
      !validAmount(amount) ||
      !recipientNo ||
      !accountType
    ) {
      return res.status(400).json({
        success: false,
        message:
          'Provide a valid recipient account, transfer source, and amount.'
      });
    }

    const db = readDatabase();

    const account = getCurrentAccount(req, db);

    if (!account) {
      return res.status(401).json({
        success: false,
        message: 'Please sign in again.'
      });
    }

    if (
      String(account.accountNumber) === recipientNo
    ) {
      return res.status(400).json({
        success: false,
        message:
          'Cannot transfer funds to the originating account.'
      });
    }

    const recipient = db.accounts.find(
      item =>
        String(item.accountNumber) === recipientNo
    );

    if (!recipient) {
      return res.status(404).json({
        success: false,
        message:
          'Recipient account was not found in this simulation.'
      });
    }

    const key = balanceKey(accountType);

    account[key] = Number(account[key] || 0);

    if (amount > account[key]) {
      return res.status(400).json({
        success: false,
        message:
          `Insufficient funds in the selected ${accountType} account.`
      });
    }

    // Deduct from the selected source account only.
    account[key] = Math.round(
      (account[key] - amount) * 100
    ) / 100;

    // Credit the recipient's checking balance.
    recipient.checkingBalance = Math.round(
      (
        Number(
          recipient.checkingBalance ??
          recipient.balance ??
          0
        ) + amount
      ) * 100
    ) / 100;

    delete recipient.balance;

    recordTransaction(
      db,
      account,
      'Transfer',
      -amount,
      `Transfer to account ending ${recipientNo.slice(-4)}`,
      accountType
    );

    recordTransaction(
      db,
      recipient,
      'Transfer',
      amount,
      `Transfer from account ending ${String(
        account.accountNumber
      ).slice(-4)}`,
      'checking'
    );

    writeDatabase(db);

    res.json({
      success: true,
      account: publicAccount(account),
      message: 'Transfer recorded successfully.'
    });
  }
);

// --------------------------------------------------
// FRONTEND
// --------------------------------------------------

// Serve files such as index.html and app.js from public/.
app.use(express.static(PUBLIC_DIR));

// Serve the homepage.
// This replaces the invalid Express 5 route pattern '(.*)'.
app.get('/', (req, res) => {
  res.sendFile(
    path.join(PUBLIC_DIR, 'index.html')
  );
});

// --------------------------------------------------
// ERROR HANDLER
// --------------------------------------------------

app.use((err, req, res, next) => {
  console.error('Server error:', err.message);

  if (req.path.startsWith('/api/')) {
    return res.status(500).json({
      success: false,
      message:
        'A server error occurred. Check the terminal for details.'
    });
  }

  res.status(500).send(
    'A server error occurred. Check the server terminal.'
  );
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(PORT, () => {
  console.log(
    `Local banking simulation running at http://localhost:${PORT}`
  );
});