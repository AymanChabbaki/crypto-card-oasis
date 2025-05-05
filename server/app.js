
import express from 'express';
import { createPool } from 'mysql2/promise';
import cors from 'cors';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

// Initialize Express app
const app = express();

// Configuration
const config = {
  port: process.env.PORT || 5000,
  jwt: {
    secret: process.env.JWT_SECRET || 'df52e04a310d9882ebb2e91242f81c9ecd8f69f1f117dc4a04da7d1ee305ef2ddcfe684845273e5283f7e2cae8faa2e3f64f976bb0c74b4416a25de66661579820fb04aba6ff45d745069dca86590ff2ec3300c9725df96dffb6b9cf3636ec2fefd910ed39646887deef794c76c33b9c38c47006bc034c609456952b89cca8d12668401ac01ac09846dcab29b9d9b614d602ace761d1cb4fc3dccf752907fbd0a3aad2b6c9c6134e9683d5da31d092e9d442f5834a96064a500e144d10f4fb504f4c032a282435b2f868ca79dffdebedfd03624d1d5ce7a92f460eb313d6a73eb894f768dc01f74206ac7b36709150d3bf62c37226341d350586e431aedc8b4c',
    expire: process.env.JWT_EXPIRE || '90d'
  },
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true
  }
};

// Database connection pool
const pool = createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'cryptocard_oasis',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware
app.use(cors(config.cors));
app.use(express.json());
app.use(cookieParser());
app.use(morgan('dev'));

// Utility functions
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, config.jwt.secret, {
    expiresIn: config.jwt.expire
  });
};

const verifyToken = (token) => {
  return jwt.verify(token, config.jwt.secret);
};

// Authentication Middleware
const authenticate = async (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  try {
    const decoded = verifyToken(token);
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [decoded.id]);
    
    if (users.length === 0) {
      return res.status(401).json({ message: 'User not found' });
    }

    req.user = users[0];
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// API Endpoints

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, name, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    await pool.query(
      'INSERT INTO users (id, email, name, password) VALUES (?, ?, ?, ?)',
      [userId, email, name, hashedPassword]
    );

    const token = generateToken(userId);
    res.cookie('token', token, { httpOnly: true });
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: 'Email already exists' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

    if (users.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = generateToken(user.id);
    res.cookie('token', token, { httpOnly: true });
    res.json({ message: 'Logged in successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

// User Routes
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, email, name, role, walletBalance FROM users WHERE id = ?', [req.params.id]);
    
    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(users[0]);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { name } = req.body;
    await pool.query('UPDATE users SET name = ? WHERE id = ?', [name, req.params.id]);
    res.json({ message: 'User updated successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/users/:id/holdings', authenticate, async (req, res) => {
  try {
    const [holdings] = await pool.query('SELECT * FROM cryptoHoldings WHERE userId = ?', [req.params.id]);
    res.json(holdings);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Transaction Routes
app.get('/api/transactions', authenticate, async (req, res) => {
  try {
    const [transactions] = await pool.query('SELECT * FROM transactions WHERE userId = ?', [req.user.id]);
    res.json(transactions);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/transactions/:id', authenticate, async (req, res) => {
  try {
    const [transactions] = await pool.query('SELECT * FROM transactions WHERE id = ? AND userId = ?', [req.params.id, req.user.id]);
    
    if (transactions.length === 0) {
      return res.status(404).json({ message: 'Transaction not found' });
    }

    res.json(transactions[0]);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/transactions', authenticate, async (req, res) => {
  try {
    const { type, cryptoId, cryptoSymbol, cryptoName, amount, price, total, paymentMethod } = req.body;
    const transactionId = uuidv4();

    await pool.query(
      `INSERT INTO transactions 
      (id, userId, type, cryptoId, cryptoSymbol, cryptoName, amount, price, total, paymentMethod) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [transactionId, req.user.id, type, cryptoId, cryptoSymbol, cryptoName, amount, price, total, paymentMethod]
    );

    res.status(201).json({ message: 'Transaction created successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/transactions/:id/approve', authenticate, async (req, res) => {
  try {
    await pool.query(
      `UPDATE transactions 
      SET status = 'completed', completedAt = CURRENT_TIMESTAMP 
      WHERE id = ? AND userId = ?`,
      [req.params.id, req.user.id]
    );
    res.json({ message: 'Transaction approved successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/transactions/:id/cancel', authenticate, async (req, res) => {
  try {
    const { reason } = req.body;
    await pool.query(
      `UPDATE transactions 
      SET status = 'cancelled', cancelledAt = CURRENT_TIMESTAMP, cancelReason = ? 
      WHERE id = ? AND userId = ?`,
      [reason, req.params.id, req.user.id]
    );
    res.json({ message: 'Transaction cancelled successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/transactions/pending', authenticate, async (req, res) => {
  try {
    const [transactions] = await pool.query(
      `SELECT * FROM transactions 
      WHERE userId = ? AND status = 'pending'`,
      [req.user.id]
    );
    res.json(transactions);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Crypto Routes
app.get('/api/crypto', authenticate, async (req, res) => {
  try {
    // In a real app, you would fetch from a crypto API or your database
    const mockCryptos = [
      { id: 'bitcoin', symbol: 'BTC', name: 'Bitcoin' },
      { id: 'ethereum', symbol: 'ETH', name: 'Ethereum' }
    ];
    res.json(mockCryptos);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/crypto/:id', authenticate, async (req, res) => {
  try {
    // In a real app, you would fetch details for the specific crypto
    res.json({
      id: req.params.id,
      symbol: req.params.id.toUpperCase(),
      name: req.params.id.charAt(0).toUpperCase() + req.params.id.slice(1),
      price: Math.random() * 10000,
      marketCap: Math.random() * 100000000000,
      volume: Math.random() * 1000000000
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Watchlist Routes
app.get('/api/watchlist', authenticate, async (req, res) => {
  try {
    const [watchlists] = await pool.query(
      `SELECT wi.cryptoId 
      FROM watchlists w
      JOIN watchlist_items wi ON w.id = wi.watchlistId
      WHERE w.userId = ?`,
      [req.user.id]
    );
    res.json(watchlists.map(item => item.cryptoId));
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/watchlist', authenticate, async (req, res) => {
  try {
    const { cryptoId } = req.body;
    
    // Get or create watchlist for user
    let [watchlists] = await pool.query(
      'SELECT id FROM watchlists WHERE userId = ?',
      [req.user.id]
    );

    if (watchlists.length === 0) {
      const watchlistId = uuidv4();
      await pool.query(
        'INSERT INTO watchlists (id, userId) VALUES (?, ?)',
        [watchlistId, req.user.id]
      );
      watchlists = [{ id: watchlistId }];
    }

    // Add to watchlist
    await pool.query(
      'INSERT INTO watchlist_items (watchlistId, cryptoId) VALUES (?, ?)',
      [watchlists[0].id, cryptoId]
    );

    res.status(201).json({ message: 'Added to watchlist' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: 'Already in watchlist' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/watchlist/:cryptoId', authenticate, async (req, res) => {
  try {
    const [watchlists] = await pool.query(
      'SELECT id FROM watchlists WHERE userId = ?',
      [req.user.id]
    );

    if (watchlists.length === 0) {
      return res.status(404).json({ message: 'Watchlist not found' });
    }

    await pool.query(
      'DELETE FROM watchlist_items WHERE watchlistId = ? AND cryptoId = ?',
      [watchlists[0].id, req.params.cryptoId]
    );

    res.json({ message: 'Removed from watchlist' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something broke!' });
});

// Start server
app.listen(config.port, () => {
  console.log(`Server running on port ${config.port}`);
});

export default app;