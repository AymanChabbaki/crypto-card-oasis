
/**
 * Database Structure for CryptoCard Oasis
 * 
 * This file contains the suggested database schema for the CryptoCard Oasis application.
 * You can implement this using your preferred database technology.
 */

/**
 * users table
 * Stores user account information
 * 
 * Schema:
 * {
 *   id: string (primary key, uuid),
 *   email: string (unique),
 *   name: string,
 *   role: enum('user', 'admin'),
 *   walletBalance: number,
 *   createdAt: timestamp,
 *   updatedAt: timestamp
 * }
 */

/**
 * cryptoHoldings table
 * Stores cryptocurrency holdings for each user
 * 
 * Schema:
 * {
 *   id: string (primary key, uuid),
 *   userId: string (foreign key -> users.id),
 *   cryptoId: string,
 *   symbol: string,
 *   name: string,
 *   amount: number,
 *   purchasedAt: timestamp,
 *   updatedAt: timestamp
 * }
 */

/**
 * transactions table
 * Stores all cryptocurrency transactions
 * 
 * Schema:
 * {
 *   id: string (primary key, uuid),
 *   userId: string (foreign key -> users.id),
 *   type: enum('buy', 'sell', 'deposit', 'withdraw'),
 *   status: enum('pending', 'completed', 'cancelled'),
 *   cryptoId: string,
 *   cryptoSymbol: string,
 *   cryptoName: string,
 *   amount: number,
 *   price: number,
 *   total: number,
 *   paymentMethod: string,
 *   createdAt: timestamp,
 *   updatedAt: timestamp,
 *   completedAt: timestamp,
 *   cancelledAt: timestamp,
 *   cancelReason: string
 * }
 */

/**
 * watchlists table
 * Stores watchlists for each user
 * 
 * Schema:
 * {
 *   id: string (primary key, uuid),
 *   userId: string (foreign key -> users.id),
 *   cryptoIds: array<string>,
 *   createdAt: timestamp,
 *   updatedAt: timestamp
 * }
 */

/**
 * API Endpoints:
 * 
 * Authentication:
 * - POST /api/auth/register - Register a new user
 * - POST /api/auth/login - Login user
 * - POST /api/auth/logout - Logout user
 * 
 * Users:
 * - GET /api/users/:id - Get user profile
 * - PUT /api/users/:id - Update user profile
 * - GET /api/users/:id/holdings - Get user crypto holdings
 * 
 * Transactions:
 * - GET /api/transactions - Get all transactions
 * - GET /api/transactions/:id - Get transaction by id
 * - POST /api/transactions - Create a new transaction
 * - PUT /api/transactions/:id/approve - Approve transaction
 * - PUT /api/transactions/:id/cancel - Cancel transaction
 * - GET /api/transactions/pending - Get all pending transactions
 * 
 * Crypto:
 * - GET /api/crypto - Get all cryptocurrencies
 * - GET /api/crypto/:id - Get cryptocurrency by id
 * 
 * Watchlist:
 * - GET /api/watchlist - Get user's watchlist
 * - POST /api/watchlist - Add crypto to watchlist
 * - DELETE /api/watchlist/:cryptoId - Remove crypto from watchlist
 */
