
export interface Cryptocurrency {
  id: string;
  rank: number;
  name: string;
  symbol: string;
  price: number;
  priceChange1h: number;
  priceChange24h: number;
  priceChange7d: number;
  volume24h: number;
  marketCap: number;
  image: string;
}

export interface Transaction {
  id: string;
  userId: string;
  type: 'buy' | 'sell' | 'deposit' | 'withdrawal';
  status: 'pending' | 'completed' | 'cancelled';
  amount: number;
  cryptoAmount?: number;
  cryptocurrency?: string;
  cryptoSymbol?: string;
  date: Date;
  paymentDetails?: {
    cardNumber?: string;
    name?: string;
    walletAddress?: string;
    country?: string;
    phoneNumber?: string;
  };
  cancellationReason?: string;
}

export interface CryptoHolding {
  cryptoId: string;
  name: string;
  symbol: string;
  amount: number;
  image?: string;
}

export interface CryptoContextType {
  cryptocurrencies: Cryptocurrency[];
  loading: boolean;
  transactions: Transaction[];
  pendingTransactions: Transaction[];
  addTransaction: (transaction: Omit<Transaction, 'id' | 'date'>) => void;
  approveTransaction: (transactionId: string) => void;
  cancelTransaction: (transactionId: string, reason: string) => void;
  getUserTransactions: (userId: string) => Transaction[];
  addToWatchlist: (cryptoId: string) => void;
  removeFromWatchlist: (cryptoId: string) => void;
  watchlist: string[];
  loadSavedTransactions: () => void;
}
