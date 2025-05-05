
import React, { createContext, useContext } from 'react';
import { useCryptoOperations } from '@/hooks/useCryptoOperations';
import { useTransactionOperations } from '@/hooks/useTransactionOperations';
import type { CryptoContextType } from '@/types/crypto';

const CryptoContext = createContext<CryptoContextType | undefined>(undefined);

export function CryptoProvider({ children }: { children: React.ReactNode }) {
  const {
    cryptocurrencies,
    transactions,
    loading,
    watchlist,
    pendingTransactions,
    setTransactions,
    setWatchlist,
    addToWatchlist,
    removeFromWatchlist,
    loadSavedTransactions
  } = useCryptoOperations();

  const {
    addTransaction,
    approveTransaction,
    cancelTransaction,
    getUserTransactions
  } = useTransactionOperations(transactions, setTransactions);

  const value = {
    cryptocurrencies,
    loading,
    transactions,
    pendingTransactions,
    addTransaction,
    approveTransaction,
    cancelTransaction,
    getUserTransactions,
    addToWatchlist,
    removeFromWatchlist,
    watchlist,
    loadSavedTransactions
  };

  return <CryptoContext.Provider value={value}>{children}</CryptoContext.Provider>;
}

export const useCrypto = (): CryptoContextType => {
  const context = useContext(CryptoContext);
  if (context === undefined) {
    throw new Error('useCrypto must be used within a CryptoProvider');
  }
  return context;
};
