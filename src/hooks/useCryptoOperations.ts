
import { useAuth } from '@/contexts/AuthContext';
import { useCryptoData } from './useCryptoData';
import { useTransactionsStorage } from './useTransactionsStorage';
import { useWatchlistStorage } from './useWatchlistStorage';
import { useEffect } from 'react';
import type { Transaction } from '@/types/crypto';

export const useCryptoOperations = () => {
  const { user, setUser } = useAuth();
  const { cryptocurrencies, loading } = useCryptoData();
  const { transactions, pendingTransactions, setTransactions, loadSavedTransactions } = useTransactionsStorage(user?.id);
  const { watchlist, setWatchlist, addToWatchlist, removeFromWatchlist } = useWatchlistStorage();

  // Process pending transactions on component mount and when transactions change
  useEffect(() => {
    // Reload user data from localStorage to get any updates
    if (user) {
      const storedUser = localStorage.getItem('cryptoUser');
      if (storedUser) {
        try {
          const refreshedUser = JSON.parse(storedUser);
          setUser(refreshedUser);
          console.log('Refreshed user data:', refreshedUser);
        } catch (error) {
          console.error('Failed to parse user data', error);
        }
      }
    }
    
    // Reload transactions whenever user or transactions change
    loadSavedTransactions();
  }, [setUser, user, loadSavedTransactions]);

  return {
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
  };
};
