
import { useEffect } from 'react';
import { useLoadTransactions } from './transaction/useLoadTransactions';
import { useSaveTransactions } from './transaction/useSaveTransactions';
import { useFilterTransactions } from './transaction/useFilterTransactions';
import type { Transaction } from '@/types/crypto';

export const useTransactionsStorage = (userId?: string) => {
  const { transactions, setTransactions, loadSavedTransactions } = useLoadTransactions();
  const { 
    pendingTransactions,
    completedTransactions,
    cancelledTransactions,
    buyTransactions,
    sellTransactions 
  } = useFilterTransactions(transactions);
  
  // Hook up the save functionality
  useSaveTransactions(transactions);

  // Initial load of transactions
  useEffect(() => {
    // In a real API implementation, you would fetch transactions from an API
    /* 
    Example API call:
    const fetchTransactions = async () => {
      try {
        const response = await fetch(`/api/transactions?userId=${userId}`);
        const data = await response.json();
        if (data.success) {
          setTransactions(data.transactions);
        }
      } catch (error) {
        console.error('Error fetching transactions:', error);
      }
    };
    
    if (userId) {
      fetchTransactions();
    }
    */
    
    // Using localStorage for demo purposes
    loadSavedTransactions();
  }, [userId, loadSavedTransactions]);

  return {
    transactions,
    pendingTransactions,
    completedTransactions,
    cancelledTransactions,
    buyTransactions,
    sellTransactions,
    setTransactions,
    loadSavedTransactions
  };
};
