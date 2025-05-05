
import { useState } from 'react';
import type { Transaction } from '@/types/crypto';

export const useLoadTransactions = () => {
  const [transactions, setTransactions] = useState<Transaction[]>([]);

  const loadSavedTransactions = () => {
    try {
      const savedTransactions = localStorage.getItem('cryptoTransactions');
      if (savedTransactions) {
        const parsedTransactions = JSON.parse(savedTransactions);
        
        // Ensure dates are properly converted back to Date objects
        const formattedTransactions = parsedTransactions.map((t: any) => ({
          ...t,
          date: new Date(t.date),
          // Ensure status is a valid enum value
          status: t.status === 'pending' || t.status === 'completed' || t.status === 'cancelled' 
            ? t.status 
            : 'pending'
        }));
        
        setTransactions(formattedTransactions);
        console.log('Loaded transactions:', formattedTransactions);
      } else {
        console.log('No saved transactions found in localStorage');
        setTransactions([]);
      }
    } catch (error) {
      console.error('Error loading transactions from localStorage:', error);
      setTransactions([]);
    }
  };

  return { transactions, setTransactions, loadSavedTransactions };
};
