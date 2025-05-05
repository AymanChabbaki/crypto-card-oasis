
import { useMemo } from 'react';
import type { Transaction } from '@/types/crypto';

export const useFilterTransactions = (transactions: Transaction[]) => {
  const pendingTransactions = useMemo(() => 
    transactions.filter(transaction => transaction.status === 'pending'),
    [transactions]
  );

  const completedTransactions = useMemo(() => 
    transactions.filter(transaction => transaction.status === 'completed'),
    [transactions]
  );

  const cancelledTransactions = useMemo(() => 
    transactions.filter(transaction => transaction.status === 'cancelled'),
    [transactions]
  );
  
  const buyTransactions = useMemo(() => 
    transactions.filter(transaction => transaction.type === 'buy'),
    [transactions]
  );

  const sellTransactions = useMemo(() => 
    transactions.filter(transaction => transaction.type === 'sell'),
    [transactions]
  );

  return { 
    pendingTransactions,
    completedTransactions,
    cancelledTransactions,
    buyTransactions,
    sellTransactions
  };
};
