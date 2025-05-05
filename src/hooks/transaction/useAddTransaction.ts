
import type { Transaction } from '@/types/crypto';
import { toast } from '@/hooks/use-toast';

export const useAddTransaction = (
  setTransactions: React.Dispatch<React.SetStateAction<Transaction[]>>
) => {
  const addTransaction = (newTransaction: Omit<Transaction, 'id' | 'date'>) => {
    const transaction: Transaction = {
      ...newTransaction,
      id: `txn-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
      date: new Date()
    };
    
    setTransactions((prev) => {
      const updatedTransactions = [...prev, transaction];
      localStorage.setItem('cryptoTransactions', JSON.stringify(updatedTransactions));
      return updatedTransactions;
    });
    
    toast({
      title: "Transaction Created",
      description: "Your transaction has been submitted and is awaiting approval",
    });
  };

  return addTransaction;
};
