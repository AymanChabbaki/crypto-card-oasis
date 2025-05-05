
import type { Transaction } from '@/types/crypto';
import { toast } from '@/hooks/use-toast';

export const useCancelTransaction = (
  setTransactions: React.Dispatch<React.SetStateAction<Transaction[]>>
) => {
  const cancelTransaction = (transactionId: string, reason: string) => {
    setTransactions((prev) => {
      const updatedTransactions = prev.map((transaction) =>
        transaction.id === transactionId
          ? { ...transaction, status: 'cancelled' as const, cancellationReason: reason }
          : transaction
      );
      localStorage.setItem('cryptoTransactions', JSON.stringify(updatedTransactions));
      return updatedTransactions;
    });
    
    toast({
      title: "Transaction Cancelled",
      description: reason || "Your transaction has been cancelled",
      variant: "destructive"
    });
  };

  return cancelTransaction;
};
