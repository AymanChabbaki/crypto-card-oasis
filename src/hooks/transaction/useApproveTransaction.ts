
import type { Transaction } from '@/types/crypto';
import { updateUserData } from '@/utils/transactionUtils';
import { toast } from '@/hooks/use-toast';

export const useApproveTransaction = (
  transactions: Transaction[],
  setTransactions: React.Dispatch<React.SetStateAction<Transaction[]>>
) => {
  const approveTransaction = (transactionId: string) => {
    // Find the transaction first to use it in the updates
    const transaction = transactions.find(t => t.id === transactionId);
    if (!transaction || !transaction.userId) {
      console.error('Transaction not found or missing user ID');
      return;
    }
    
    // Update user data in localStorage
    updateUserData(transaction.userId, transaction);
    
    // Finally, update the transaction status
    setTransactions((prev) => {
      const updatedTransactions = prev.map((t) =>
        t.id === transactionId
          ? { ...t, status: 'completed' as const }
          : t
      );
      localStorage.setItem('cryptoTransactions', JSON.stringify(updatedTransactions));
      return updatedTransactions;
    });
    
    toast({
      title: "Transaction Approved",
      description: "Your transaction has been successfully processed",
      variant: "default"
    });
  };

  return approveTransaction;
};
