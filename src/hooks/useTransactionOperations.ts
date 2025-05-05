
import type { Transaction } from '../types/crypto';
import { useAddTransaction } from './transaction/useAddTransaction';
import { useApproveTransaction } from './transaction/useApproveTransaction';
import { useCancelTransaction } from './transaction/useCancelTransaction';
import { useGetUserTransactions } from './transaction/useGetUserTransactions';

export const useTransactionOperations = (
  transactions: Transaction[],
  setTransactions: React.Dispatch<React.SetStateAction<Transaction[]>>
) => {
  const addTransaction = useAddTransaction(setTransactions);
  const approveTransaction = useApproveTransaction(transactions, setTransactions);
  const cancelTransaction = useCancelTransaction(setTransactions);
  const getUserTransactions = useGetUserTransactions(transactions);

  return {
    addTransaction,
    approveTransaction,
    cancelTransaction,
    getUserTransactions
  };
};
