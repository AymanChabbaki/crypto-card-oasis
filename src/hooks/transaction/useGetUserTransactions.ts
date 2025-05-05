
import type { Transaction } from '@/types/crypto';

export const useGetUserTransactions = (transactions: Transaction[]) => {
  const getUserTransactions = (userId: string) => {
    return transactions.filter((transaction) => transaction.userId === userId);
  };

  return getUserTransactions;
};
