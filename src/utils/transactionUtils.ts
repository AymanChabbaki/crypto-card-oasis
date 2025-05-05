
import type { Transaction, CryptoHolding } from '../types/crypto';

/**
 * Updates user's crypto holdings based on transaction type
 */
export const updateCryptoHoldings = (
  userHoldings: CryptoHolding[] = [], 
  transaction: Transaction
): CryptoHolding[] => {
  if (!transaction.cryptocurrency || !transaction.cryptoSymbol || !transaction.cryptoAmount) {
    return userHoldings;
  }
  
  const holdings = [...userHoldings];
  
  // Find the existing holding - ensure case-insensitive symbol matching
  const existingHoldingIndex = holdings.findIndex(
    (holding) => 
      holding.cryptoId === transaction.cryptocurrency || 
      holding.symbol.toLowerCase() === transaction.cryptoSymbol?.toLowerCase()
  );
  
  if (transaction.type === 'buy') {
    if (existingHoldingIndex !== -1) {
      // Update existing holding
      holdings[existingHoldingIndex].amount += transaction.cryptoAmount;
    } else {
      // Add new holding
      holdings.push({
        cryptoId: transaction.cryptocurrency,
        name: transaction.cryptocurrency,
        symbol: transaction.cryptoSymbol,
        amount: transaction.cryptoAmount,
      });
    }
  } 
  else if (transaction.type === 'sell') {
    if (existingHoldingIndex !== -1) {
      // Reduce the amount
      holdings[existingHoldingIndex].amount -= transaction.cryptoAmount;
      
      // Remove the holding if amount is zero or less
      if (holdings[existingHoldingIndex].amount <= 0) {
        holdings.splice(existingHoldingIndex, 1);
      }
    }
  }
  
  return holdings;
};

/**
 * Updates user's wallet balance based on transaction type
 */
export const updateWalletBalance = (
  currentBalance: number = 0, 
  transaction: Transaction
): number => {
  switch (transaction.type) {
    case 'deposit':
      return currentBalance + transaction.amount;
    case 'withdrawal':
      return Math.max(0, currentBalance - transaction.amount);
    case 'buy':
      return Math.max(0, currentBalance - transaction.amount);
    case 'sell':
      return currentBalance + transaction.amount;
    default:
      return currentBalance;
  }
};

/**
 * Updates a user's data in localStorage based on a transaction
 */
export const updateUserData = (userId: string, transaction: Transaction): void => {
  // Get users from localStorage
  const storedUsers = JSON.parse(localStorage.getItem('registeredUsers') || '[]');
  const userIndex = storedUsers.findIndex((u: any) => u.id === userId);
  
  if (userIndex !== -1) {
    const updatedUsers = [...storedUsers];
    
    // Initialize crypto holdings if not exists
    if (!updatedUsers[userIndex].cryptoHoldings) {
      updatedUsers[userIndex].cryptoHoldings = [];
    }
    
    // Update wallet balance
    updatedUsers[userIndex].walletBalance = updateWalletBalance(
      updatedUsers[userIndex].walletBalance || 0,
      transaction
    );
    
    // Update crypto holdings for buy/sell transactions
    if ((transaction.type === 'buy' || transaction.type === 'sell') && 
        transaction.cryptocurrency && 
        transaction.cryptoSymbol && 
        transaction.cryptoAmount) {
      updatedUsers[userIndex].cryptoHoldings = updateCryptoHoldings(
        updatedUsers[userIndex].cryptoHoldings,
        transaction
      );
    }
    
    // Save updated users to localStorage
    localStorage.setItem('registeredUsers', JSON.stringify(updatedUsers));
    
    // Update current user if logged in
    const currentUser = JSON.parse(localStorage.getItem('cryptoUser') || '{}');
    if (currentUser.id === userId) {
      // Update wallet balance
      currentUser.walletBalance = updatedUsers[userIndex].walletBalance;
      
      // Update crypto holdings
      currentUser.cryptoHoldings = updatedUsers[userIndex].cryptoHoldings;
      
      // Save updated current user
      localStorage.setItem('cryptoUser', JSON.stringify(currentUser));
    }
  }
};
