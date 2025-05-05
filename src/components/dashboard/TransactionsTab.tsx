
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import TransactionItem from '@/components/TransactionItem';
import { Transaction } from '@/types/crypto';

interface TransactionsTabProps {
  userTransactions: Transaction[];
  pendingTransactions: Transaction[];
  completedTransactions: Transaction[];
  cancelledTransactions: Transaction[];
}

const TransactionsTab: React.FC<TransactionsTabProps> = ({
  userTransactions,
  pendingTransactions,
  completedTransactions,
  cancelledTransactions
}) => {
  // Track which currencies are new (not seen before by the user)
  const [seenCurrencies, setSeenCurrencies] = useState<Record<string, boolean>>({});
  
  // Initialize on first render by getting stored seen currencies
  useEffect(() => {
    const storedSeenCurrencies = localStorage.getItem('seenCurrencies');
    if (storedSeenCurrencies) {
      setSeenCurrencies(JSON.parse(storedSeenCurrencies));
    }
  }, []);

  // Determine which currencies are new
  const getNewCurrencies = () => {
    const newCurrencyMap: Record<string, boolean> = {};
    const updatedSeenCurrencies = { ...seenCurrencies };

    userTransactions.forEach(transaction => {
      if (transaction.cryptoSymbol && !seenCurrencies[transaction.cryptoSymbol]) {
        newCurrencyMap[transaction.cryptoSymbol] = true;
        updatedSeenCurrencies[transaction.cryptoSymbol] = true;
      }
    });

    // Store the updated seen currencies in localStorage after a delay
    // This ensures the user sees the "new" indicator at least once
    setTimeout(() => {
      localStorage.setItem('seenCurrencies', JSON.stringify(updatedSeenCurrencies));
    }, 5000);

    return newCurrencyMap;
  };

  const newCurrencies = getNewCurrencies();

  return (
    <Card className="crypto-card">
      <CardHeader>
        <CardTitle>Transaction History</CardTitle>
        <CardDescription>View and manage your transactions</CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="all">
          <TabsList className="bg-crypto-darker mb-4">
            <TabsTrigger value="all">
              All ({userTransactions.length})
            </TabsTrigger>
            <TabsTrigger value="pending">
              Pending ({pendingTransactions.length})
            </TabsTrigger>
            <TabsTrigger value="completed">
              Completed ({completedTransactions.length})
            </TabsTrigger>
            <TabsTrigger value="cancelled">
              Cancelled ({cancelledTransactions.length})
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="all" className="space-y-4">
            {userTransactions.length > 0 ? (
              userTransactions.map((transaction) => (
                <TransactionItem 
                  key={transaction.id} 
                  transaction={transaction} 
                  isNewCurrency={transaction.cryptoSymbol ? newCurrencies[transaction.cryptoSymbol] : false}
                />
              ))
            ) : (
              <p className="text-muted-foreground text-center py-8">
                No transactions found. Start by buying some crypto!
              </p>
            )}
          </TabsContent>
          
          <TabsContent value="pending" className="space-y-4">
            {pendingTransactions.length > 0 ? (
              pendingTransactions.map((transaction) => (
                <TransactionItem 
                  key={transaction.id} 
                  transaction={transaction} 
                  isNewCurrency={transaction.cryptoSymbol ? newCurrencies[transaction.cryptoSymbol] : false}
                />
              ))
            ) : (
              <p className="text-muted-foreground text-center py-8">
                No pending transactions
              </p>
            )}
          </TabsContent>
          
          <TabsContent value="completed" className="space-y-4">
            {completedTransactions.length > 0 ? (
              completedTransactions.map((transaction) => (
                <TransactionItem 
                  key={transaction.id} 
                  transaction={transaction} 
                  isNewCurrency={transaction.cryptoSymbol ? newCurrencies[transaction.cryptoSymbol] : false}
                />
              ))
            ) : (
              <p className="text-muted-foreground text-center py-8">
                No completed transactions
              </p>
            )}
          </TabsContent>
          
          <TabsContent value="cancelled" className="space-y-4">
            {cancelledTransactions.length > 0 ? (
              cancelledTransactions.map((transaction) => (
                <TransactionItem 
                  key={transaction.id} 
                  transaction={transaction} 
                  isNewCurrency={transaction.cryptoSymbol ? newCurrencies[transaction.cryptoSymbol] : false}
                />
              ))
            ) : (
              <p className="text-muted-foreground text-center py-8">
                No cancelled transactions
              </p>
            )}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default TransactionsTab;
