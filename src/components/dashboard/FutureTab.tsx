
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { TransactionList } from '@/components/admin/transactions/TransactionList';
import { Transaction } from '@/types/crypto';

interface FutureTabProps {
  pendingTransactions: Transaction[];
  onApprove: (id: string) => void;
  onCancel: (id: string, reason: string) => void;
}

const FutureTab: React.FC<FutureTabProps> = ({
  pendingTransactions,
  onApprove,
  onCancel
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
    
    pendingTransactions.forEach(transaction => {
      if (transaction.cryptoSymbol && !seenCurrencies[transaction.cryptoSymbol]) {
        newCurrencyMap[transaction.cryptoSymbol] = true;
      }
    });

    return newCurrencyMap;
  };

  const newCurrencies = getNewCurrencies();

  return (
    <Card className="crypto-card">
      <CardHeader>
        <CardTitle>Purchase Requests</CardTitle>
        <CardDescription>Accept or reject pending purchase requests</CardDescription>
      </CardHeader>
      <CardContent>
        <TransactionList
          transactions={pendingTransactions.filter(t => t.type === 'buy')}
          isAdmin={true}
          onApprove={onApprove}
          onCancel={onCancel}
          emptyMessage="No pending purchase requests."
          newCurrencies={newCurrencies}
        />
      </CardContent>
    </Card>
  );
};

export default FutureTab;
