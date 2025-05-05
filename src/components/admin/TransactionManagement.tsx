
import React from 'react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { TabContent } from './transactions/TabContent';
import type { Transaction } from '@/types/crypto';

interface TransactionManagementProps {
  transactions: Transaction[];
  pendingTransactions: Transaction[];
  onApprove: (id: string) => void;
  onCancel: (id: string, reason: string) => void;
}

export const TransactionManagement: React.FC<TransactionManagementProps> = ({
  transactions,
  pendingTransactions,
  onApprove,
  onCancel,
}) => {
  const completedTransactions = transactions.filter(t => t.status === 'completed');
  const cancelledTransactions = transactions.filter(t => t.status === 'cancelled');

  return (
    <Card className="crypto-card">
      <CardHeader>
        <CardTitle>Transaction Management</CardTitle>
        <CardDescription>Review and manage user transactions</CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="pending">
          <TabsList className="bg-crypto-darker mb-4">
            <TabsTrigger value="pending" className="relative">
              Pending
              {pendingTransactions.length > 0 && (
                <span className="absolute -top-1 -right-1 bg-yellow-500 text-black text-xs rounded-full h-5 w-5 flex items-center justify-center">
                  {pendingTransactions.length}
                </span>
              )}
            </TabsTrigger>
            <TabsTrigger value="all">All</TabsTrigger>
            <TabsTrigger value="completed">Completed</TabsTrigger>
            <TabsTrigger value="cancelled">Cancelled</TabsTrigger>
          </TabsList>
          
          <TabContent
            value="pending"
            transactions={pendingTransactions}
            isAdmin={true}
            onApprove={onApprove}
            onCancel={onCancel}
            emptyMessage="No pending transactions to review."
          />
          
          <TabContent
            value="all"
            transactions={transactions}
            isAdmin={true}
            onApprove={onApprove}
            onCancel={onCancel}
            emptyMessage="No transactions found."
          />
          
          <TabContent
            value="completed"
            transactions={completedTransactions}
            emptyMessage="No completed transactions."
          />
          
          <TabContent
            value="cancelled"
            transactions={cancelledTransactions}
            emptyMessage="No cancelled transactions."
          />
        </Tabs>
      </CardContent>
    </Card>
  );
};
