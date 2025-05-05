
import React from 'react';
import { TabsContent } from '@/components/ui/tabs';
import { TransactionList } from './TransactionList';
import type { Transaction } from '@/types/crypto';

interface TabContentProps {
  value: string;
  transactions: Transaction[];
  isAdmin?: boolean;
  onApprove?: (id: string) => void;
  onCancel?: (id: string, reason: string) => void;
  emptyMessage: string;
}

export const TabContent: React.FC<TabContentProps> = ({
  value,
  transactions,
  isAdmin = false,
  onApprove,
  onCancel,
  emptyMessage
}) => {
  return (
    <TabsContent value={value}>
      <TransactionList
        transactions={transactions}
        isAdmin={isAdmin}
        onApprove={onApprove}
        onCancel={onCancel}
        emptyMessage={emptyMessage}
      />
    </TabsContent>
  );
};
