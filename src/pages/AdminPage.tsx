
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { useCrypto } from '@/contexts/CryptoContext';
import { useToast } from '@/hooks/use-toast';
import { StatsDashboard } from '@/components/admin/StatsDashboard';
import { LastApprovedTransaction } from '@/components/admin/LastApprovedTransaction';
import { TransactionManagement } from '@/components/admin/TransactionManagement';
import type { Transaction } from '@/types/crypto';

const AdminPage: React.FC = () => {
  const { user, isAdmin } = useAuth();
  const { transactions, pendingTransactions, approveTransaction, cancelTransaction } = useCrypto();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [lastApprovedTransaction, setLastApprovedTransaction] = useState<any>(null);
  const [notifiedTransactions, setNotifiedTransactions] = useState<string[]>([]);
  
  // Redirect if not admin
  React.useEffect(() => {
    if (!user || !isAdmin) {
      navigate('/login');
    }
  }, [user, isAdmin, navigate]);
  
  // Check for new pending transactions and show notifications
  useEffect(() => {
    if (user && isAdmin && pendingTransactions.length > 0) {
      const newTransactions = pendingTransactions.filter(
        transaction => !notifiedTransactions.includes(transaction.id)
      );
      
      if (newTransactions.length > 0) {
        if (newTransactions.length === 1) {
          const transaction = newTransactions[0];
          toast({
            title: "New Transaction Pending",
            description: `${transaction.type.charAt(0).toUpperCase() + transaction.type.slice(1)} transaction of $${transaction.amount.toLocaleString()} requires your approval.`,
            variant: "default",
          });
        } else {
          toast({
            title: "New Transactions Pending",
            description: `${newTransactions.length} new transactions require your approval.`,
            variant: "default",
          });
        }
        
        setNotifiedTransactions(prev => [
          ...prev,
          ...newTransactions.map(transaction => transaction.id)
        ]);
      }
    }
  }, [pendingTransactions, user, isAdmin, notifiedTransactions, toast]);
  
  if (!user || !isAdmin) {
    return null;
  }

  const handleApproveTransaction = (transactionId: string) => {
    const transaction = transactions.find(t => t.id === transactionId);
    
    approveTransaction(transactionId);
    
    if (transaction) {
      setLastApprovedTransaction({
        ...transaction,
        approvedAt: new Date(),
        status: 'completed'
      });
      
      toast({
        title: "Transaction Approved",
        description: `${transaction.type.charAt(0).toUpperCase() + transaction.type.slice(1)} transaction of $${transaction.amount.toLocaleString()} has been approved.`,
        variant: "default",
      });
    }
  };
  
  const completedTransactions = transactions.filter(t => t.status === 'completed');

  return (
    <div className="container mx-auto px-4 pb-12">
      <div className="pt-8 pb-6">
        <div className="flex items-center mb-4">
          <div className="h-10 w-10 rounded-full bg-gray-800 flex items-center justify-center mr-3">
            <ShieldCheck className="h-5 w-5 text-crypto-accent" />
          </div>
          <div>
            <h1 className="text-3xl font-bold">Admin Dashboard</h1>
            <p className="text-muted-foreground">Manage transactions and user activities</p>
          </div>
        </div>
      </div>
      
      <StatsDashboard 
        pendingTransactions={pendingTransactions}
        completedTransactions={completedTransactions}
      />
      
      <LastApprovedTransaction transaction={lastApprovedTransaction} />
      
      <TransactionManagement 
        transactions={transactions}
        pendingTransactions={pendingTransactions}
        onApprove={handleApproveTransaction}
        onCancel={cancelTransaction}
      />
    </div>
  );
};

export default AdminPage;
