
import React from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { AlertCircle, FileCheck, Gauge } from 'lucide-react';
import type { Transaction } from '@/types/crypto';

interface StatsDashboardProps {
  pendingTransactions: Transaction[];
  completedTransactions: Transaction[];
}

export const StatsDashboard: React.FC<StatsDashboardProps> = ({
  pendingTransactions,
  completedTransactions,
}) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
      <Card className="crypto-card bg-gradient-to-br from-crypto-card to-crypto-accent/5">
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground">Pending Transactions</p>
              <h3 className="text-2xl font-bold">{pendingTransactions.length}</h3>
            </div>
            <div className="h-12 w-12 bg-yellow-500/10 rounded-full flex items-center justify-center">
              <AlertCircle className="h-6 w-6 text-yellow-500" />
            </div>
          </div>
        </CardContent>
      </Card>
      
      <Card className="crypto-card bg-gradient-to-br from-crypto-card to-crypto-accent/5">
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground">Completed Transactions</p>
              <h3 className="text-2xl font-bold">{completedTransactions.length}</h3>
            </div>
            <div className="h-12 w-12 bg-green-500/10 rounded-full flex items-center justify-center">
              <FileCheck className="h-6 w-6 text-green-500" />
            </div>
          </div>
        </CardContent>
      </Card>
      
      <Card className="crypto-card bg-gradient-to-br from-crypto-card to-crypto-accent/5">
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground">Total Volume</p>
              <h3 className="text-2xl font-bold">
                ${completedTransactions.reduce((sum, t) => sum + t.amount, 0).toLocaleString()}
              </h3>
            </div>
            <div className="h-12 w-12 bg-blue-500/10 rounded-full flex items-center justify-center">
              <Gauge className="h-6 w-6 text-blue-500" />
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
