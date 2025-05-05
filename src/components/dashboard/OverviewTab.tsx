
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import TransactionItem from '@/components/TransactionItem';
import { Wallet, ArrowUpRight, ArrowDownLeft, History, Bitcoin, LineChart, User, HelpCircle } from 'lucide-react';
import { Transaction } from '@/types/crypto';
import CryptoHoldingsCard from './CryptoHoldingsCard';

interface OverviewTabProps {
  walletBalance: number;
  totalCryptoValue: number;
  pendingTransactions: Transaction[];
  setActiveTab: (tab: string) => void;
}

const OverviewTab: React.FC<OverviewTabProps> = ({
  walletBalance,
  totalCryptoValue,
  pendingTransactions,
  setActiveTab
}) => {
  const navigate = useNavigate();
  const totalBalance = walletBalance + totalCryptoValue;
  
  return (
    <div className="space-y-6">
      <Card className="crypto-card">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center">
            <Wallet className="mr-2 h-5 w-5 text-crypto-accent" />
            <span>Wallet Balance</span>
          </CardTitle>
          <CardDescription>Your current balance and actions</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-6">
            <h3 className="text-3xl font-bold">
              ${totalBalance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
            </h3>
            <div className="text-sm text-muted-foreground mt-1">
              <span className="mr-2">Cash: ${walletBalance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</span>
              {totalCryptoValue > 0 && (
                <span>Crypto: ${totalCryptoValue.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</span>
              )}
            </div>
          </div>
          
          <div className="flex space-x-2">
            <Button 
              className="flex-1 bg-crypto-accent hover:bg-crypto-accent/80 text-black" 
              onClick={() => navigate('/dashboard/deposit')}
            >
              <ArrowDownLeft className="mr-2 h-4 w-4" />
              Deposit
            </Button>
            <Button 
              variant="outline" 
              className="flex-1 border-gray-700" 
              onClick={() => navigate('/dashboard/withdraw')}
            >
              <ArrowUpRight className="mr-2 h-4 w-4" />
              Withdraw
            </Button>
          </div>
        </CardContent>
      </Card>
      
      <CryptoHoldingsCard />
      
      <Card className="crypto-card">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center">
            <History className="mr-2 h-5 w-5 text-yellow-500" />
            <span>Pending Transactions</span>
            {pendingTransactions.length > 0 && (
              <span className="ml-2 bg-yellow-500/20 text-yellow-500 px-2 py-0.5 rounded-full text-xs">
                {pendingTransactions.length}
              </span>
            )}
          </CardTitle>
          <CardDescription>Transactions awaiting processing</CardDescription>
        </CardHeader>
        <CardContent>
          {pendingTransactions.length > 0 ? (
            <div className="space-y-3">
              {pendingTransactions.slice(0, 3).map((transaction) => (
                <TransactionItem key={transaction.id} transaction={transaction} />
              ))}
              {pendingTransactions.length > 3 && (
                <Button 
                  variant="link" 
                  className="text-crypto-accent p-0 h-auto" 
                  onClick={() => setActiveTab('transactions')}
                >
                  View all pending transactions
                </Button>
              )}
            </div>
          ) : (
            <p className="text-muted-foreground text-sm">No pending transactions</p>
          )}
        </CardContent>
      </Card>
      
      <Card className="crypto-card">
        <CardHeader className="pb-2">
          <CardTitle>Quick Actions</CardTitle>
          <CardDescription>Commonly used features</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3">
            <Button 
              variant="outline" 
              className="border-gray-700 hover:border-crypto-accent/50 hover:bg-crypto-accent/10"
              onClick={() => navigate('/market')}
            >
              <Bitcoin className="mr-2 h-4 w-4 text-crypto-accent" />
              Buy Crypto
            </Button>
            <Button 
              variant="outline" 
              className="border-gray-700 hover:border-crypto-accent/50 hover:bg-crypto-accent/10"
              onClick={() => navigate('/market')}
            >
              <LineChart className="mr-2 h-4 w-4 text-crypto-accent" />
              Markets
            </Button>
            <Button 
              variant="outline" 
              className="border-gray-700 hover:border-crypto-accent/50 hover:bg-crypto-accent/10"
              onClick={() => navigate('/dashboard/account')}
            >
              <User className="mr-2 h-4 w-4 text-crypto-accent" />
              Account
            </Button>
            <Button 
              variant="outline" 
              className="border-gray-700 hover:border-crypto-accent/50 hover:bg-crypto-accent/10"
              onClick={() => navigate('/support')}
            >
              <HelpCircle className="mr-2 h-4 w-4 text-crypto-accent" />
              Support
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default OverviewTab;
