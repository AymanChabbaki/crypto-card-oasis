
import React, { useState } from 'react';
import type { Transaction } from '@/types/crypto';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Check, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { TransactionIcon } from './transaction/TransactionIcon';
import { PaymentDetails } from './transaction/PaymentDetails';
import { CancellationDialog } from './transaction/CancellationDialog';
import { formatDate, formatAmount } from '@/utils/formatters';

interface TransactionItemProps {
  transaction: Transaction;
  isAdmin?: boolean;
  onApprove?: (id: string) => void;
  onCancel?: (id: string, reason: string) => void;
  isNewCurrency?: boolean;
}

const TransactionItem: React.FC<TransactionItemProps> = ({ 
  transaction, 
  isAdmin = false,
  onApprove,
  onCancel,
  isNewCurrency = false
}) => {
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [cancellationReason, setCancellationReason] = useState('');

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-500/10 text-green-500 border-green-500/20';
      case 'pending':
        return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20';
      case 'cancelled':
        return 'bg-red-500/10 text-red-500 border-red-500/20';
      default:
        return 'bg-gray-500/10 text-gray-500 border-gray-500/20';
    }
  };

  const getTransactionTitle = () => {
    switch (transaction.type) {
      case 'buy':
        return `Buy ${transaction.cryptoSymbol || 'Crypto'}`;
      case 'sell':
        return `Sell ${transaction.cryptoSymbol || 'Crypto'}`;
      case 'deposit':
        return 'Deposit';
      case 'withdrawal':
        return 'Withdrawal';
      default:
        return 'Transaction';
    }
  };

  const handleCancel = () => {
    if (onCancel && cancellationReason.trim()) {
      onCancel(transaction.id, cancellationReason);
      setIsDialogOpen(false);
      setCancellationReason('');
    }
  };

  return (
    <>
      <Card className={cn(
        "crypto-card hover:shadow-sm transition-all mb-4",
        transaction.status === 'pending' && isAdmin && "border-yellow-500/30"
      )}>
        <CardContent className="p-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center">
              <TransactionIcon 
                type={transaction.type} 
                showNotification={isNewCurrency}
              />
              <div>
                <h3 className="font-medium">
                  {getTransactionTitle()}
                  {isNewCurrency && (
                    <span className="inline-block ml-2 px-1 py-0.5 bg-[#FEF7CD] text-yellow-800 text-xs rounded">New</span>
                  )}
                </h3>
                <p className="text-xs text-muted-foreground">{formatDate(transaction.date)}</p>
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <div className="text-right">
                <p className="font-medium">{formatAmount(transaction.amount)}</p>
                {transaction.cryptoAmount && transaction.cryptoSymbol && (
                  <p className="text-xs text-muted-foreground">
                    {transaction.cryptoAmount.toFixed(6)} {transaction.cryptoSymbol}
                  </p>
                )}
              </div>
              <Badge variant="outline" className={cn("ml-2", getStatusColor(transaction.status))}>
                {transaction.status}
              </Badge>
            </div>
          </div>
          
          {transaction.paymentDetails && (
            <PaymentDetails paymentDetails={transaction.paymentDetails} />
          )}
          
          {transaction.cancellationReason && (
            <div className="mt-3 pt-3 border-t border-gray-800">
              <p className="text-sm font-medium text-red-400">Cancellation Reason:</p>
              <p className="text-xs text-muted-foreground">{transaction.cancellationReason}</p>
            </div>
          )}
          
          {isAdmin && transaction.status === 'pending' && (
            <div className="mt-3 pt-3 border-t border-gray-800 flex justify-end space-x-2">
              <Button 
                variant="outline" 
                size="sm"
                className="border-red-500/30 text-red-500 hover:bg-red-500/10"
                onClick={() => setIsDialogOpen(true)}
              >
                <X className="h-4 w-4 mr-1" /> Cancel
              </Button>
              <Button 
                size="sm"
                className="bg-crypto-accent hover:bg-crypto-accent/80 text-black"
                onClick={() => onApprove && onApprove(transaction.id)}
              >
                <Check className="h-4 w-4 mr-1" /> Approve
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
      
      <CancellationDialog 
        isOpen={isDialogOpen}
        onClose={() => setIsDialogOpen(false)}
        onCancel={handleCancel}
        cancellationReason={cancellationReason}
        onReasonChange={setCancellationReason}
      />
    </>
  );
};

export default TransactionItem;
