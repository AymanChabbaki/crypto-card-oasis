
import React from 'react';
import type { Transaction } from '@/types/crypto';

interface PaymentDetailsProps {
  paymentDetails: NonNullable<Transaction['paymentDetails']>;
}

export const PaymentDetails: React.FC<PaymentDetailsProps> = ({ paymentDetails }) => {
  return (
    <div className="mt-3 pt-3 border-t border-gray-800">
      <p className="text-sm font-medium mb-1">Payment Details:</p>
      <div className="grid grid-cols-2 gap-2 text-xs">
        {paymentDetails.name && (
          <div>
            <span className="text-muted-foreground">Name:</span> {paymentDetails.name}
          </div>
        )}
        {paymentDetails.cardNumber && (
          <div>
            <span className="text-muted-foreground">Card:</span> •••• {paymentDetails.cardNumber.slice(-4)}
          </div>
        )}
        {paymentDetails.walletAddress && (
          <div className="col-span-2">
            <span className="text-muted-foreground">Wallet:</span> {paymentDetails.walletAddress.substring(0, 15)}...
          </div>
        )}
        {paymentDetails.country && (
          <div>
            <span className="text-muted-foreground">Country:</span> {paymentDetails.country}
          </div>
        )}
        {paymentDetails.phoneNumber && (
          <div>
            <span className="text-muted-foreground">Phone:</span> {paymentDetails.phoneNumber}
          </div>
        )}
      </div>
    </div>
  );
};
