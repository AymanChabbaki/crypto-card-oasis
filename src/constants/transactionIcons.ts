
import { CreditCard, Wallet, ArrowDown, ArrowUp } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

export type TransactionType = 'buy' | 'sell' | 'deposit' | 'withdrawal';

export interface TransactionIconData {
  icon: LucideIcon;
  bgColor: string;
  textColor: string;
}

export const TRANSACTION_ICONS: Record<TransactionType | 'default', TransactionIconData> = {
  buy: {
    icon: CreditCard,
    bgColor: 'bg-crypto-accent/10',
    textColor: 'text-crypto-accent'
  },
  sell: {
    icon: Wallet,
    bgColor: 'bg-red-500/10',
    textColor: 'text-red-500'
  },
  deposit: {
    icon: ArrowDown,
    bgColor: 'bg-blue-500/10',
    textColor: 'text-blue-500'
  },
  withdrawal: {
    icon: ArrowUp,
    bgColor: 'bg-purple-500/10',
    textColor: 'text-purple-500'
  },
  default: {
    icon: CreditCard,
    bgColor: 'bg-purple-500/10',
    textColor: 'text-purple-500'
  }
};

