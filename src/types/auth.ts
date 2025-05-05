
import { CryptoHolding } from './crypto';

export interface User {
  id: string;
  email: string;
  name: string;
  role: 'user' | 'admin';
  walletBalance: number;
  cryptoHoldings?: CryptoHolding[];
}

export interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string, rememberMe?: boolean) => Promise<boolean>;
  register: (name: string, email: string, password: string) => Promise<boolean>;
  logout: () => void;
  isAdmin: boolean;
  savedCredentials: { email: string; password: string } | null;
  setUser: React.Dispatch<React.SetStateAction<User | null>>; // Add setUser
}
