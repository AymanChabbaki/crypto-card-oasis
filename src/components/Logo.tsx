
import React from 'react';
import { Bitcoin } from 'lucide-react';

const Logo: React.FC = () => {
  return (
    <div className="flex items-center gap-2">
      <Bitcoin size={28} className="text-crypto-accent" />
      <span className="font-bold text-xl tracking-tight">
        <span className="gradient-text">CryptoCard</span> Oasis
      </span>
    </div>
  );
};

export default Logo;
