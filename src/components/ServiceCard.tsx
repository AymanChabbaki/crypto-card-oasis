
import React from 'react';
import { cn } from '@/lib/utils';
import { LucideIcon } from 'lucide-react';

interface ServiceCardProps {
  title: string;
  description: string;
  icon: LucideIcon;
  highlighted?: boolean;
  onClick?: () => void;
}

const ServiceCard: React.FC<ServiceCardProps> = ({ 
  title, 
  description, 
  icon: Icon,
  highlighted = false,
  onClick
}) => {
  return (
    <div 
      className={cn(
        "service-card cursor-pointer group",
        highlighted && "border-crypto-accent/30"
      )}
      onClick={onClick}
    >
      <div className="flex items-center mb-2">
        <div className="h-10 w-10 rounded-full bg-crypto-accent/10 flex items-center justify-center mr-3">
          <Icon className="h-5 w-5 text-crypto-accent" />
        </div>
        <div>
          <h3 className="font-medium text-sm sm:text-base">
            {title}
            {highlighted && (
              <span className="ml-2 text-xs bg-crypto-accent text-black font-bold px-2 py-0.5 rounded-full">
                HOT
              </span>
            )}
          </h3>
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>
      </div>
    </div>
  );
};

export default ServiceCard;
