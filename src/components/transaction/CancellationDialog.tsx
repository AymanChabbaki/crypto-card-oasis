
import React from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface CancellationDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onCancel: () => void;
  cancellationReason: string;
  onReasonChange: (reason: string) => void;
}

export const CancellationDialog: React.FC<CancellationDialogProps> = ({
  isOpen,
  onClose,
  onCancel,
  cancellationReason,
  onReasonChange,
}) => {
  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="bg-crypto-card border-gray-800">
        <DialogHeader>
          <DialogTitle>Cancel Transaction</DialogTitle>
          <DialogDescription>
            Please provide a reason for canceling this transaction. This will be visible to the user.
          </DialogDescription>
        </DialogHeader>
        <div className="py-4">
          <Label htmlFor="reason" className="text-sm font-medium">
            Cancellation Reason
          </Label>
          <Input
            id="reason"
            value={cancellationReason}
            onChange={(e) => onReasonChange(e.target.value)}
            className="mt-1 bg-crypto-darker border-gray-700"
            placeholder="Enter reason for cancellation"
          />
        </div>
        <DialogFooter>
          <Button 
            variant="outline" 
            onClick={onClose}
            className="border-gray-700"
          >
            Cancel
          </Button>
          <Button 
            className="bg-red-500 hover:bg-red-600 text-white"
            onClick={onCancel}
            disabled={!cancellationReason.trim()}
          >
            Confirm Cancellation
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
