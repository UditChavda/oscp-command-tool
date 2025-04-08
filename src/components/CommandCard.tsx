
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Copy } from 'lucide-react';
import { toast } from '@/components/ui/use-toast';
import { Command } from '@/data/commands';

interface CommandCardProps {
  command: Command;
  replaceVars: (cmd: string) => string;
}

const CommandCard: React.FC<CommandCardProps> = ({ command, replaceVars }) => {
  const [isCopied, setIsCopied] = useState(false);
  
  const handleCopy = () => {
    const processedCommand = replaceVars(command.command);
    navigator.clipboard.writeText(processedCommand);
    setIsCopied(true);
    toast({
      title: "Command copied!",
      description: "The command has been copied to your clipboard",
      duration: 1500,
    });
    
    setTimeout(() => {
      setIsCopied(false);
    }, 1500);
  };

  return (
    <div className="command-card relative">
      <div className="flex justify-between items-start mb-2">
        <h3 className="font-bold text-white">{command.title}</h3>
        <Button 
          variant="ghost" 
          size="sm" 
          onClick={handleCopy}
          className="h-8 w-8 p-0"
        >
          <Copy size={16} className={isCopied ? "text-hacker-green" : "text-white/70"} />
        </Button>
      </div>
      
      {command.description && (
        <p className="text-sm text-gray-400 mb-2">{command.description}</p>
      )}
      
      <pre className="command-text text-xs sm:text-sm">{replaceVars(command.command)}</pre>
    </div>
  );
};

export default CommandCard;
