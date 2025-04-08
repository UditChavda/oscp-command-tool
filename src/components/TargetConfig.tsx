
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Trash2, Plus } from 'lucide-react';
import { toast } from '@/components/ui/use-toast';

interface TargetConfigProps {
  targetIP: string;
  setTargetIP: (ip: string) => void;
  attackerIP: string;
  setAttackerIP: (ip: string) => void;
  listeningPort: string;
  setListeningPort: (port: string) => void;
  remotePort: string;
  setRemotePort: (port: string) => void;
  commonTargets: string[];
  setCommonTargets: React.Dispatch<React.SetStateAction<string[]>>;
  commonPorts: string[];
  setCommonPorts: React.Dispatch<React.SetStateAction<string[]>>;
}

const TargetConfig: React.FC<TargetConfigProps> = ({
  targetIP,
  setTargetIP,
  attackerIP,
  setAttackerIP,
  listeningPort,
  setListeningPort,
  remotePort,
  setRemotePort,
  commonTargets,
  setCommonTargets,
  commonPorts,
  setCommonPorts,
}) => {
  const [newTarget, setNewTarget] = useState('');
  const [newPort, setNewPort] = useState('');

  const handleAddTarget = () => {
    if (!newTarget) {
      toast({
        title: "Error",
        description: "Please enter an IP address",
        variant: "destructive",
      });
      return;
    }
    
    if (newTarget && !commonTargets.includes(newTarget)) {
      setCommonTargets((prev) => [...prev, newTarget]);
      setTargetIP(newTarget);
      setNewTarget('');
      toast({
        title: "Target added",
        description: `Added ${newTarget} to target list`,
      });
    } else {
      toast({
        title: "Duplicate target",
        description: "This target is already in your list",
        variant: "destructive",
      });
    }
  };

  const handleRemoveTarget = (ip: string) => {
    setCommonTargets((prev) => prev.filter((t) => t !== ip));
    if (targetIP === ip) {
      setTargetIP(commonTargets.filter(t => t !== ip)[0] || '');
    }
    toast({
      title: "Target removed",
      description: `Removed ${ip} from target list`,
    });
  };

  const handleAddPort = () => {
    if (!newPort) {
      toast({
        title: "Error",
        description: "Please enter a port number",
        variant: "destructive",
      });
      return;
    }
    
    if (newPort && !commonPorts.includes(newPort)) {
      setCommonPorts((prev) => [...prev, newPort]);
      setRemotePort(newPort);
      setNewPort('');
      toast({
        title: "Port added",
        description: `Added port ${newPort} to list`,
      });
    } else {
      toast({
        title: "Duplicate port",
        description: "This port is already in your list",
        variant: "destructive",
      });
    }
  };

  const handleRemovePort = (port: string) => {
    setCommonPorts((prev) => prev.filter((p) => p !== port));
    if (remotePort === port) {
      setRemotePort(commonPorts.filter(p => p !== port)[0] || '');
    }
    toast({
      title: "Port removed",
      description: `Removed port ${port} from list`,
    });
  };

  return (
    <div className="bg-hacker-dark-gray rounded-lg border border-hacker-green/20 p-4 mb-6">
      <h2 className="text-lg font-bold mb-4 text-white">Target Configuration</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Target IP Section */}
        <div className="space-y-2">
          <label className="block text-sm text-gray-300">Target IP</label>
          <div className="flex space-x-2">
            <select
              value={targetIP}
              onChange={(e) => setTargetIP(e.target.value)}
              className="bg-hacker-medium-gray border border-hacker-green/20 rounded p-2 w-full text-white focus:border-hacker-green focus:ring-1 focus:ring-hacker-green"
            >
              {commonTargets.map((ip) => (
                <option key={ip} value={ip}>
                  {ip}
                </option>
              ))}
            </select>
          </div>
          
          <div className="flex flex-wrap gap-1 mt-1">
            {commonTargets.map((ip) => (
              <div key={ip} className="inline-flex items-center bg-hacker-medium-gray rounded-md px-2 py-1">
                <span className="text-xs text-gray-300">{ip}</span>
                <button
                  onClick={() => handleRemoveTarget(ip)}
                  className="ml-1 text-gray-400 hover:text-red-500"
                >
                  <Trash2 size={12} />
                </button>
              </div>
            ))}
          </div>
        </div>
        
        {/* Add Target IP Section */}
        <div className="space-y-2">
          <label className="block text-sm text-gray-300">Add New Target</label>
          <div className="flex space-x-2">
            <Input
              type="text"
              value={newTarget}
              onChange={(e) => setNewTarget(e.target.value)}
              placeholder="e.g. 10.10.10.10"
              className="bg-hacker-medium-gray border-hacker-green/20"
            />
            <Button
              onClick={handleAddTarget}
              size="icon"
              className="bg-hacker-medium-gray hover:bg-hacker-green hover:text-black"
            >
              <Plus size={16} />
            </Button>
          </div>
        </div>
        
        {/* Remote Port Section */}
        <div className="space-y-2">
          <label className="block text-sm text-gray-300">Remote Port</label>
          <div className="flex space-x-2">
            <select
              value={remotePort}
              onChange={(e) => setRemotePort(e.target.value)}
              className="bg-hacker-medium-gray border border-hacker-green/20 rounded p-2 w-full text-white focus:border-hacker-green focus:ring-1 focus:ring-hacker-green"
            >
              {commonPorts.map((port) => (
                <option key={port} value={port}>
                  {port}
                </option>
              ))}
            </select>
          </div>
          
          <div className="flex flex-wrap gap-1 mt-1">
            {commonPorts.map((port) => (
              <div key={port} className="inline-flex items-center bg-hacker-medium-gray rounded-md px-2 py-1">
                <span className="text-xs text-gray-300">{port}</span>
                <button
                  onClick={() => handleRemovePort(port)}
                  className="ml-1 text-gray-400 hover:text-red-500"
                >
                  <Trash2 size={12} />
                </button>
              </div>
            ))}
          </div>
        </div>
        
        {/* Add Port Section */}
        <div className="space-y-2">
          <label className="block text-sm text-gray-300">Add New Port</label>
          <div className="flex space-x-2">
            <Input
              type="text"
              value={newPort}
              onChange={(e) => setNewPort(e.target.value)}
              placeholder="e.g. 80"
              className="bg-hacker-medium-gray border-hacker-green/20"
            />
            <Button
              onClick={handleAddPort}
              size="icon"
              className="bg-hacker-medium-gray hover:bg-hacker-green hover:text-black"
            >
              <Plus size={16} />
            </Button>
          </div>
        </div>

        {/* Attacker IP Section */}
        <div className="space-y-2">
          <label className="block text-sm text-gray-300">Attacker IP (LHOST)</label>
          <Input
            type="text"
            value={attackerIP}
            onChange={(e) => setAttackerIP(e.target.value)}
            placeholder="e.g. 192.168.1.100"
            className="bg-hacker-medium-gray border-hacker-green/20"
          />
        </div>
        
        {/* Listening Port Section */}
        <div className="space-y-2">
          <label className="block text-sm text-gray-300">Listening Port (LPORT)</label>
          <Input
            type="text"
            value={listeningPort}
            onChange={(e) => setListeningPort(e.target.value)}
            placeholder="e.g. 4444"
            className="bg-hacker-medium-gray border-hacker-green/20"
          />
        </div>
      </div>
    </div>
  );
};

export default TargetConfig;
