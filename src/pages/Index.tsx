
import React, { useState } from 'react';
import Sidebar from '@/components/Sidebar';
import CommandCard from '@/components/CommandCard';
import TargetConfig from '@/components/TargetConfig';
import { commandData } from '@/data/commands';
import { Shield, Terminal } from 'lucide-react';

const Index: React.FC = () => {
  // State for configuration
  const [category, setCategory] = useState('Enumeration');
  const [subCategory, setSubCategory] = useState('Nmap');
  const [targetIP, setTargetIP] = useState('10.10.10.10');
  const [attackerIP, setAttackerIP] = useState('192.168.119.119');
  const [listeningPort, setListeningPort] = useState('4444');
  const [remotePort, setRemotePort] = useState('80');
  const [commonTargets, setCommonTargets] = useState([
    '10.10.10.10',
    '10.129.11.20',
    '192.168.1.10',
    '172.16.5.5',
  ]);
  const [commonPorts, setCommonPorts] = useState(['80', '443', '22', '8080', '445', '139']);

  // Get commands for current category/subcategory
  const commands = commandData[category]?.[subCategory] || [];

  // Function to replace variables in commands
  const replaceVars = (cmd: string): string => {
    return cmd
      .replace(/<IP>/g, targetIP)
      .replace(/<LHOST>/g, attackerIP)
      .replace(/<LPORT>/g, listeningPort)
      .replace(/<RPORT>/g, remotePort)
      .replace(/<PORT>/g, remotePort);
  };

  // Handle category selection
  const handleSelectCategory = (cat: string, subCat: string) => {
    setCategory(cat);
    setSubCategory(subCat);
  };

  return (
    <div className="flex h-screen overflow-hidden bg-hacker-black text-white">
      {/* Sidebar */}
      <Sidebar
      
        data={commandData}
        activeCategory={category}
        activeSubCategory={subCategory}
        onSelectCategory={handleSelectCategory}
      />
      

      {/* Main Content */}
      <div className="flex-1 overflow-y-auto p-4 lg:p-6">
        <div className="max-w-5xl mx-auto">
        
          {/* Header */}
          <div className="mb-6 flex items-center justify-between">
            <div>
              <h1 className="text-2xl lg:text-3xl font-bold flex items-center">
             
                <Shield className="mr-2 text-hacker-green" />
                OSCP Command Navigator
              </h1>
              <p className="text-gray-400 mt-1">
                Browsing: {category} &gt; {subCategory}
              </p>
            </div>
            
            <div className="flex items-center text-hacker-green">
              <Terminal className="mr-2" />
              <span className="hidden md:inline">Command Reference</span>
            </div>
          </div>

          {/* Configuration */}
          <TargetConfig
            targetIP={targetIP}
            setTargetIP={setTargetIP}
            attackerIP={attackerIP}
            setAttackerIP={setAttackerIP}
            listeningPort={listeningPort}
            setListeningPort={setListeningPort}
            remotePort={remotePort}
            setRemotePort={setRemotePort}
            commonTargets={commonTargets}
            setCommonTargets={setCommonTargets}
            commonPorts={commonPorts}
            setCommonPorts={setCommonPorts}
          />

          {/* Commands - Changed from 2-column grid to 1-column */}
          <div className="grid grid-cols-1 gap-4">
            {commands.map((cmd, idx) => (
              <CommandCard
                key={idx}
                command={cmd}
                replaceVars={replaceVars}
              />
            ))}
          </div>

          {/* No Commands Message */}
          {commands.length === 0 && (
            <div className="text-center py-10">
            
              <p className="text-gray-500">Choose a tool from left and add targets to see relevant commands.</p>
              <img className="mx-auto block" src="../../public/dragon.png" alt="Footer Image" width="50%" height="40%" />
            </div>
          )}
          
          {/* Footer  <img src="../../public/favicon.ico" alt="Footer Image" class="footer-image" width="50" height="33" style="{justify-content: center;}"/> */}
           
          <div className="mt-8 text-center text-xs text-gray-500">
          
            <p>OSCP Command Navigator &copy; 2025 - Security Testing Tool</p>
            <p className="mt-1">For educational purposes only. Use responsibly.</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Index;
