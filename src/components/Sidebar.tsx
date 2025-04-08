
import React from 'react';
import { cn } from '@/lib/utils';
import { Category } from '@/data/commands';

interface SidebarProps {
  data: Category;
  activeCategory: string;
  activeSubCategory: string;
  onSelectCategory: (category: string, subCategory: string) => void;
}

const Sidebar: React.FC<SidebarProps> = ({
  data,
  activeCategory,
  activeSubCategory,
  onSelectCategory,
}) => {
  return (
    <aside className="w-64 lg:w-72 h-screen overflow-y-auto bg-hacker-black border-r border-hacker-green/20 p-4 flex-shrink-0">
      <div className="mb-6">
        <h1 className="text-xl font-bold text-hacker-green flex items-center">
          <span className="mr-2">&gt;</span>
          <span className="cursor-blink">OSCP Command Navigator</span>
        </h1>
      </div>
      
      <div className="space-y-4">
        {Object.keys(data).map((category) => (
          <div key={category} className="space-y-2">
            <h2
              className={cn(
                "text-lg font-medium cursor-pointer hover:text-hacker-green transition-colors",
                activeCategory === category ? "text-hacker-green" : "text-white"
              )}
              onClick={() => {
                const firstSubCategory = Object.keys(data[category])[0];
                onSelectCategory(category, firstSubCategory);
              }}
            >
              &gt; {category}
            </h2>
            
            <ul className="pl-4 space-y-1">
              {Object.keys(data[category]).map((subCategory) => (
                <li
                  key={subCategory}
                  className={cn(
                    "sidebar-item",
                    activeCategory === category && activeSubCategory === subCategory
                      ? "bg-hacker-medium-gray border-l-2 border-hacker-green pl-2 -ml-0.5"
                      : "text-gray-400 hover:text-white"
                  )}
                  onClick={() => onSelectCategory(category, subCategory)}
                >
                  {subCategory}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </aside>
  );
};

export default Sidebar;
