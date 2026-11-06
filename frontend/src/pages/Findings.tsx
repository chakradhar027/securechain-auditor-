import React, { useEffect, useState } from 'react';
import { Finding } from '../types';
import { reportService } from '../services/reportService';
import { FindingCard } from '../components/findings/FindingCard';
import { Filter, Search, ShieldAlert } from 'lucide-react';

export const Findings: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    loadFindings();
  }, [severityFilter, categoryFilter]);

  const loadFindings = async () => {
    try {
      setLoading(true);
      const data = await reportService.getFindings({
        severity: severityFilter || undefined,
        category: categoryFilter || undefined,
      });
      setFindings(data);
    } catch (err) {
      console.error('Failed to load findings', err);
    } finally {
      setLoading(false);
    }
  };

  const filteredFindings = findings.filter((f) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.title.toLowerCase().includes(q) ||
      f.description.toLowerCase().includes(q) ||
      f.category.toLowerCase().includes(q) ||
      f.engine.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6">
      {/* Filter Bar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-xl backdrop-blur-sm space-y-4">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              placeholder="Search findings, CWE, engines..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-3 w-full sm:w-auto">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFORMATIONAL">Informational</option>
            </select>

            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Categories</option>
              <option value="REENTRANCY">Reentrancy</option>
              <option value="ACCESS_CONTROL">Access Control</option>
              <option value="UNCHECKED_CALL">Unchecked Call</option>
              <option value="ORACLE_MANIPULATION">Oracle Manipulation</option>
              <option value="OTHER">Other / Security Hygiene</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Catalog List */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-xs text-slate-400 px-1">
          <span>Found {filteredFindings.length} Security Issues</span>
        </div>

        {loading ? (
          <div className="py-12 text-center text-slate-500 text-xs">
            Loading vulnerability database...
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="p-12 text-center text-slate-500 text-xs bg-slate-900/40 rounded-xl border border-slate-800">
            No matching vulnerabilities found with current filter selections.
          </div>
        ) : (
          filteredFindings.map((finding) => (
            <FindingCard key={finding.id} finding={finding} defaultExpanded={false} />
          ))
        )}
      </div>
    </div>
  );
};

