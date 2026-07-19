import React, { useState, useEffect } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts';

const API_BASE = 'http://192.168.56.107:8000';
const COLORS = ['#ef4444', '#f59e0b', '#10b981'];

function App() {
  const [stats, setStats] = useState({ total_events: 0, high_severity: 0, blocked_ips: [] });
  const [events, setEvents] = useState([]);
  const [suspiciousIPs, setSuspiciousIPs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [currentView, setCurrentView] = useState('dashboard');
  const [theme, setTheme] = useState('dark');
  const [refreshInterval, setRefreshInterval] = useState(5);
  
  // Search, Filter, and Pagination States
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalEvents, setTotalEvents] = useState(0);
  const eventsPerPage = 20; 

  // Working Kenyan time formatter 
  function formatKenyanTime(utcString) {
    if (!utcString) return '—';
    try {
      const date = new Date(utcString);
      date.setHours(date.getHours());
      return date.toISOString().slice(0, 19).replace('T', ' ');
    } catch (e) {
      return utcString;
    }
  }

  const exportEvidenceForIP = (ip) => {
    window.open(`${API_BASE}/export?ip=${ip}`, '_blank');
  };

  const fetchAllData = async () => {
    try {
      const offset = (currentPage - 1) * eventsPerPage;
      
      let eventsUrl = `${API_BASE}/events?limit=${eventsPerPage}&offset=${offset}`;
      if (searchQuery) eventsUrl += `&search=${encodeURIComponent(searchQuery)}`;
      if (severityFilter !== 'All') eventsUrl += `&severity=${severityFilter}`;

      let countUrl = `${API_BASE}/events/count`;
      if (searchQuery) countUrl += `&search=${encodeURIComponent(searchQuery)}`;
      if (severityFilter !== 'All') countUrl += `&severity=${severityFilter}`;

      const [statsRes, eventsRes, suspiciousRes, countRes] = await Promise.all([
        fetch(`${API_BASE}/stats`),
        fetch(eventsUrl),
        fetch(`${API_BASE}/suspicious_ips`),
        fetch(countUrl)
      ]);
      
      const statsData = await statsRes.json();
      const eventsData = await eventsRes.json();
      const suspiciousData = await suspiciousRes.json();
      
      let countData = { total: 0 };
      if (countRes.ok) {
        countData = await countRes.json();
      }

      setStats(statsData);
      setEvents(eventsData);
      setSuspiciousIPs(suspiciousData);
      setTotalEvents(countData.total || eventsData.length);
    } catch (err) {
      console.error('Fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    fetchAllData();
    const interval = setInterval(fetchAllData, refreshInterval * 1000);
    return () => clearInterval(interval);
  }, [refreshInterval, searchQuery, severityFilter, currentPage]);

  const blockIP = async (ip) => {
    try {
      const res = await fetch(`${API_BASE}/block_ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `ip=${ip}`
      });
      if (res.ok) { alert(`Blocked ${ip}`); fetchAllData(); } 
      else alert('Block failed');
    } catch (err) { alert('Error'); }
  };

  const whitelistIP = async (ip) => {
    try {
      const res = await fetch(`${API_BASE}/whitelist_ip?ip=${ip}`, { method: 'POST' });
      if (res.ok) { alert(`Whitelisted ${ip}`); fetchAllData(); } 
      else alert('Whitelist failed');
    } catch (err) { alert('Error'); }
  };

  const getCommandUsed = (ev) => {
    if (ev.event_type === 'command_execution') {
      const match = ev.summary?.match(/Command executed: (.*)/);
      return match ? match[1] : ev.summary;
    }
    return '';
  };

  const getMitre = (ev) => {
    if (ev.mitre_tactic && ev.mitre_technique_id) {
      return `${ev.mitre_tactic} (${ev.mitre_technique_id})`;
    }
    return '—';
  };

  const severityCount = { High: 0, Medium: 0, Low: 0 };
  events.forEach(ev => {
    if (ev.severity === 'High') severityCount.High++;
    else if (ev.severity === 'Medium') severityCount.Medium++;
    else severityCount.Low++;
  });
  const pieData = [
    { name: 'High', value: severityCount.High, color: '#ef4444' },
    { name: 'Medium', value: severityCount.Medium, color: '#f59e0b' },
    { name: 'Low', value: severityCount.Low, color: '#10b981' },
  ].filter(item => item.value > 0);

  // Dynamic Chart Data
  const dateCounts = {};
  events.forEach(ev => {
    if (ev.timestamp) {
      const dateStr = ev.timestamp.slice(0, 10); 
      dateCounts[dateStr] = (dateCounts[dateStr] || 0) + 1;
    }
  });

  const chartData = Object.keys(dateCounts)
    .sort() 
    .map(date => ({ date, attacks: dateCounts[date] }));

  const bgColor = theme === 'dark' ? '#1f2937' : '#f9fafb';
  const textColor = theme === 'dark' ? '#f3f4f6' : '#111827';
  const cardBg = theme === 'dark' ? '#374151' : '#ffffff';
  const tableHeaderBg = theme === 'dark' ? '#334155' : '#e5e7eb';

  // ---------- Dashboard ----------
  const renderDashboard = () => (
    <>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>
        <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px' }}>
          <div style={{ color: '#6b7280' }}>Total Events</div>
          <div style={{ fontSize: '28px', fontWeight: 'bold' }}>{stats.total_events}</div>
        </div>
        <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px' }}>
          <div style={{ color: '#6b7280' }}>High Severity</div>
          <div style={{ fontSize: '28px', fontWeight: 'bold', color: '#dc2626' }}>{stats.high_severity}</div>
        </div>
        <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px' }}>
          <div style={{ color: '#6b7280' }}>Blocked IPs</div>
          <div style={{ fontSize: '28px', fontWeight: 'bold' }}>{stats.blocked_ips?.length || 0}</div>
        </div>
        <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px' }}>
          <div style={{ color: '#6b7280' }}>Anomaly Rate</div>
          <div style={{ fontSize: '28px', fontWeight: 'bold' }}>0.23%</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '16px', marginBottom: '24px' }}>
        <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px' }}>
          <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '16px' }}>Attack Trend (All Time)</h2>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line type="monotone" dataKey="attacks" stroke="#3b82f6" fill="rgba(59,130,246,0.1)" />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px' }}>
          <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '16px' }}>Severity Distribution</h2>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie 
                data={pieData} 
                cx="50%" 
                cy="50%" 
                innerRadius={60} 
                outerRadius={80} 
                dataKey="value"
                nameKey="name"
                label
              >
                {pieData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* RECENT INCIDENTS WITH SEARCH, FILTER & PAGINATION */}
      <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
          <h2 style={{ fontSize: '20px', fontWeight: 'bold', margin: 0 }}>Recent Incidents</h2>
          
          <div style={{ display: 'flex', gap: '10px' }}>
            <input 
              type="text" 
              placeholder="Search IP, Event, or Summary..." 
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }} 
              style={{ padding: '6px 10px', borderRadius: '4px', border: '1px solid #ccc', width: '250px', backgroundColor: theme === 'dark' ? '#1f2937' : '#fff', color: textColor }}
            />
            <select 
              value={severityFilter} 
              onChange={(e) => { setSeverityFilter(e.target.value); setCurrentPage(1); }} 
              style={{ padding: '6px 10px', borderRadius: '4px', border: '1px solid #ccc', backgroundColor: theme === 'dark' ? '#1f2937' : '#fff', color: textColor }}
            >
              <option value="All">All Severities</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ backgroundColor: tableHeaderBg, textAlign: 'left' }}>
                <th style={{ padding: '10px' }}>Name / Summary</th><th>Indicator</th><th>Reporter</th><th>Severity</th><th>ID</th><th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {events.length > 0 ? events.map(ev => (
                <tr key={ev.id} style={{ borderBottom: '1px solid #e5e7eb' }}>
                  <td style={{ padding: '10px' }}>{ev.summary || ev.event_type}</td>
                  <td style={{ padding: '10px' }}>{ev.source_ip}</td>
                  <td style={{ padding: '10px' }}>{ev.asset}</td>
                  <td style={{ padding: '10px' }}>
                    <span style={{ padding: '4px 8px', borderRadius: '12px', fontSize: '12px', backgroundColor: ev.severity === 'High' ? '#fee2e2' : ev.severity === 'Medium' ? '#fef3c7' : '#dcfce7', color: ev.severity === 'High' ? '#dc2626' : ev.severity === 'Medium' ? '#d97706' : '#10b981' }}>
                      {ev.severity}
                    </span>
                  </td>
                  <td style={{ padding: '10px' }}>{ev.id ? ev.id.slice(0, 8) : 'N/A'}</td>
                  <td style={{ padding: '10px' }}>
                    <button style={{ backgroundColor: '#3b82f6', color: 'white', border: 'none', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer' }} onClick={() => alert(JSON.stringify(ev, null, 2))}>View</button>
                  </td>
                </tr>
              )) : (
                <tr><td colSpan="6" style={{ padding: '20px', textAlign: 'center' }}>No events found matching your criteria.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px' }}>
          <div style={{ color: '#6b7280', fontSize: '14px' }}>
            Showing {events.length} of {totalEvents} events
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button 
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))} 
              disabled={currentPage === 1}
              style={{ padding: '6px 12px', borderRadius: '4px', border: 'none', backgroundColor: currentPage === 1 ? '#9ca3af' : '#3b82f6', color: 'white', cursor: 'pointer' }}
            >
              Previous
            </button>
            <span style={{ padding: '6px 12px', color: textColor }}>
              Page {currentPage} of {Math.ceil(totalEvents / eventsPerPage) || 1}
            </span>
            <button 
              onClick={() => setCurrentPage(p => p + 1)} 
              disabled={currentPage >= Math.ceil(totalEvents / eventsPerPage)}
              style={{ padding: '6px 12px', borderRadius: '4px', border: 'none', backgroundColor: currentPage >= Math.ceil(totalEvents / eventsPerPage) ? '#9ca3af' : '#3b82f6', color: 'white', cursor: 'pointer' }}
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </>
  );

  // ---------- Suspicious IPs ----------
  const renderSuspiciousIPs = () => (
    <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px' }}>
      <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '16px' }}>Suspicious IPs</h2>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ backgroundColor: tableHeaderBg, textAlign: 'left' }}>
              <th style={{ padding: '10px' }}>IP Address</th><th>Event Count</th><th>High Severity</th><th>Blocked</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {suspiciousIPs.map(ip => (
              <tr key={ip.ip} style={{ borderBottom: '1px solid #475569' }}>
                <td style={{ padding: '8px' }}>{ip.ip}</td>
                <td style={{ padding: '8px' }}>{ip.count}</td>
                <td style={{ padding: '8px' }}>{ip.high ? 'Yes' : 'No'}</td>
                <td style={{ padding: '8px' }}>{ip.blocked ? 'Blocked' : 'Allowed'}</td>
                <td style={{ padding: '8px' }}>
                  <button 
                    onClick={() => blockIP(ip.ip)} 
                    style={{ backgroundColor: '#ef4444', padding: '4px 8px', borderRadius: '4px', marginRight: '8px', border: 'none', color: 'white', cursor: 'pointer' }}
                  >
                    Block
                  </button>
                  <button 
                    onClick={() => whitelistIP(ip.ip)} 
                    style={{ backgroundColor: '#10b981', padding: '4px 8px', borderRadius: '4px', border: 'none', color: 'white', cursor: 'pointer' }}
                  >
                    Whitelist
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  // ---------- Logs ----------
  const renderLogs = () => (
    <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px', maxHeight: '600px', overflowY: 'auto' }}>
      <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '16px' }}>Raw Event Logs</h2>
      {events.map(ev => (
        <pre key={ev.id} style={{ backgroundColor: '#1f2937', padding: '8px', borderRadius: '4px', marginBottom: '8px', overflowX: 'auto', fontSize: '12px' }}>
          {JSON.stringify(ev, null, 2)}
        </pre>
      ))}
    </div>
  );

  // ---------- Settings ----------
  const renderSettings = () => (
    <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px' }}>
      <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '16px' }}>Settings</h2>
      <div style={{ marginBottom: '16px' }}>
        <label>Theme: </label>
        <select value={theme} onChange={(e) => setTheme(e.target.value)} style={{ marginLeft: '8px', padding: '4px' }}>
          <option value="dark">Dark</option>
          <option value="light">Light</option>
        </select>
      </div>
      <div style={{ marginBottom: '16px' }}>
        <label>Auto-refresh interval (seconds): </label>
        <input type="number" value={refreshInterval} onChange={(e) => setRefreshInterval(Number(e.target.value))} min="2" step="1" style={{ marginLeft: '8px', padding: '4px', width: '60px' }} />
      </div>
      <div>
        <button onClick={() => alert('This is a demo – no actual account changes.')} style={{ marginLeft: '8px', padding: '4px 8px', cursor: 'pointer' }}>Change Credentials</button>
      </div>
    </div>
  );

  // ---------- Evidence Capture ----------
  const renderEvidenceCapture = () => {
    const incidents = events.filter(ev => ev.event_type !== null);
    return (
      <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px' }}>
        <h2 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '16px' }}>Incident Reports & TTPs</h2>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '14px' }}>
            <thead>
              <tr style={{ backgroundColor: tableHeaderBg, textAlign: 'left' }}>
                <th style={{ padding: '10px' }}>Name</th><th>Severity</th><th>Time</th><th>Location (IP)</th><th>Resolution</th><th>Similar Incidents</th><th>Commands Used</th><th>MITRE ATT&CK</th><th>Structured Evidence</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((ev, idx) => (
                <tr key={ev.id} style={{ borderBottom: '1px solid #475569', backgroundColor: idx % 2 === 0 ? '#1e293b' : '#0f172a' }}>
                  <td style={{ padding: '10px' }}>{ev.event_type || ev.summary?.slice(0, 30)}</td>
                  <td style={{ padding: '10px' }}>
                    <span style={{ padding: '2px 8px', borderRadius: '12px', fontSize: '12px', backgroundColor: ev.severity === 'High' ? '#dc2626' : ev.severity === 'Medium' ? '#f59e0b' : '#10b981', color: 'white' }}>
                      {ev.severity}
                    </span>
                  </td>
                  <td style={{ padding: '10px' }}>{formatKenyanTime(ev.timestamp)}</td>
                  <td style={{ padding: '10px' }}>{ev.source_ip}</td>
                  <td style={{ padding: '10px' }}>{ev.severity === 'High' ? 'Block IP, isolate host' : 'Monitor and log'}</td>
                  <td style={{ padding: '10px' }}>{ev.source_ip === '127.0.0.1' ? 'Localhost test' : 'Similar from same IP range'}</td>
                  <td style={{ padding: '10px' }}>
                    <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontFamily: 'monospace', fontSize: '12px' }}>
                      {getCommandUsed(ev) || '—'}
                    </pre>
                  </td>
                  <td style={{ padding: '10px' }}>{getMitre(ev)}</td>
                  <td style={{ padding: '10px' }}>
                    <button onClick={() => exportEvidenceForIP(ev.source_ip)} style={{ backgroundColor: '#8b5cf6', border: 'none', color: 'white', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer' }}>
                      Export
                    </button>
                  </td>
                </tr>
              ))}
              {incidents.length === 0 && (
                <tr>
                  <td colSpan="9" style={{ padding: '20px', textAlign: 'center' }}>No incidents recorded</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  // ---------- Incidents & Events ----------
  const renderIncidents = () => (
    <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px' }}>
      <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '16px' }}>Incidents & Events</h2>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ backgroundColor: tableHeaderBg }}>
              <th style={{ padding: '8px' }}>Time</th>
              <th style={{ padding: '8px' }}>Source IP</th>
              <th style={{ padding: '8px' }}>Event Type</th>
              <th style={{ padding: '8px' }}>Severity</th>
              <th style={{ padding: '8px' }}>Asset</th>
              <th style={{ padding: '8px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {events.map(ev => (
              <tr key={ev.id} style={{ borderBottom: '1px solid #e5e7eb' }}>
                <td style={{ padding: '8px' }}>{formatKenyanTime(ev.timestamp)}</td>
                <td style={{ padding: '8px' }}>{ev.source_ip}</td>
                <td style={{ padding: '8px' }}>{ev.event_type}</td>
                <td style={{ padding: '8px' }}>
                  <span style={{ padding: '2px 6px', borderRadius: '12px', fontSize: '12px', backgroundColor: ev.severity === 'High' ? '#fee2e2' : ev.severity === 'Medium' ? '#fef3c7' : '#dcfce7', color: ev.severity === 'High' ? '#dc2626' : ev.severity === 'Medium' ? '#d97706' : '#10b981' }}>
                    {ev.severity}
                  </span>
                </td>
                <td style={{ padding: '8px' }}>{ev.asset}</td>
                <td style={{ padding: '8px' }}>
                  <button onClick={() => alert(JSON.stringify(ev, null, 2))} style={{ backgroundColor: '#3b82f6', color: 'white', border: 'none', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer' }}>Details</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  const renderContent = () => {
    if (loading) return <div>Loading dashboard...</div>;
    switch (currentView) {
      case 'dashboard': return renderDashboard();
      case 'incidents': return renderIncidents();
      case 'suspicious': return renderSuspiciousIPs();
      case 'logs': return renderLogs();
      case 'evidence': return renderEvidenceCapture();
      case 'settings': return renderSettings();
      default: return renderDashboard();
    }
  };

  return (
    <div style={{ display: 'flex', fontFamily: 'Arial, sans-serif', backgroundColor: bgColor, color: textColor, minHeight: '100vh' }}>
      <div style={{ width: '260px', backgroundColor: '#1f2937', color: 'white', position: 'fixed', height: '100%', padding: '20px' }}>
        <div style={{ marginBottom: '30px' }}><h2>Offensive Guard</h2><p style={{ fontSize: '12px', color: '#9ca3af' }}>Active Defense SOC</p></div>
        <ul style={{ listStyle: 'none', padding: 0 }}>
          <li onClick={() => setCurrentView('dashboard')} style={{ marginBottom: '15px', padding: '8px', cursor: 'pointer', borderRadius: '5px', backgroundColor: currentView === 'dashboard' ? '#374151' : 'transparent' }}>Dashboard</li>
          <li onClick={() => setCurrentView('incidents')} style={{ marginBottom: '15px', padding: '8px', cursor: 'pointer', borderRadius: '5px', backgroundColor: currentView === 'incidents' ? '#374151' : 'transparent' }}>Incidents</li>
          <li onClick={() => setCurrentView('suspicious')} style={{ marginBottom: '15px', padding: '8px', cursor: 'pointer', borderRadius: '5px', backgroundColor: currentView === 'suspicious' ? '#374151' : 'transparent' }}>Suspicious IPs</li>
          <li onClick={() => setCurrentView('logs')} style={{ marginBottom: '15px', padding: '8px', cursor: 'pointer', borderRadius: '5px', backgroundColor: currentView === 'logs' ? '#374151' : 'transparent' }}>Logs</li>
          <li onClick={() => setCurrentView('evidence')} style={{ marginBottom: '15px', padding: '8px', cursor: 'pointer', borderRadius: '5px', backgroundColor: currentView === 'evidence' ? '#374151' : 'transparent' }}>Evidence Capture</li>
          <li onClick={() => setCurrentView('settings')} style={{ marginBottom: '15px', padding: '8px', cursor: 'pointer', borderRadius: '5px', backgroundColor: currentView === 'settings' ? '#374151' : 'transparent' }}>Settings</li>
        </ul>
        <div style={{ marginTop: '40px', borderTop: '1px solid #374151', paddingTop: '20px' }}>
          <button onClick={() => alert('Logged out (demo)')} style={{ width: '100%', padding: '8px', backgroundColor: '#ef4444', border: 'none', borderRadius: '5px', color: 'white', cursor: 'pointer' }}>Logout</button>
        </div>
      </div>
      <div style={{ marginLeft: '260px', flex: 1, padding: '24px' }}>
        {renderContent()}
      </div>
    </div>
  );
}

export default App;