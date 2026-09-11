import React, { useState, useEffect } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts';

const API_BASE = 'ip';
//Replace 'ip' with your real ip address
const COLORS = ['#ef4444', '#f59e0b', '#10b981'];

function App() {
  const [stats, setStats] = useState({ total_events: 0, high_severity: 0, blocked_ips: [] });
  const [events, setEvents] = useState([]);
  const [suspiciousIPs, setSuspiciousIPs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [currentView, setCurrentView] = useState('dashboard');
  const [refreshInterval, setRefreshInterval] = useState(2);
  const [ipFilter, setIpFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');

  // Export evidence for a specific EVENT ID – triggers download
  const exportEvidence = (eventId) => {
    window.open(`${API_BASE}/export?event_id=${eventId}`, '_blank');
  };

  // Working Kenyan time formatter (UNTOUCHED)
  function formatKenyanTime(timeString) {
    if (!timeString) return '—';
    // Just print the string exactly as it came from the database
    return String(timeString).replace('T', ' ').slice(0, 19);
  }

const fetchAllData = async () => {
  try {
    const [statsRes, eventsRes, suspiciousRes] = await Promise.all([
      fetch(`${API_BASE}/stats`),
      fetch(`${API_BASE}/events`),
      fetch(`${API_BASE}/suspicious_ips`),
    ]);
    const statsData = await statsRes.json();
    let eventsData = await eventsRes.json();
    const suspiciousData = await suspiciousRes.json();
    
    // SORT EVENTS BY TIMESTAMP (NEWEST FIRST)
    eventsData.sort((a, b) => {
      const timeA = new Date(a.timestamp.replace(' ', 'T'));
      const timeB = new Date(b.timestamp.replace(' ', 'T'));
      return timeB - timeA; // Descending order (newest first)
    });
    
    setStats(statsData);
    setEvents(eventsData);
    setSuspiciousIPs(suspiciousData);
  } catch (err) {
    console.error('Fetch error:', err);
  } finally {
    setLoading(false);
  }
};

  useEffect(() => {
    fetchAllData();
    const interval = setInterval(fetchAllData, refreshInterval * 1000);
    return () => clearInterval(interval);
  }, [refreshInterval]);

  const blockIP = async (ip) => {
    try {
      const res = await fetch(`${API_BASE}/block_ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `ip=${ip}`
      });
      if (res.ok) {
        alert(`Blocked ${ip}`);
        fetchAllData();
      } else alert('Block failed');
    } catch (err) { alert('Error'); }
  };

  const whitelistIP = async (ip) => {
    try {
      const res = await fetch(`${API_BASE}/whitelist_ip?ip=${ip}`, { method: 'POST' });
      if (res.ok) {
        alert(`Whitelisted ${ip}`);
        fetchAllData();
      } else alert('Whitelist failed');
    } catch (err) { alert('Error'); }
  };

  const getCommandUsed = (ev) => {
    if (ev.event_type === 'command_execution') {
      const match = ev.summary.match(/Command executed: (.*)/);
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

  const pieData = [
    { name: 'High', value: stats.high_severity || 0 },
    { name: 'Medium', value: stats.medium_severity || 0 },
    { name: 'Low', value: stats.low_severity || 0 },
  ].filter(item => item.value > 0);

  const last7Days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    last7Days.push(d.toISOString().slice(0, 10));
  }
  const dailyCounts = last7Days.map(day =>
    events.filter(ev => ev.timestamp?.startsWith(day)).length
  );
  const chartData = last7Days.map((day, idx) => ({ date: day, attacks: dailyCounts[idx] }));

  const bgColor = '#1f2937';
  const textColor = '#f3f4f6';
  const cardBg = '#374151';
  const tableHeaderBg = '#334155';

  // ---------- Dashboard ----------
  const renderDashboard = () => {
    return (
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
            <div style={{ fontSize: '28px', fontWeight: 'bold' }}>{stats.blocked_ips.length}</div>
          </div>
          <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px' }}>
            <div style={{ color: '#6b7280' }}>Anomaly Rate</div>
            <div style={{ fontSize: '28px', fontWeight: 'bold' }}>0.23%</div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '16px', marginBottom: '24px' }}>
          <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px' }}>
            <h3 style={{ fontSize: '18px', fontWeight: '600', marginBottom: '16px' }}>Attack Trend (Last 7 Days)</h3>
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
            <h3 style={{ fontSize: '18px', fontWeight: '600', marginBottom: '16px' }}>Severity Distribution</h3>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} dataKey="value" label>
                  {pieData.map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />)}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* RECENT INCIDENTS TABLE (NO FILTERS) */}
        <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '8px' }}>
          <h2 style={{ color: 'white', marginBottom: '15px' }}>Recent Incidents</h2>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', color: 'white' }}>
              <thead>
                <tr style={{ backgroundColor: '#334155', textAlign: 'left' }}>
                  <th style={{ padding: '12px' }}>Time</th>
                  <th style={{ padding: '12px' }}>Source IP</th>
                  <th style={{ padding: '12px' }}>Event Type</th>
                  <th style={{ padding: '12px' }}>Severity</th>
                  <th style={{ padding: '12px' }}>Asset</th>
                </tr>
              </thead>
              <tbody>
                {events.slice(0, 10).map((ev) => (
                  <tr key={ev.id} style={{ borderBottom: '1px solid #334155' }}>
                    <td style={{ padding: '12px' }}>{formatKenyanTime(ev.timestamp)}</td>
                    <td style={{ padding: '12px' }}>{ev.source_ip}</td>
                    <td style={{ padding: '12px' }}>{ev.event_type}</td>
                    <td style={{ padding: '12px' }}>
                      <span style={{
                        padding: '4px 8px', borderRadius: '12px', fontSize: '12px', fontWeight: 'bold',
                        backgroundColor: ev.severity === 'High' ? '#7f1d1d' : ev.severity === 'Medium' ? '#78350f' : '#14532d',
                        color: ev.severity === 'High' ? '#fca5a5' : ev.severity === 'Medium' ? '#fcd34d' : '#86efac'
                      }}>
                        {ev.severity}
                      </span>
                    </td>
                    <td style={{ padding: '12px' }}>{ev.asset}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </>
    );
  };

  // ---------- Incidents & Events (WITH FILTERS) ----------
const renderIncidents = () => {
  const filteredEvents = events.filter(ev => {
    // IP Filter - trim whitespace and make it case-insensitive
    const ipMatch = !ipFilter || 
      (ev.source_ip && ev.source_ip.toString().toLowerCase().includes(ipFilter.trim().toLowerCase()));
    
    // Severity Filter
    const severityMatch = severityFilter === 'All' || ev.severity === severityFilter;
    
    return ipMatch && severityMatch;
  });

  return (
    <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '8px' }}>
      <h2 style={{ color: 'white', marginBottom: '15px' }}>Incidents & Events</h2>
      
      {/* FILTERS */}
      <div style={{ display: 'flex', gap: '15px', marginBottom: '20px', alignItems: 'center', flexWrap: 'wrap' }}>
        <input 
          type="text" 
          placeholder="Filter by IP Address..." 
          value={ipFilter}
          onChange={(e) => {
            const value = e.target.value;
            console.log('IP Filter changed to:', value); // Debug log
            setIpFilter(value);
          }}
          style={{ padding: '8px 12px', borderRadius: '4px', border: '1px solid #475569', backgroundColor: '#0f172a', color: 'white', width: '200px' }}
        />

        <select 
          value={severityFilter} 
          onChange={(e) => {
            console.log('Severity Filter changed to:', e.target.value); // Debug log
            setSeverityFilter(e.target.value);
          }}
          style={{ padding: '8px 12px', borderRadius: '4px', border: '1px solid #475569', backgroundColor: '#0f172a', color: 'white' }}
        >
          <option value="All">All Severities</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>

        {(ipFilter || severityFilter !== 'All') && (
          <button 
            onClick={() => { setIpFilter(''); setSeverityFilter('All'); }}
            style={{ padding: '8px 12px', backgroundColor: '#6b7280', border: 'none', borderRadius: '4px', color: 'white', cursor: 'pointer' }}
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* Show filter status */}
      <div style={{ color: '#94a3b8', marginBottom: '15px', fontSize: '14px' }}>
        Showing {filteredEvents.length} of {events.length} events
      </div>

      {/* INCIDENTS TABLE */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', color: 'white' }}>
          <thead>
            <tr style={{ backgroundColor: '#334155', textAlign: 'left' }}>
              <th style={{ padding: '12px' }}>Time</th>
              <th style={{ padding: '12px' }}>Source IP</th>
              <th style={{ padding: '12px' }}>Event Type</th>
              <th style={{ padding: '12px' }}>Severity</th>
              <th style={{ padding: '12px' }}>Asset</th>
              <th style={{ padding: '12px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvents.length > 0 ? (
              filteredEvents.map((ev) => (
                <tr key={ev.id} style={{ borderBottom: '1px solid #334155' }}>
                  <td style={{ padding: '12px' }}>{formatKenyanTime(ev.timestamp)}</td>
                  <td style={{ padding: '12px' }}>{ev.source_ip}</td>
                  <td style={{ padding: '12px' }}>{ev.event_type}</td>
                  <td style={{ padding: '12px' }}>
                    <span style={{
                      padding: '4px 8px',
                      borderRadius: '12px',
                      fontSize: '12px',
                      fontWeight: 'bold',
                      backgroundColor: ev.severity === 'High' ? '#7f1d1d' : ev.severity === 'Medium' ? '#78350f' : '#14532d',
                      color: ev.severity === 'High' ? '#fca5a5' : ev.severity === 'Medium' ? '#fcd34d' : '#86efac'
                    }}>
                      {ev.severity}
                    </span>
                  </td>
                  <td style={{ padding: '12px' }}>{ev.asset}</td>
                  <td style={{ padding: '12px' }}>
                    <button onClick={() => alert(JSON.stringify(ev, null, 2))} style={{ backgroundColor: '#8b5cf6', border: 'none', color: 'white', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer' }}>
                      Details
                    </button>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '40px', color: '#94a3b8' }}>
                  No incidents match your filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

  // ---------- Evidence Capture (WITH INDIVIDUAL EXPORT BUTTONS) ----------
  const renderEvidenceCapture = () => {
    const incidents = events.filter(ev => ev.event_type !== null);

    return (
      <div style={{ backgroundColor: cardBg, padding: '20px', borderRadius: '8px' }}>
        <h2 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '16px', color: 'white' }}>Evidence Capture</h2>

        {/* Incident Details Table */}
        <div style={{ overflowX: 'auto' }}>
          <h3 style={{ color: 'white', marginBottom: '15px', fontSize: '18px' }}>Incident Reports & TTPs</h3>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '14px', color: 'white' }}>
            <thead>
              <tr style={{ backgroundColor: '#334155', textAlign: 'left' }}>
                <th style={{ padding: '10px' }}>Name</th>
                <th style={{ padding: '10px' }}>Severity</th>
                <th style={{ padding: '10px' }}>Time</th>
                <th style={{ padding: '10px' }}>Location (IP)</th>
                <th style={{ padding: '10px' }}>Resolution</th>
                <th style={{ padding: '10px' }}>Commands Used</th>
                <th style={{ padding: '10px' }}>MITRE ATT&CK</th>
                <th style={{ padding: '10px' }}>Actions</th>
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
                  <td style={{ padding: '10px' }}>
                    <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontFamily: 'monospace', fontSize: '12px' }}>
                      {getCommandUsed(ev) || '—'}
                    </pre>
                  </td>
                  <td style={{ padding: '10px' }}>{getMitre(ev)}</td>
                  <td style={{ padding: '10px' }}>
                    <button 
                      onClick={() => exportEvidence(ev.id)} 
                      style={{ backgroundColor: '#8b5cf6', border: 'none', color: 'white', padding: '6px 12px', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold', fontSize: '12px' }}
                    >
                      Export Evidence
                    </button>
                  </td>
                </tr>
              ))}
              {incidents.length === 0 && (
                <tr>
                  <td colSpan="8" style={{ padding: '20px', textAlign: 'center', color: '#94a3b8' }}>No incidents recorded</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  // ---------- Suspicious IPs ----------
  const renderSuspiciousIPs = () => (
    <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px' }}>
      <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '16px', color: 'white' }}>Suspicious IPs</h2>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', color: 'white' }}>
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
                  <button onClick={() => blockIP(ip.ip)} style={{ backgroundColor: '#ef4444', padding: '4px 8px', borderRadius: '4px', marginRight: '8px', border: 'none', color: 'white', cursor: 'pointer' }}>Block</button>
                  <button onClick={() => whitelistIP(ip.ip)} style={{ backgroundColor: '#10b981', padding: '4px 8px', borderRadius: '4px', border: 'none', color: 'white', cursor: 'pointer' }}>Whitelist</button>
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
      <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '16px', color: 'white' }}>Raw Event Logs</h2>
      {events.map(ev => (
        <pre key={ev.id} style={{ backgroundColor: '#1f2937', padding: '8px', borderRadius: '4px', marginBottom: '8px', overflowX: 'auto', fontSize: '12px', color: '#10b981' }}>
          {JSON.stringify(ev, null, 2)}
        </pre>
      ))}
    </div>
  );

  // ---------- Settings ----------
  const renderSettings = () => (
    <div style={{ backgroundColor: cardBg, padding: '16px', borderRadius: '8px', color: 'white' }}>
      <h2 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '16px' }}>Settings</h2>
      <div style={{ marginBottom: '16px' }}>
        <label>Auto-refresh interval (seconds): </label>
        <input type="number" value={refreshInterval} onChange={(e) => setRefreshInterval(Number(e.target.value))} min="2" step="1" style={{ marginLeft: '8px', padding: '4px', width: '60px' }} />
      </div>
    </div>
  );

  const renderContent = () => {
    if (loading) return <div style={{ color: 'white' }}>Loading dashboard...</div>;
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
