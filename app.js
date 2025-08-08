// CyberSOC Dashboard - Professional Operations Center
class SOCDashboard {
    constructor() {
        this.data = {
            threatIntelligence: {
                currentThreatLevel: "ELEVATED",
                threatLevelScore: 7.2,
                activeIocs: [
                    {"type": "IP", "value": "185.220.101.47", "source": "CrowdStrike", "risk": "HIGH", "firstSeen": "2025-08-08T06:30:00Z"},
                    {"type": "Domain", "value": "suspicious-banking-site.co", "source": "VirusTotal", "risk": "CRITICAL", "firstSeen": "2025-08-08T05:15:00Z"},
                    {"type": "Hash", "value": "d41d8cd98f00b204e9800998ecf8427e", "source": "Hybrid Analysis", "risk": "MEDIUM", "firstSeen": "2025-08-07T22:45:00Z"},
                    {"type": "IP", "value": "203.45.67.89", "source": "AlienVault", "risk": "HIGH", "firstSeen": "2025-08-08T04:22:00Z"},
                    {"type": "Domain", "value": "malicious-crypto-exchange.ru", "source": "IBM X-Force", "risk": "CRITICAL", "firstSeen": "2025-08-08T03:15:00Z"}
                ],
                mitreAttacks: [
                    {"technique": "T1566.001", "name": "Spearphishing Attachment", "detected": 12},
                    {"technique": "T1059.003", "name": "Windows Command Shell", "detected": 8},
                    {"technique": "T1083", "name": "File and Directory Discovery", "detected": 15},
                    {"technique": "T1055", "name": "Process Injection", "detected": 6},
                    {"technique": "T1003.001", "name": "LSASS Memory", "detected": 4}
                ]
            },
            networkTraffic: {
                totalBandwidth: "2.4 Gbps",
                inboundTraffic: "1.6 Gbps",
                outboundTraffic: "0.8 Gbps",
                topTalkers: [
                    {"ip": "10.0.1.100", "hostname": "mail-server-01", "traffic": "340 MB", "connections": 1250},
                    {"ip": "10.0.2.45", "hostname": "web-server-prod", "traffic": "280 MB", "connections": 890},
                    {"ip": "172.16.10.25", "hostname": "db-cluster-03", "traffic": "195 MB", "connections": 445},
                    {"ip": "10.0.3.78", "hostname": "fileserver-02", "traffic": "167 MB", "connections": 324},
                    {"ip": "192.168.1.50", "hostname": "workstation-dev", "traffic": "134 MB", "connections": 256}
                ],
                protocols: [
                    {"name": "HTTPS", "percentage": 45.2, "volume": "1.08 GB"},
                    {"name": "HTTP", "percentage": 23.1, "volume": "554 MB"},
                    {"name": "SSH", "percentage": 15.8, "volume": "379 MB"},
                    {"name": "DNS", "percentage": 8.9, "volume": "213 MB"},
                    {"name": "SMTP", "percentage": 7.0, "volume": "168 MB"}
                ]
            },
            securityEvents: [
                {"id": "EVT-2025-0001247", "severity": "HIGH", "category": "Malware Detection", "source": "EDR-Endpoint-45", "timestamp": "2025-08-08T10:25:00Z", "status": "Under Investigation", "description": "Suspicious PowerShell execution detected"},
                {"id": "EVT-2025-0001246", "severity": "CRITICAL", "category": "Unauthorized Access", "source": "Domain Controller", "timestamp": "2025-08-08T10:18:00Z", "status": "Active Response", "description": "Multiple failed admin login attempts"},
                {"id": "EVT-2025-0001245", "severity": "MEDIUM", "category": "Suspicious Network Traffic", "source": "Firewall-DMZ", "timestamp": "2025-08-08T10:12:00Z", "status": "Resolved", "description": "Unusual outbound connections to TOR nodes"},
                {"id": "EVT-2025-0001244", "severity": "LOW", "category": "Policy Violation", "source": "Web Proxy", "timestamp": "2025-08-08T10:08:00Z", "status": "False Positive", "description": "Blocked access to social media sites"},
                {"id": "EVT-2025-0001243", "severity": "HIGH", "category": "Data Exfiltration", "source": "DLP-System", "timestamp": "2025-08-08T09:45:00Z", "status": "Investigating", "description": "Large file transfer detected"},
                {"id": "EVT-2025-0001242", "severity": "MEDIUM", "category": "Phishing Attempt", "source": "Email Security", "timestamp": "2025-08-08T09:32:00Z", "status": "Blocked", "description": "Suspicious attachment quarantined"}
            ],
            systemHealth: {
                infrastructure: [
                    {"system": "SIEM Platform", "status": "Healthy", "uptime": "99.97%", "lastCheck": "2025-08-08T10:29:00Z"},
                    {"system": "Log Collectors", "status": "Warning", "uptime": "98.45%", "lastCheck": "2025-08-08T10:29:00Z"},
                    {"system": "Threat Intelligence", "status": "Healthy", "uptime": "99.99%", "lastCheck": "2025-08-08T10:29:00Z"},
                    {"system": "Backup Systems", "status": "Healthy", "uptime": "100.00%", "lastCheck": "2025-08-08T10:28:00Z"}
                ],
                dataIngestion: {
                    eventsPerSecond: 15420,
                    totalEvents24h: 1847552,
                    storageUsed: "847 GB",
                    storageCapacity: "2.5 TB",
                    retentionDays: 90
                }
            },
            vulnerabilities: [
                {"cve": "CVE-2025-0001", "cvss": 9.8, "severity": "CRITICAL", "affected": 12, "category": "Remote Code Execution", "description": "Critical vulnerability in web server component"},
                {"cve": "CVE-2024-12345", "cvss": 7.5, "severity": "HIGH", "affected": 45, "category": "Privilege Escalation", "description": "Local privilege escalation in Windows service"},
                {"cve": "CVE-2024-11111", "cvss": 5.4, "severity": "MEDIUM", "affected": 23, "category": "Information Disclosure", "description": "Information disclosure in third-party library"},
                {"cve": "CVE-2024-10987", "cvss": 6.8, "severity": "HIGH", "affected": 34, "category": "SQL Injection", "description": "SQL injection vulnerability in database interface"}
            ],
            activeIncidents: [
                {"id": "INC-2025-0089", "title": "Suspected APT Activity - Finance Dept", "severity": "CRITICAL", "assignee": "Sarah Chen", "status": "Active Investigation", "opened": "2025-08-08T08:30:00Z"},
                {"id": "INC-2025-0088", "title": "Phishing Campaign Detection", "severity": "HIGH", "assignee": "Mike Rodriguez", "status": "Containment", "opened": "2025-08-08T07:15:00Z"},
                {"id": "INC-2025-0087", "title": "Unusual Data Transfer Pattern", "severity": "MEDIUM", "assignee": "Alex Johnson", "status": "Analysis", "opened": "2025-08-07T23:45:00Z"}
            ],
            complianceStatus: {
                frameworks: [
                    {"name": "SOC 2 Type II", "status": "Compliant", "score": 98.2, "lastAudit": "2025-06-15"},
                    {"name": "ISO 27001", "status": "Compliant", "score": 96.8, "lastAudit": "2025-05-20"},
                    {"name": "PCI DSS", "status": "Minor Issues", "score": 89.5, "lastAudit": "2025-07-10"},
                    {"name": "NIST CSF", "status": "Compliant", "score": 94.7, "lastAudit": "2025-07-01"}
                ]
            }
        };

        this.charts = {};
        this.init();
    }

    init() {
        this.updateCurrentTime();
        this.populateIOCs();
        this.populateMITREAttacks();
        this.populateTopTalkers();
        this.populateSecurityEvents();
        this.populateVulnerabilities();
        this.populateActiveIncidents();
        this.populateComplianceFrameworks();
        this.initializeCharts();
        this.setupEventListeners();
        this.startRealTimeUpdates();

        console.log('CyberSOC Dashboard initialized');
    }

    updateCurrentTime() {
        const now = new Date();
        const timeString = now.toLocaleString('en-US', {
            timeZone: 'UTC',
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
        
        const timeElement = document.getElementById('currentTime');
        if (timeElement) {
            timeElement.textContent = `${timeString} UTC`;
        }
    }

    populateIOCs() {
        const iocList = document.getElementById('iocList');
        if (!iocList) return;

        iocList.innerHTML = '';
        this.data.threatIntelligence.activeIocs.forEach(ioc => {
            const iocElement = document.createElement('div');
            iocElement.className = `ioc-item ${ioc.risk.toLowerCase()}`;
            iocElement.innerHTML = `
                <div class="ioc-value">${ioc.type}: ${ioc.value}</div>
                <div class="ioc-meta">Source: ${ioc.source} | Risk: ${ioc.risk} | First Seen: ${new Date(ioc.firstSeen).toLocaleString()}</div>
            `;
            iocElement.onclick = () => this.showIOCDetails(ioc);
            iocList.appendChild(iocElement);
        });
    }

    populateMITREAttacks() {
        const mitreList = document.getElementById('mitreList');
        if (!mitreList) return;

        mitreList.innerHTML = '';
        this.data.threatIntelligence.mitreAttacks.forEach(attack => {
            const mitreElement = document.createElement('div');
            mitreElement.className = 'mitre-item';
            mitreElement.innerHTML = `
                <div class="ioc-value">${attack.technique}: ${attack.name}</div>
                <div class="ioc-meta">Detections: ${attack.detected} in last 24h</div>
            `;
            mitreElement.onclick = () => this.showMITREDetails(attack);
            mitreList.appendChild(mitreElement);
        });
    }

    populateTopTalkers() {
        const talkersList = document.getElementById('talkersList');
        if (!talkersList) return;

        talkersList.innerHTML = '';
        this.data.networkTraffic.topTalkers.forEach(talker => {
            const talkerElement = document.createElement('div');
            talkerElement.className = 'talker-item';
            talkerElement.innerHTML = `
                <div class="talker-info">
                    <div class="talker-ip">${talker.ip}</div>
                    <div class="talker-hostname">${talker.hostname}</div>
                </div>
                <div class="talker-stats">
                    <div>${talker.traffic}</div>
                    <div style="font-size: 0.8em; color: #a0aec0;">${talker.connections} conn</div>
                </div>
            `;
            talkerElement.onclick = () => this.showTalkerDetails(talker);
            talkersList.appendChild(talkerElement);
        });
    }

    populateSecurityEvents() {
        const eventsList = document.getElementById('eventsList');
        if (!eventsList) return;

        eventsList.innerHTML = '';
        this.data.securityEvents.forEach(event => {
            const eventElement = document.createElement('div');
            eventElement.className = 'event-row';
            eventElement.innerHTML = `
                <div class="event-time">${new Date(event.timestamp).toLocaleTimeString()}</div>
                <div class="event-severity ${event.severity.toLowerCase()}">${event.severity}</div>
                <div class="event-description">${event.description}</div>
                <div class="event-source">${event.source}</div>
                <div class="event-actions">
                    <button class="action-btn" onclick="investigateEvent('${event.id}')">Investigate</button>
                    <button class="action-btn" onclick="acknowledgeEvent('${event.id}')">ACK</button>
                </div>
            `;
            eventElement.onclick = () => this.showEventDetails(event);
            eventsList.appendChild(eventElement);
        });
    }

    populateVulnerabilities() {
        const recentVulns = document.getElementById('recentVulns');
        if (!recentVulns) return;

        recentVulns.innerHTML = '';
        this.data.vulnerabilities.forEach(vuln => {
            const vulnElement = document.createElement('div');
            vulnElement.className = `vuln-item ${vuln.severity.toLowerCase()}`;
            vulnElement.innerHTML = `
                <div class="vuln-header">
                    <span class="vuln-cve">${vuln.cve}</span>
                    <span class="vuln-cvss">CVSS: ${vuln.cvss}</span>
                </div>
                <div class="vuln-description">${vuln.description}</div>
                <div class="ioc-meta">Category: ${vuln.category} | Affected Assets: ${vuln.affected}</div>
            `;
            vulnElement.onclick = () => this.showVulnDetails(vuln);
            recentVulns.appendChild(vulnElement);
        });
    }

    populateActiveIncidents() {
        const activeIncidents = document.getElementById('activeIncidents');
        if (!activeIncidents) return;

        activeIncidents.innerHTML = '';
        this.data.activeIncidents.forEach(incident => {
            const incidentElement = document.createElement('div');
            incidentElement.className = `incident-item ${incident.severity.toLowerCase()}`;
            incidentElement.innerHTML = `
                <div class="incident-header">
                    <span class="incident-id">${incident.id}</span>
                    <span class="incident-severity ${incident.severity.toLowerCase()}">${incident.severity}</span>
                </div>
                <div class="incident-title">${incident.title}</div>
                <div class="incident-meta">
                    <span>Assignee: ${incident.assignee}</span>
                    <span>Status: ${incident.status}</span>
                    <span>Opened: ${new Date(incident.opened).toLocaleString()}</span>
                </div>
            `;
            incidentElement.onclick = () => this.showIncidentDetails(incident);
            activeIncidents.appendChild(incidentElement);
        });
    }

    populateComplianceFrameworks() {
        const complianceFrameworks = document.getElementById('complianceFrameworks');
        if (!complianceFrameworks) return;

        complianceFrameworks.innerHTML = '';
        this.data.complianceStatus.frameworks.forEach(framework => {
            const frameworkElement = document.createElement('div');
            frameworkElement.className = 'compliance-item';
            frameworkElement.innerHTML = `
                <div>
                    <div class="compliance-name">${framework.name}</div>
                    <div style="font-size: 0.8em; color: #a0aec0;">Last Audit: ${framework.lastAudit}</div>
                </div>
                <div class="compliance-score">${framework.score}%</div>
            `;
            frameworkElement.onclick = () => this.showComplianceDetails(framework);
            complianceFrameworks.appendChild(frameworkElement);
        });
    }

    initializeCharts() {
        this.initTrafficChart();
        this.initResourceChart();
    }

    initTrafficChart() {
        const ctx = document.getElementById('trafficChart');
        if (!ctx) return;

        // Generate sample traffic data
        const labels = [];
        const data = [];
        const now = new Date();
        
        for (let i = 23; i >= 0; i--) {
            const time = new Date(now.getTime() - i * 60 * 60 * 1000);
            labels.push(time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
            data.push(Math.random() * 2000 + 1000); // Random traffic data
        }

        this.charts.traffic = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Network Traffic (Mbps)',
                    data: data,
                    borderColor: '#38b2ac',
                    backgroundColor: 'rgba(56, 178, 172, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#e2e8f0'
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: '#a0aec0'
                        },
                        grid: {
                            color: '#4a5568'
                        }
                    },
                    y: {
                        ticks: {
                            color: '#a0aec0'
                        },
                        grid: {
                            color: '#4a5568'
                        }
                    }
                }
            }
        });
    }

    initResourceChart() {
        const ctx = document.getElementById('resourceChart');
        if (!ctx) return;

        this.charts.resource = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['CPU', 'Memory', 'Storage', 'Network'],
                datasets: [{
                    data: [65, 78, 45, 82],
                    backgroundColor: [
                        '#e53e3e',
                        '#d69e2e',
                        '#38a169',
                        '#3182ce'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#e2e8f0',
                            padding: 10
                        }
                    }
                }
            }
        });
    }

    setupEventListeners() {
        // Search functionality
        const searchInput = document.querySelector('.search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.filterEvents(e.target.value);
            });
        }

        // Severity filter
        const severityFilter = document.querySelector('.severity-filter');
        if (severityFilter) {
            severityFilter.addEventListener('change', (e) => {
                this.filterEventsBySeverity(e.target.value);
            });
        }

        // Time range selector
        const timeRange = document.querySelector('.time-range');
        if (timeRange) {
            timeRange.addEventListener('change', (e) => {
                this.updateTimeRange(e.target.value);
            });
        }

        // Panel expand/collapse
        document.querySelectorAll('.btn-expand').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const panel = e.target.closest('.panel');
                panel.classList.toggle('expanded');
            });
        });
    }

    startRealTimeUpdates() {
        // Update time every second
        setInterval(() => {
            this.updateCurrentTime();
        }, 1000);

        // Simulate real-time data updates every 30 seconds
        setInterval(() => {
            this.simulateDataUpdates();
        }, 30000);

        // Update charts every 5 minutes
        setInterval(() => {
            this.updateCharts();
        }, 300000);
    }

    simulateDataUpdates() {
        // Simulate new events
        const newEventId = `EVT-2025-${String(Math.floor(Math.random() * 10000)).padStart(7, '0')}`;
        const severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        const categories = ['Malware Detection', 'Network Intrusion', 'Policy Violation', 'Data Exfiltration'];
        const sources = ['EDR-Endpoint', 'Firewall-DMZ', 'Web Proxy', 'Email Security'];

        const newEvent = {
            id: newEventId,
            severity: severities[Math.floor(Math.random() * severities.length)],
            category: categories[Math.floor(Math.random() * categories.length)],
            source: sources[Math.floor(Math.random() * sources.length)] + '-' + Math.floor(Math.random() * 100),
            timestamp: new Date().toISOString(),
            status: 'New',
            description: 'Simulated security event for demonstration'
        };

        this.data.securityEvents.unshift(newEvent);
        if (this.data.securityEvents.length > 20) {
            this.data.securityEvents.pop();
        }

        this.populateSecurityEvents();
        this.showNotification(`New ${newEvent.severity} event: ${newEvent.category}`, newEvent.severity);
    }

    updateCharts() {
        // Update traffic chart with new data
        if (this.charts.traffic) {
            const newData = Math.random() * 2000 + 1000;
            this.charts.traffic.data.datasets[0].data.push(newData);
            this.charts.traffic.data.datasets[0].data.shift();
            
            const newLabel = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            this.charts.traffic.data.labels.push(newLabel);
            this.charts.traffic.data.labels.shift();
            
            this.charts.traffic.update();
        }

        // Update resource chart
        if (this.charts.resource) {
            const newData = [
                Math.random() * 100,
                Math.random() * 100,
                Math.random() * 100,
                Math.random() * 100
            ];
            this.charts.resource.data.datasets[0].data = newData;
            this.charts.resource.update();
        }
    }

    // Detail view functions
    showIOCDetails(ioc) {
        const modalContent = `
            <h2>IOC Details</h2>
            <div class="detail-grid">
                <div><strong>Type:</strong> ${ioc.type}</div>
                <div><strong>Value:</strong> ${ioc.value}</div>
                <div><strong>Source:</strong> ${ioc.source}</div>
                <div><strong>Risk Level:</strong> ${ioc.risk}</div>
                <div><strong>First Seen:</strong> ${new Date(ioc.firstSeen).toLocaleString()}</div>
            </div>
            <div class="action-buttons">
                <button onclick="blockIOC('${ioc.value}')">Block IOC</button>
                <button onclick="addToWatchlist('${ioc.value}')">Add to Watchlist</button>
                <button onclick="exportIOC('${ioc.value}')">Export</button>
            </div>
        `;
        this.showModal(modalContent);
    }

    showEventDetails(event) {
        const modalContent = `
            <h2>Security Event Details</h2>
            <div class="detail-grid">
                <div><strong>Event ID:</strong> ${event.id}</div>
                <div><strong>Severity:</strong> <span class="event-severity ${event.severity.toLowerCase()}">${event.severity}</span></div>
                <div><strong>Category:</strong> ${event.category}</div>
                <div><strong>Source:</strong> ${event.source}</div>
                <div><strong>Timestamp:</strong> ${new Date(event.timestamp).toLocaleString()}</div>
                <div><strong>Status:</strong> ${event.status}</div>
                <div><strong>Description:</strong> ${event.description}</div>
            </div>
            <div class="action-buttons">
                <button onclick="investigateEvent('${event.id}')">Start Investigation</button>
                <button onclick="escalateEvent('${event.id}')">Escalate</button>
                <button onclick="closeEvent('${event.id}')">Close Event</button>
            </div>
        `;
        this.showModal(modalContent);
    }

    showModal(content) {
        const modal = document.getElementById('detailModal');
        const modalContent = document.getElementById('modalContent');
        
        if (modal && modalContent) {
            modalContent.innerHTML = content;
            modal.style.display = 'block';
        }
    }

    filterEvents(searchTerm) {
        const eventRows = document.querySelectorAll('.event-row');
        eventRows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(searchTerm.toLowerCase()) ? 'grid' : 'none';
        });
    }

    filterEventsBySeverity(severity) {
        const eventRows = document.querySelectorAll('.event-row');
        eventRows.forEach(row => {
            if (severity === 'all') {
                row.style.display = 'grid';
            } else {
                const severityElement = row.querySelector('.event-severity');
                const eventSeverity = severityElement.textContent.toLowerCase();
                row.style.display = eventSeverity === severity ? 'grid' : 'none';
            }
        });
    }

    showNotification(message, severity) {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${severity.toLowerCase()}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-exclamation-triangle"></i>
                <span>${message}</span>
            </div>
            <button class="notification-close" onclick="this.parentElement.remove()">&times;</button>
        `;

        // Add to page
        document.body.appendChild(notification);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }
}

// Global functions for button actions
function refreshThreatIntel() {
    console.log('Refreshing threat intelligence...');
    socDashboard.populateIOCs();
    socDashboard.populateMITREAttacks();
    socDashboard.showNotification('Threat intelligence updated', 'LOW');
}

function refreshNetwork() {
    console.log('Refreshing network data...');
    socDashboard.populateTopTalkers();
    socDashboard.updateCharts();
    socDashboard.showNotification('Network data refreshed', 'LOW');
}

function refreshSystemHealth() {
    console.log('Refreshing system health...');
    socDashboard.showNotification('System health updated', 'LOW');
}

function startVulnScan() {
    console.log('Starting vulnerability scan...');
    socDashboard.showNotification('Vulnerability scan initiated', 'MEDIUM');
}

function createIncident() {
    console.log('Creating new incident...');
    const modalContent = `
        <h2>Create New Incident</h2>
        <form class="incident-form">
            <div class="form-group">
                <label>Title:</label>
                <input type="text" class="form-input" placeholder="Incident title">
            </div>
            <div class="form-group">
                <label>Severity:</label>
                <select class="form-input">
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                </select>
            </div>
            <div class="form-group">
                <label>Description:</label>
                <textarea class="form-input" rows="4" placeholder="Incident description"></textarea>
            </div>
            <div class="action-buttons">
                <button type="submit">Create Incident</button>
                <button type="button" onclick="closeModal()">Cancel</button>
            </div>
        </form>
    `;
    socDashboard.showModal(modalContent);
}

function investigateEvent(eventId) {
    console.log(`Investigating event: ${eventId}`);
    socDashboard.showNotification(`Investigation started for ${eventId}`, 'MEDIUM');
}

function acknowledgeEvent(eventId) {
    console.log(`Acknowledging event: ${eventId}`);
    socDashboard.showNotification(`Event ${eventId} acknowledged`, 'LOW');
}

function escalateEvent(eventId) {
    console.log(`Escalating event: ${eventId}`);
    socDashboard.showNotification(`Event ${eventId} escalated`, 'HIGH');
}

function closeEvent(eventId) {
    console.log(`Closing event: ${eventId}`);
    socDashboard.showNotification(`Event ${eventId} closed`, 'LOW');
}

function blockIOC(ioc) {
    console.log(`Blocking IOC: ${ioc}`);
    socDashboard.showNotification(`IOC ${ioc} blocked`, 'HIGH');
}

function addToWatchlist(ioc) {
    console.log(`Adding to watchlist: ${ioc}`);
    socDashboard.showNotification(`IOC ${ioc} added to watchlist`, 'MEDIUM');
}

function exportIOC(ioc) {
    console.log(`Exporting IOC: ${ioc}`);
    socDashboard.showNotification(`IOC ${ioc} exported`, 'LOW');
}

function closeModal() {
    const modal = document.getElementById('detailModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('detailModal');
    if (event.target === modal) {
        modal.style.display = 'none';
    }
};

// Initialize dashboard when page loads
let socDashboard;
document.addEventListener('DOMContentLoaded', function() {
    socDashboard = new SOCDashboard();
});

// Add notification styles
const notificationStyles = `
    .notification {
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--bg-panel);
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 16px;
        box-shadow: 0 4px 12px var(--shadow);
        z-index: 1000;
        display: flex;
        align-items: center;
        justify-content: space-between;
        min-width: 300px;
        animation: slideIn 0.3s ease-out;
    }
    
    .notification.critical {
        border-left: 4px solid var(--critical);
    }
    
    .notification.high {
        border-left: 4px solid var(--error);
    }
    
    .notification.medium {
        border-left: 4px solid var(--warning);
    }
    
    .notification.low {
        border-left: 4px solid var(--success);
    }
    
    .notification-content {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    
    .notification-close {
        background: transparent;
        border: none;
        color: var(--text-secondary);
        font-size: 18px;
        cursor: pointer;
        padding: 0;
        margin-left: 12px;
    }
    
    .notification-close:hover {
        color: var(--text-primary);
    }
    
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    .detail-grid {
        display: grid;
        grid-template-columns: 1fr;
        gap: 12px;
        margin: 20px 0;
    }
    
    .detail-grid > div {
        padding: 8px;
        background: var(--bg-secondary);
        border-radius: 4px;
    }
    
    .action-buttons {
        display: flex;
        gap: 8px;
        margin-top: 20px;
        justify-content: flex-end;
    }
    
    .form-group {
        margin-bottom: 16px;
    }
    
    .form-group label {
        display: block;
        margin-bottom: 4px;
        font-weight: bold;
    }
    
    .form-input {
        width: 100%;
        padding: 8px 12px;
        background: var(--bg-primary);
        border: 1px solid var(--border);
        border-radius: 4px;
        color: var(--text-primary);
    }
    
    .form-input:focus {
        outline: none;
        border-color: var(--accent-blue);
    }
`;

// Inject notification styles
const styleSheet = document.createElement('style');
styleSheet.textContent = notificationStyles;
document.head.appendChild(styleSheet);