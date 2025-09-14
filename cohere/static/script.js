class NetworkAnalyzer {
    constructor() {
        this.initializeElements();
        this.attachEventListeners();
        this.currentData = null;
        this.currentAnalysis = null;
    }

    initializeElements() {
        this.fileInput = document.getElementById('fileInput');
        this.uploadBtn = document.getElementById('uploadBtn');
        this.fileName = document.getElementById('fileName');
        this.analyzeBtn = document.getElementById('analyzeBtn');
        this.downloadBtn = document.getElementById('downloadBtn');
        this.retryBtn = document.getElementById('retryBtn');
        this.malcolmBtn = document.getElementById('malcolmBtn');
        
        this.loadingSection = document.getElementById('loadingSection');
        this.resultsSection = document.getElementById('resultsSection');
        this.errorSection = document.getElementById('errorSection');
        this.errorMessage = document.getElementById('errorMessage');
        
        this.datasetOverview = document.getElementById('datasetOverview');
        this.securityAnalysis = document.getElementById('securityAnalysis');
        this.detectedAnomalies = document.getElementById('detectedAnomalies');
        this.trafficPatterns = document.getElementById('trafficPatterns');
        this.topStatistics = document.getElementById('topStatistics');
        this.eventTrends = document.getElementById('eventTrends');
        this.aiAnalysis = document.getElementById('aiAnalysis');
    }

    attachEventListeners() {
        this.uploadBtn.addEventListener('click', () => this.fileInput.click());
        this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        this.analyzeBtn.addEventListener('click', () => this.analyzeData());
        this.downloadBtn.addEventListener('click', () => this.downloadReport());
        this.retryBtn.addEventListener('click', () => this.hideError());
        this.malcolmBtn.addEventListener('click', () => this.openMalcolmApp());
    }

    handleFileSelect(event) {
        const file = event.target.files[0];
        if (file) {
            if (file.type === 'application/json' || file.name.endsWith('.json')) {
                this.fileName.textContent = `Selected: ${file.name}`;
                this.fileName.classList.add('show');
                this.analyzeBtn.disabled = false;
                
                // Read and parse the file
                const reader = new FileReader();
                reader.onload = (e) => {
                    try {
                        this.currentData = JSON.parse(e.target.result);
                    } catch (error) {
                        this.showError('Invalid JSON file. Please select a valid JSON file.');
                    }
                };
                reader.readAsText(file);
            } else {
                this.showError('Please select a JSON file.');
                this.resetFileInput();
            }
        }
    }

    async useSampleData() {
        try {
            this.showLoading();
            const response = await fetch('/api/sample-data');
            if (response.ok) {
                this.currentData = await response.json();
                this.fileName.textContent = 'Using sample network data';
                this.fileName.classList.add('show');
                this.analyzeBtn.disabled = false;
                this.hideLoading();
                
                // Auto-analyze sample data
                setTimeout(() => this.analyzeData(), 500);
            } else {
                throw new Error('Failed to load sample data');
            }
        } catch (error) {
            this.hideLoading();
            this.showError('Failed to load sample data. Please try again.');
        }
    }

    async analyzeData() {
        if (!this.currentData) {
            this.showError('No data to analyze. Please select a file first.');
            return;
        }

        try {
            this.showLoading();
            
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(this.currentData)
            });

            if (response.ok) {
                const result = await response.json();
                this.currentAnalysis = result;
                this.displayResults(result);
                this.hideLoading();
            } else {
                const error = await response.json();
                throw new Error(error.error || 'Analysis failed');
            }
        } catch (error) {
            this.hideLoading();
            this.showError(`Analysis failed: ${error.message}`);
        }
    }

    displayResults(analysisData) {
        this.hideError();
        this.hideLoading();
        
        // Display dataset overview
        this.displayDatasetOverview(analysisData.load_statistics, analysisData.analytics_results);
        
        // Display security analysis
        this.displaySecurityAnalysisResults(analysisData.analytics_results);
        
        // Display detected anomalies
        this.displayDetectedAnomalies(analysisData.analytics_results);
        
        // Display traffic patterns
        this.displayTrafficPatternsResults(analysisData.analytics_results);
        
        // Display top statistics
        this.displayTopStatistics(analysisData.analytics_results);
        
        // Display event trends visualization
        this.displayEventTrends(analysisData.analytics_results);
        
        // Display AI analysis if available
        if (analysisData.llm_analysis) {
            this.displayAIAnalysis(analysisData.llm_analysis);
        }
        
        // Show results section
        this.resultsSection.classList.remove('hidden');
        this.resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    displayDatasetOverview(loadStats, analyticsResults) {
        const basicStats = analyticsResults.basic_statistics || {};
        const html = `
            <div class="stat-item">
                <span class="stat-label">Total Events:</span>
                <span class="stat-value">${basicStats.total_events || 'N/A'}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Load Time:</span>
                <span class="stat-value">${loadStats?.load_time_seconds ? loadStats.load_time_seconds.toFixed(2) + 's' : 'N/A'}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Time Range:</span>
                <span class="stat-value">${basicStats.time_range || 'N/A'}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Unique Protocols:</span>
                <span class="stat-value">${basicStats.unique_protocols || 'N/A'}</span>
            </div>
        `;
        this.datasetOverview.innerHTML = html;
    }

    displaySecurityAnalysisResults(analyticsResults) {
        const security = analyticsResults.security_analysis || {};
        let html = '';
        
        if (security.alert_severity && security.alert_severity.length > 0) {
            html += '<h4>Alert Severity Distribution</h4>';
            security.alert_severity.forEach(item => {
                html += `
                    <div class="stat-item">
                        <span class="stat-label">Severity ${item.severity}:</span>
                        <span class="stat-value severity-${item.severity}">${item.count} alerts</span>
                    </div>
                `;
            });
        }
        
        if (security.top_signatures && security.top_signatures.length > 0) {
            html += '<h4>Top Alert Signatures</h4>';
            security.top_signatures.slice(0, 3).forEach(item => {
                html += `
                    <div class="stat-item">
                        <span class="stat-label">${item.signature}:</span>
                        <span class="stat-value">${item.count} occurrences</span>
                    </div>
                `;
            });
        }
        
        if (security.failed_connections > 0) {
            html += '<h4>Security Threats</h4>';
            html += `
                <div class="stat-item">
                    <span class="stat-label">Failed Connections:</span>
                    <span class="stat-value">${security.failed_connections} attempts</span>
                </div>
            `;
        }
        
        this.securityAnalysis.innerHTML = html || '<p>No security data available</p>';
    }

    displayTrafficPatternsResults(analyticsResults) {
        const traffic = analyticsResults.traffic_patterns || {};
        let html = '';
        
        if (traffic.hourly_distribution) {
            html += '<h4>Peak Traffic Hours</h4>';
            traffic.hourly_distribution.slice(0, 3).forEach(item => {
                html += `
                    <div class="stat-item">
                        <span class="stat-label">Hour ${item.hour}:00:</span>
                        <span class="stat-value">${item.event_count} events</span>
                    </div>
                `;
            });
        }
        
        if (traffic.top_destinations) {
            html += '<h4>Top Destinations</h4>';
            traffic.top_destinations.slice(0, 3).forEach(item => {
                html += `
                    <div class="stat-item">
                        <span class="stat-label">${item.dest_ip}:</span>
                        <span class="stat-value">${item.connection_count} connections</span>
                    </div>
                `;
            });
        }
        
        this.trafficPatterns.innerHTML = html || '<p>No traffic pattern data available</p>';
    }

    displayDetectedAnomalies(analyticsResults) {
        const security = analyticsResults.security_analysis || {};
        let allAnomalies = [];
        
        // Add data science anomalies from security analysis
        if (security.data_science_anomalies && security.data_science_anomalies.length > 0) {
            allAnomalies = allAnomalies.concat(security.data_science_anomalies.filter(a => a.count > 0));
        }
        
        // Add any other anomaly detection results
        if (security.anomaly_detection && security.anomaly_detection.length > 0) {
            allAnomalies = allAnomalies.concat(security.anomaly_detection.filter(a => a.count > 0));
        }
        
        let html = '';
        if (allAnomalies.length > 0) {
            html += '<h4>🚨 Anomalies Detected:</h4>';
            allAnomalies.forEach(anomaly => {
                const severity = this.getAnomalySeverity(anomaly.anomaly_type, anomaly.count);
                const type = anomaly.anomaly_type.replace(/_/g, ' ').toUpperCase();
                
                // Create brief summary based on anomaly type with key details
                let summary = '';
                switch(anomaly.anomaly_type) {
                    case 'isolation_forest':
                        summary = `${anomaly.count} unusual patterns detected`;
                        if (anomaly.anomaly_score) {
                            summary += ` (score: ${anomaly.anomaly_score.toFixed(2)})`;
                        }
                        break;
                    case 'dbscan_clustering':
                        summary = `${anomaly.count} behavioral anomalies found`;
                        if (anomaly.n_clusters) {
                            summary += ` (${anomaly.n_clusters} clusters)`;
                        }
                        break;
                    case 'z_score':
                        summary = `${anomaly.count} statistical outliers`;
                        if (anomaly.threshold) {
                            summary += ` (z-score > ${anomaly.threshold})`;
                        }
                        break;
                    case 'iqr':
                        summary = `${anomaly.count} unusual traffic patterns`;
                        break;
                    case 'rolling_window':
                        summary = `${anomaly.count} temporal anomalies detected`;
                        break;
                    case 'oversized_payload':
                        summary = `${anomaly.count} large data transfers`;
                        if (anomaly.max_events) {
                            summary += ` (max: ${anomaly.max_events})`;
                        }
                        break;
                    case 'suspicious_user_agent':
                        summary = `${anomaly.count} suspicious user agents`;
                        break;
                    case 'rare_port':
                        summary = `${anomaly.count} rare port activities`;
                        if (anomaly.unique_ports) {
                            summary += ` (${anomaly.unique_ports} ports)`;
                        }
                        break;
                    case 'high_frequency_source':
                        summary = `${anomaly.count} high-frequency sources`;
                        break;
                    default:
                        summary = `${anomaly.count} anomalies detected`;
                }
                
                html += `<div class="anomaly-item anomaly-${severity}">
                    <strong>${type}:</strong> ${summary}
                </div>`;
            });
        } else {
            html += '<p>No anomalies detected.</p>';
        }
        
        this.detectedAnomalies.innerHTML = html;
    }


    displayTopStatistics(analyticsResults) {
        const security = analyticsResults.security_analysis || {};
        const traffic = analyticsResults.traffic_patterns || {};
        let html = '';
        
        if (security.suspicious_ports && security.suspicious_ports.length > 0) {
            html += '<h4>Suspicious Ports</h4>';
            security.suspicious_ports.slice(0, 3).forEach(item => {
                html += `
                    <div class="stat-item">
                        <span class="stat-label">Port ${item.dest_port}:</span>
                        <span class="stat-value">${item.connection_count} connections</span>
                    </div>
                `;
            });
        }
        
        if (traffic.protocol_distribution && traffic.protocol_distribution.length > 0) {
            html += '<h4>Protocol Distribution</h4>';
            traffic.protocol_distribution.slice(0, 3).forEach(item => {
                html += `
                    <div class="stat-item">
                        <span class="stat-label">${item.protocol}:</span>
                        <span class="stat-value">${item.count} events</span>
                    </div>
                `;
            });
        }
        
        if (traffic.port_analysis && traffic.port_analysis.length > 0) {
            html += '<h4>Port Analysis</h4>';
            traffic.port_analysis.slice(0, 3).forEach(item => {
                html += `
                    <div class="stat-item">
                        <span class="stat-label">Port ${item.dest_port}:</span>
                        <span class="stat-value">${item.connection_count} conn (${item.unique_sources} sources)</span>
                    </div>
                `;
            });
        }
        
        this.topStatistics.innerHTML = html || '<p>No additional statistics available</p>';
    }

    displayEventTrends(analyticsResults) {
        const traffic = analyticsResults.traffic_patterns || {};
        const trends = traffic.event_type_trends || [];
        
        if (trends.length > 0) {
            this.createSimpleChart(trends);
        } else {
            this.eventTrends.innerHTML = '<p>No trend data available</p>';
        }
    }

    displayAIAnalysis(analysis) {
        // Format the analysis text with proper HTML
        const formattedAnalysis = this.formatAnalysisText(analysis);
        this.aiAnalysis.innerHTML = formattedAnalysis;
    }

    formatAnalysisText(text) {
        // Clean and format HTML output from LLM
        let formatted = text.trim();
        
        // Remove any extra whitespace and normalize line breaks
        formatted = formatted.replace(/\s+/g, ' ').replace(/\s*<br>\s*/g, '<br>');
        
        // Ensure proper HTML structure
        if (!formatted.includes('<p>') && !formatted.includes('<h') && !formatted.includes('<ul>') && !formatted.includes('<ol>')) {
            // If it's plain text, wrap in paragraph tags
            formatted = '<p>' + formatted + '</p>';
        }
        
        // Fix common HTML formatting issues
        formatted = formatted
            .replace(/<h4>/g, '<h4>')
            .replace(/<\/h4>/g, '</h4>')
            .replace(/<p>/g, '<p>')
            .replace(/<\/p>/g, '</p>')
            .replace(/<ul>/g, '<ul>')
            .replace(/<\/ul>/g, '</ul>')
            .replace(/<li>/g, '<li>')
            .replace(/<\/li>/g, '</li>')
            .replace(/<strong>/g, '<strong>')
            .replace(/<\/strong>/g, '</strong>')
            .replace(/<em>/g, '<em>')
            .replace(/<\/em>/g, '</em>');
        
        // Ensure proper spacing around headers
        formatted = formatted.replace(/<\/h4>/g, '</h4><br>');
        
        return formatted;
    }

    downloadReport() {
        if (!this.currentAnalysis) {
            this.showError('No analysis results to download. Please run an analysis first.');
            return;
        }

        const report = {
            timestamp: new Date().toISOString(),
            analysis_results: this.currentAnalysis
        };

        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `network_analysis_report_${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    showLoading() {
        this.hideError();
        this.resultsSection.classList.add('hidden');
        this.loadingSection.classList.remove('hidden');
    }

    hideLoading() {
        this.loadingSection.classList.add('hidden');
    }

    showError(message) {
        this.hideLoading();
        this.resultsSection.classList.add('hidden');
        this.errorMessage.textContent = message;
        this.errorSection.classList.remove('hidden');
    }

    hideError() {
        this.errorSection.classList.add('hidden');
    }

    resetFileInput() {
        this.fileInput.value = '';
        this.fileName.classList.remove('show');
        this.analyzeBtn.disabled = true;
        this.currentData = null;
    }

    formatDate(dateString) {
        if (!dateString) return null;
        try {
            return new Date(dateString).toLocaleString();
        } catch {
            return dateString;
        }
    }

    capitalize(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    formatAnomalyName(anomalyType) {
        const names = {
            'expired_tls': 'Expired TLS Certificates',
            'rare_ports': 'Rare Port Usage',
            'oversized_payloads': 'Oversized Payloads',
            'high_severity_alerts': 'High Severity Alerts'
        };
        return names[anomalyType] || anomalyType;
    }

    getAnomalySeverity(anomalyType, count) {
        if (count === 0) return 'low';
        
        // ML-based anomaly severity
        if (anomalyType.includes('isolation_forest') && count > 5) return 'high';
        if (anomalyType.includes('dbscan') && count > 10) return 'high';
        if (anomalyType.includes('z_score') && count > 20) return 'medium';
        if (anomalyType.includes('iqr') && count > 15) return 'medium';
        if (anomalyType.includes('temporal_pattern') && count > 3) return 'high';
        
        // Rule-based anomaly severity
        if (anomalyType === 'oversized_payloads' && count > 20) return 'high';
        if (anomalyType === 'suspicious_user_agents' && count > 5) return 'high';
        if (anomalyType === 'high_frequency_sources' && count > 3) return 'medium';
        if (anomalyType === 'rare_ports' && count > 10) return 'medium';
        
        if (count > 50) return 'medium';
        return 'low';
    }

    createSimpleChart(trends) {
        // Group data by hour and event type
        const hourlyData = {};
        const eventTypes = [...new Set(trends.map(t => t.event_type))];
        
        // Initialize all hours with 0 for each event type
        for (let hour = 0; hour < 24; hour++) {
            hourlyData[hour] = {};
            eventTypes.forEach(type => {
                hourlyData[hour][type] = 0;
            });
        }
        
        // Fill in actual data
        trends.forEach(item => {
            hourlyData[item.hour][item.event_type] = item.count;
        });

        // Prepare data for Chart.js
        const labels = Array.from({length: 24}, (_, i) => `${i.toString().padStart(2, '0')}:00`);
        const colors = {
            'alert': {
                border: '#dc3545',
                background: 'rgba(220, 53, 69, 0.1)',
                point: '#dc3545'
            },
            'tls': {
                border: '#28a745',
                background: 'rgba(40, 167, 69, 0.1)',
                point: '#28a745'
            },
            'http': {
                border: '#007bff',
                background: 'rgba(0, 123, 255, 0.1)',
                point: '#007bff'
            },
            'flow': {
                border: '#6f42c1',
                background: 'rgba(111, 66, 193, 0.1)',
                point: '#6f42c1'
            },
            'dns': {
                border: '#fd7e14',
                background: 'rgba(253, 126, 20, 0.1)',
                point: '#fd7e14'
            },
            'ssh': {
                border: '#20c997',
                background: 'rgba(32, 201, 151, 0.1)',
                point: '#20c997'
            }
        };

        const datasets = eventTypes.map(type => ({
            label: type.charAt(0).toUpperCase() + type.slice(1),
            data: Array.from({length: 24}, (_, hour) => hourlyData[hour][type] || 0),
            borderColor: colors[type]?.border || '#6c757d',
            backgroundColor: colors[type]?.background || 'rgba(108, 117, 125, 0.1)',
            pointBackgroundColor: colors[type]?.point || '#6c757d',
            pointBorderColor: colors[type]?.point || '#6c757d',
            pointHoverBackgroundColor: colors[type]?.point || '#6c757d',
            pointHoverBorderColor: '#fff',
            fill: true,
            tension: 0.4,
            pointRadius: 5,
            pointHoverRadius: 8,
            borderWidth: 3,
            pointBorderWidth: 2
        }));

        // Get canvas element
        const canvas = document.getElementById('trendsChart');
        if (!canvas) return;

        // Destroy existing chart if it exists
        if (this.chart) {
            this.chart.destroy();
        }

        // Create new Chart.js chart with enhanced styling
        this.chart = new Chart(canvas, {
            type: 'line',
            data: {
                labels: labels,
                datasets: datasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Network Event Trends - 24 Hour Overview',
                        font: {
                            size: 18,
                            weight: 'bold',
                            family: 'system-ui, -apple-system, sans-serif'
                        },
                        color: '#2c3e50',
                        padding: {
                            top: 10,
                            bottom: 30
                        }
                    },
                    legend: {
                        display: true,
                        position: 'top',
                        labels: {
                            usePointStyle: true,
                            padding: 20,
                            font: {
                                size: 12,
                                weight: '600'
                            }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        borderColor: '#ddd',
                        borderWidth: 1,
                        cornerRadius: 8,
                        displayColors: true,
                        callbacks: {
                            title: function(context) {
                                return `Time: ${context[0].label}`;
                            },
                            label: function(context) {
                                return `${context.dataset.label}: ${context.parsed.y} events`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: 'Time of Day',
                            font: {
                                size: 14,
                                weight: '600'
                            },
                            color: '#495057'
                        },
                        grid: {
                            display: true,
                            color: 'rgba(0, 0, 0, 0.1)',
                            drawBorder: false
                        },
                        ticks: {
                            maxRotation: 45,
                            minRotation: 45,
                            font: {
                                size: 11
                            }
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Number of Events',
                            font: {
                                size: 14,
                                weight: '600'
                            },
                            color: '#495057'
                        },
                        beginAtZero: true,
                        grid: {
                            display: true,
                            color: 'rgba(0, 0, 0, 0.1)',
                            drawBorder: false
                        },
                        ticks: {
                            font: {
                                size: 11
                            },
                            callback: function(value) {
                                if (value === 0) return '0';
                                if (value >= 1000) return (value / 1000).toFixed(1) + 'k';
                                return value.toString();
                            }
                        }
                    }
                },
                interaction: {
                    intersect: false,
                    mode: 'index'
                },
                elements: {
                    point: {
                        hoverRadius: 10,
                        hoverBorderWidth: 3
                    }
                },
                animation: {
                    duration: 1000,
                    easing: 'easeInOutQuart'
                }
            }
        });
    }

    addChartInteractivity() {
        // Add hover tooltips to data points
        const dataPoints = document.querySelectorAll('.data-point');
        dataPoints.forEach(point => {
            point.addEventListener('mouseenter', (e) => {
                const hour = e.target.getAttribute('data-hour');
                const count = e.target.getAttribute('data-count');
                const type = e.target.getAttribute('data-type');
                
                // Create tooltip
                const tooltip = document.createElement('div');
                tooltip.className = 'chart-tooltip';
                tooltip.innerHTML = `
                    <strong>${type}</strong><br>
                    Time: ${hour}:00<br>
                    Count: ${count} events
                `;
                document.body.appendChild(tooltip);
                
                // Position tooltip
                const rect = e.target.getBoundingClientRect();
                tooltip.style.left = rect.left + window.scrollX + 10 + 'px';
                tooltip.style.top = rect.top + window.scrollY - 50 + 'px';
            });
            
            point.addEventListener('mouseleave', () => {
                const tooltip = document.querySelector('.chart-tooltip');
                if (tooltip) {
                    tooltip.remove();
                }
            });
        });
    }

    openMalcolmApp() {
        // Open Malcolm app in a new tab
        // You can customize this URL to point to your Malcolm instance
        const malcolmUrl = 'https://localhost'; // Default Malcolm HTTPS port
        window.open(malcolmUrl, '_blank', 'noopener,noreferrer');
    }
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new NetworkAnalyzer();
});
