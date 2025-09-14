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
        this.sampleBtn = document.getElementById('sampleBtn');
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
        this.topTalkers = document.getElementById('topTalkers');
        this.trafficPatterns = document.getElementById('trafficPatterns');
        this.topStatistics = document.getElementById('topStatistics');
        this.eventTrends = document.getElementById('eventTrends');
        this.aiAnalysis = document.getElementById('aiAnalysis');
    }

    attachEventListeners() {
        this.uploadBtn.addEventListener('click', () => this.fileInput.click());
        this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        this.analyzeBtn.addEventListener('click', () => this.analyzeData());
        this.sampleBtn.addEventListener('click', () => this.useSampleData());
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
        
        // Display top talkers
        this.displayTopTalkers(analysisData.analytics_results);
        
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
        
        if (security.alert_severity_distribution) {
            html += '<h4>Alert Severity Distribution</h4>';
            security.alert_severity_distribution.forEach(item => {
                html += `
                    <div class="stat-item">
                        <span class="stat-label">Severity ${item.severity}:</span>
                        <span class="stat-value severity-${item.severity}">${item.count} alerts</span>
                    </div>
                `;
            });
        }
        
        if (security.top_signatures) {
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
        const data = analyticsResults;
        // Display anomalies (including least squares regression results)
        let allAnomalies = [];
        
        // Add statistical anomalies
        if (data.anomaly_detection && data.anomaly_detection.length > 0) {
            allAnomalies = allAnomalies.concat(data.anomaly_detection.filter(a => a.count > 0));
        }
        
        // Add data science anomalies
        if (data.data_science_anomalies && data.data_science_anomalies.length > 0) {
            allAnomalies = allAnomalies.concat(data.data_science_anomalies.filter(a => a.count > 0));
        }
        
        let html = '';
        if (allAnomalies.length > 0) {
            html += '<h4>🚨 Detected Anomalies:</h4>';
            allAnomalies.forEach(anomaly => {
                const severity = this.getAnomalySeverity(anomaly.anomaly_type, anomaly.count);
                html += `<div class="anomaly-item anomaly-${severity}">
                    <strong>${anomaly.anomaly_type.replace(/_/g, ' ').toUpperCase()}:</strong> 
                    ${anomaly.count} occurrences
                    ${anomaly.description ? `<br><small>${anomaly.description}</small>` : ''}
                    ${anomaly.outlier_hours ? `<br><small>Outlier hours: ${anomaly.outlier_hours.join(', ')}</small>` : ''}
                    ${anomaly.max_residual ? `<br><small>Max deviation: ${anomaly.max_residual.toFixed(2)}</small>` : ''}
                </div>`;
            });
        } else {
            html += '<p>No anomalies detected.</p>';
        }
        
        this.detectedAnomalies.innerHTML = html;
    }

    displayTopTalkers(analyticsResults) {
        const traffic = analyticsResults.traffic_patterns || {};
        let html = '';
        
        if (traffic.top_talkers_by_traffic) {
            html += '<h4>By Traffic Volume</h4>';
            traffic.top_talkers_by_traffic.slice(0, 3).forEach(item => {
                html += `
                    <div class="stat-item">
                        <span class="stat-label">${item.src_ip} → ${item.dest_ip}:</span>
                        <span class="stat-value">${item.total_events} events</span>
                    </div>
                `;
            });
        }
        
        if (traffic.top_alert_generators) {
            html += '<h4>Alert Generators</h4>';
            traffic.top_alert_generators.slice(0, 3).forEach(item => {
                html += `
                    <div class="stat-item">
                        <span class="stat-label">${item.src_ip}:</span>
                        <span class="stat-value">${item.alert_count} alerts</span>
                    </div>
                `;
            });
        }
        
        this.topTalkers.innerHTML = html || '<p>No traffic data available</p>';
    }

    displayTopStatistics(analyticsResults) {
        const security = analyticsResults.security_analysis || {};
        const traffic = analyticsResults.traffic_patterns || {};
        let html = '';
        
        if (security.suspicious_ports) {
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
        
        if (traffic.protocol_distribution) {
            html += '<h4>Protocol Distribution</h4>';
            traffic.protocol_distribution.slice(0, 3).forEach(item => {
                html += `
                    <div class="stat-item">
                        <span class="stat-label">${item.proto}:</span>
                        <span class="stat-value">${item.count} events</span>
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
        // Convert markdown-like formatting to HTML
        let formatted = text
            .replace(/\*\*(.*?)\*\*/g, '<h4>$1</h4>')
            .replace(/\* (.*?)(?=\n|$)/g, '<li>$1</li>')
            .replace(/(\n|^)(\d+\. .*?)(?=\n|$)/g, '<h4>$2</h4>')
            .replace(/\n\n/g, '</p><p>')
            .replace(/\n/g, '<br>');

        // Wrap list items in ul tags
        formatted = formatted.replace(/(<li>.*?<\/li>)/gs, '<ul>$1</ul>');
        
        // Wrap in paragraphs
        if (!formatted.startsWith('<h4>') && !formatted.startsWith('<ul>')) {
            formatted = '<p>' + formatted + '</p>';
        }

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
        if (anomalyType === 'high_severity_alerts' && count > 10) return 'high';
        if (anomalyType === 'expired_tls' && count > 5) return 'high';
        if (anomalyType === 'oversized_payloads' && count > 20) return 'high';
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
        const labels = Array.from({length: 24}, (_, i) => `${i}:00`);
        const colors = {
            'alert': '#dc3545',
            'tls': '#28a745',
            'http': '#007bff',
            'flow': '#6f42c1'
        };

        const datasets = eventTypes.map(type => ({
            label: type.toUpperCase(),
            data: Array.from({length: 24}, (_, hour) => hourlyData[hour][type] || 0),
            borderColor: colors[type] || '#666',
            backgroundColor: colors[type] || '#666',
            fill: false,
            tension: 0.1,
            pointRadius: 4,
            pointHoverRadius: 6
        }));

        // Get canvas element
        const canvas = document.getElementById('trendsChart');
        if (!canvas) return;

        // Destroy existing chart if it exists
        if (this.chart) {
            this.chart.destroy();
        }

        // Create new Chart.js chart
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
                        text: 'Event Trends Over 24 Hours',
                        font: {
                            size: 16,
                            weight: 'bold'
                        }
                    },
                    legend: {
                        display: true,
                        position: 'top'
                    }
                },
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: 'Time (24-hour format)'
                        },
                        grid: {
                            display: true,
                            color: '#e0e0e0'
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Event Count'
                        },
                        beginAtZero: true,
                        grid: {
                            display: true,
                            color: '#e0e0e0'
                        }
                    }
                },
                interaction: {
                    intersect: false,
                    mode: 'index'
                },
                elements: {
                    point: {
                        hoverRadius: 8
                    }
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
        const malcolmUrl = 'https://localhost:8443'; // Default Malcolm HTTPS port
        window.open(malcolmUrl, '_blank', 'noopener,noreferrer');
    }
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new NetworkAnalyzer();
});
