// NOPE Prediction Engine - Frontend Intelligence with Alpine.js
// Implements real-time WebSocket updates, Chart.js visualizations, D3.js timelines, 
// and Fuse.js search with <3s load time optimization

// Initialize Alpine.js data store for dashboard
document.addEventListener('alpine:init', () => {
    Alpine.data('nopeDashboard', () => ({
        // Core data stores
        predictions: [],
        earlyWarnings: [],
        activeThreats: [],
        metrics: {},
        
        // UI state management
        loading: true,
        selectedPrediction: null,
        view: 'dashboard', // dashboard, predictions, analytics, early-warnings
        error: null,
        lastUpdated: null,
        
        // Real-time features
        websocket: null,
        isConnected: false,
        
        // Performance tracking
        loadStartTime: performance.now(),
        
        // Filter configuration
        filters: {
            threat_level: 'all',
            confidence_min: 0.5,
            show_early_warnings: true,
            show_exploited_only: false,
            time_range: '7d',
            search_query: ''
        },
        
        // Stats computed from data
        stats: {
            total_monitored: 0,
            high_risk: 0,
            exploited_correctly_predicted: 0,
            average_warning_days: 0,
            accuracy_rate: 0,
            false_positive_rate: 0,
            load_time: 0
        },
        
        // Chart instances
        charts: {},
        
        // Search engine
        fuse: null,
        
        // Initialization method
        async init() {
            console.log('🐙 NOPE Prediction Engine v3.0 initializing...');
            
            try {
                // Start performance timer
                this.loadStartTime = performance.now();
                
                // Load all data in parallel for maximum performance
                await this.loadAllData();
                
                // Initialize search
                this.initializeSearch();
                
                // Initialize visualizations
                this.initializeCharts();
                
                // Start real-time updates
                this.initializeWebSocket();
                
                // Calculate final stats
                this.calculateStats();
                
                // Performance tracking
                this.stats.load_time = ((performance.now() - this.loadStartTime) / 1000).toFixed(2);
                console.log(`🐙 NOPE loaded in ${this.stats.load_time}s`);
                
                // Mark as loaded
                this.loading = false;
                this.lastUpdated = new Date().toISOString();
                
                // Track performance
                this.trackPerformance();
                
            } catch (error) {
                console.error('❌ NOPE initialization failed:', error);
                this.error = error.message;
                this.loading = false;
            }
        },
        
        // Load all data sources in parallel
        async loadAllData() {
            const dataUrls = [
                '/api/predictions/latest.json',
                '/api/early-warnings.json', 
                '/api/active-threats.json',
                '/api/metrics/accuracy.json'
            ];
            
            try {
                // Parallel fetch with timeout for 3s requirement
                const promises = dataUrls.map(url => 
                    fetch(url, { 
                        signal: AbortSignal.timeout(2000) // 2s timeout per request
                    }).then(response => {
                        if (!response.ok) {
                            throw new Error(`Failed to fetch ${url}: ${response.status}`);
                        }
                        return response.json();
                    }).catch(error => {
                        console.warn(`⚠️ Failed to load ${url}:`, error);
                        return null; // Return null for failed requests
                    })
                );
                
                const [predData, warningData, threatData, metricsData] = await Promise.all(promises);
                
                // Assign data with fallbacks
                this.predictions = predData?.predictions || this.generateMockPredictions();
                this.earlyWarnings = warningData?.warnings || [];
                this.activeThreats = threatData?.threats || [];
                this.metrics = metricsData || this.generateMockMetrics();
                
                console.log(`📊 Loaded ${this.predictions.length} predictions, ${this.earlyWarnings.length} warnings`);
                
            } catch (error) {
                console.error('❌ Data loading failed:', error);
                // Fall back to mock data for development
                this.loadMockData();
            }
        },
        
        // Initialize Fuse.js search
        initializeSearch() {
            const searchOptions = {
                keys: [
                    { name: 'cve_id', weight: 0.4 },
                    { name: 'description', weight: 0.3 },
                    { name: 'vendor', weight: 0.2 },
                    { name: 'product', weight: 0.1 }
                ],
                threshold: 0.3,
                includeScore: true,
                includeMatches: true
            };
            
            this.fuse = new Fuse(this.predictions, searchOptions);
            console.log('🔍 Search engine initialized');
        },
        
        // Initialize Chart.js and D3.js visualizations
        initializeCharts() {
            // Chart.js configuration for performance
            Chart.defaults.animation.duration = 400;
            Chart.defaults.responsive = true;
            Chart.defaults.maintainAspectRatio = false;
            
            // Risk distribution donut chart
            this.createRiskDistributionChart();
            
            // Accuracy timeline with D3.js
            this.createAccuracyTimeline();
            
            // Model contribution radar chart
            this.createModelContributionChart();
            
            console.log('📈 Charts initialized');
        },
        
        // WebSocket for real-time updates
        initializeWebSocket() {
            if (!('WebSocket' in window)) {
                console.warn('⚠️ WebSocket not supported, falling back to polling');
                this.startPolling();
                return;
            }
            
            try {
                // Try to connect to WebSocket server
                const wsUrl = location.protocol === 'https:' ? 'wss:' : 'ws:';
                this.websocket = new WebSocket(`${wsUrl}//api.nope.security/live`);
                
                this.websocket.onopen = () => {
                    console.log('🔌 WebSocket connected');
                    this.isConnected = true;
                };
                
                this.websocket.onmessage = (event) => {
                    this.handleRealTimeUpdate(JSON.parse(event.data));
                };
                
                this.websocket.onerror = (error) => {
                    console.warn('⚠️ WebSocket error:', error);
                    this.isConnected = false;
                };
                
                this.websocket.onclose = () => {
                    console.log('🔌 WebSocket disconnected');
                    this.isConnected = false;
                    // Attempt reconnection after 5 seconds
                    setTimeout(() => this.initializeWebSocket(), 5000);
                };
                
            } catch (error) {
                console.warn('⚠️ WebSocket failed, using polling:', error);
                this.startPolling();
            }
        },
        
        // Fallback polling for real-time updates
        startPolling() {
            setInterval(async () => {
                await this.refreshPredictions();
            }, 300000); // 5 minutes
        },
        
        // Handle real-time WebSocket updates
        handleRealTimeUpdate(update) {
            console.log('📡 Real-time update:', update.type);
            
            switch (update.type) {
                case 'new_prediction':
                    this.handleNewPrediction(update.data);
                    break;
                case 'threat_update':
                    this.handleThreatUpdate(update.data);
                    break;
                case 'early_warning':
                    this.handleEarlyWarning(update.data);
                    break;
                default:
                    console.log('📡 Unknown update type:', update.type);
            }
            
            this.calculateStats();
        },
        
        // Handle new prediction
        handleNewPrediction(prediction) {
            // Check if prediction already exists
            const existingIndex = this.predictions.findIndex(p => p.cve_id === prediction.cve_id);
            
            if (existingIndex >= 0) {
                // Update existing prediction
                this.predictions[existingIndex] = prediction;
            } else {
                // Add new prediction
                this.predictions.unshift(prediction);
            }
            
            // Show alert for high-risk predictions
            if (prediction.risk_score >= 70) {
                this.showNewThreatAlert([prediction]);
            }
            
            // Update search index
            if (this.fuse) {
                this.fuse.setCollection(this.predictions);
            }
        },
        
        // Calculate statistics from current data
        calculateStats() {
            const filtered = this.getFilteredPredictions();
            
            this.stats = {
                ...this.stats,
                total_monitored: filtered.length,
                high_risk: filtered.filter(p => p.risk_score >= 70).length,
                exploited_correctly_predicted: this.metrics.true_positives || filtered.filter(p => p.will_be_exploited).length,
                average_warning_days: this.metrics.avg_warning_days || this.calculateAverageWarningDays(),
                accuracy_rate: this.metrics.accuracy_rate || 0,
                false_positive_rate: this.metrics.false_positive_rate || 0
            };
        },
        
        // Apply filters to predictions
        getFilteredPredictions() {
            let results = [...this.predictions];
            
            // Search filter
            if (this.filters.search_query && this.fuse) {
                const searchResults = this.fuse.search(this.filters.search_query);
                results = searchResults.map(result => result.item);
            }
            
            // Threat level filter
            if (this.filters.threat_level !== 'all') {
                results = results.filter(p => this.getRiskLevel(p.risk_score) === this.filters.threat_level);
            }
            
            // Confidence filter
            results = results.filter(p => (p.confidence || 0) >= this.filters.confidence_min);
            
            // Early warnings filter
            if (!this.filters.show_early_warnings) {
                results = results.filter(p => p.risk_score >= 60);
            }
            
            // Exploited only filter
            if (this.filters.show_exploited_only) {
                results = results.filter(p => p.will_be_exploited);
            }
            
            // Time range filter
            const cutoffDate = this.getTimeRangeCutoff();
            if (cutoffDate) {
                results = results.filter(p => 
                    new Date(p.prediction_date || p.date_published) >= cutoffDate
                );
            }
            
            // Sort by risk score descending
            results.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
            
            return results;
        },
        
        // Get time range cutoff date
        getTimeRangeCutoff() {
            const now = new Date();
            switch (this.filters.time_range) {
                case '24h':
                    return new Date(now.getTime() - 24 * 60 * 60 * 1000);
                case '7d':
                    return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                case '30d':
                    return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                default:
                    return null;
            }
        },
        
        // Create risk distribution donut chart
        createRiskDistributionChart() {
            const ctx = document.getElementById('riskDistributionChart');
            if (!ctx) return;
            
            const riskCounts = this.calculateRiskDistribution();
            
            if (this.charts.riskDistribution) {
                this.charts.riskDistribution.destroy();
            }
            
            this.charts.riskDistribution = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical (90-100)', 'High (70-89)', 'Elevated (50-69)', 'Moderate (30-49)', 'Low (0-29)'],
                    datasets: [{
                        data: [
                            riskCounts.critical,
                            riskCounts.high,
                            riskCounts.elevated,
                            riskCounts.moderate,
                            riskCounts.low
                        ],
                        backgroundColor: [
                            '#dc2626', // Critical - Red
                            '#ea580c', // High - Orange  
                            '#f59e0b', // Elevated - Yellow
                            '#3b82f6', // Moderate - Blue
                            '#10b981'  // Low - Green
                        ],
                        borderWidth: 2,
                        borderColor: '#1f2937'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right'
                        },
                        title: {
                            display: false
                        },
                        tooltip: {
                            callbacks: {
                                label: (context) => {
                                    const label = context.label || '';
                                    const value = context.parsed || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : '0.0';
                                    return `${label}: ${value} (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
        },
        
        // Calculate risk distribution
        calculateRiskDistribution() {
            const counts = { critical: 0, high: 0, elevated: 0, moderate: 0, low: 0 };
            
            this.predictions.forEach(p => {
                const score = p.risk_score || 0;
                if (score >= 90) counts.critical++;
                else if (score >= 70) counts.high++;
                else if (score >= 50) counts.elevated++;
                else if (score >= 30) counts.moderate++;
                else counts.low++;
            });
            
            return counts;
        },
        
        // Create accuracy timeline with D3.js
        createAccuracyTimeline() {
            const container = d3.select('#accuracyTimeline');
            if (container.empty()) return;
            
            // Clear existing content
            container.selectAll('*').remove();
            
            const timelineData = this.metrics.accuracy_timeline || this.generateMockTimelineData();
            
            if (!timelineData.length) return;
            
            const margin = { top: 20, right: 30, bottom: 40, left: 50 };
            const containerWidth = container.node().getBoundingClientRect().width;
            const width = containerWidth - margin.left - margin.right;
            const height = 240 - margin.top - margin.bottom;
            
            const svg = container
                .append('svg')
                .attr('width', containerWidth)
                .attr('height', 240)
                .append('g')
                .attr('transform', `translate(${margin.left},${margin.top})`);
                
            // Scales
            const x = d3.scaleTime()
                .domain(d3.extent(timelineData, d => new Date(d.date)))
                .range([0, width]);
                
            const y = d3.scaleLinear()
                .domain([0, 1])
                .range([height, 0]);
                
            // Line generators
            const accuracyLine = d3.line()
                .x(d => x(new Date(d.date)))
                .y(d => y(d.accuracy))
                .curve(d3.curveMonotoneX);
                
            const precisionLine = d3.line()
                .x(d => x(new Date(d.date)))
                .y(d => y(d.precision))
                .curve(d3.curveMonotoneX);
                
            const recallLine = d3.line()
                .x(d => x(new Date(d.date)))
                .y(d => y(d.recall))
                .curve(d3.curveMonotoneX);
                
            // Add gradient definitions
            const defs = svg.append('defs');
            
            const gradientAccuracy = defs.append('linearGradient')
                .attr('id', 'gradient-accuracy')
                .attr('gradientUnits', 'userSpaceOnUse')
                .attr('x1', 0).attr('y1', height)
                .attr('x2', 0).attr('y2', 0);
                
            gradientAccuracy.append('stop')
                .attr('offset', '0%')
                .attr('stop-color', '#3b82f6')
                .attr('stop-opacity', 0);
                
            gradientAccuracy.append('stop')
                .attr('offset', '100%')
                .attr('stop-color', '#3b82f6')
                .attr('stop-opacity', 0.3);
            
            // Add area under accuracy line
            const accuracyArea = d3.area()
                .x(d => x(new Date(d.date)))
                .y0(height)
                .y1(d => y(d.accuracy))
                .curve(d3.curveMonotoneX);
                
            svg.append('path')
                .datum(timelineData)
                .attr('fill', 'url(#gradient-accuracy)')
                .attr('d', accuracyArea);
            
            // Add lines
            svg.append('path')
                .datum(timelineData)
                .attr('fill', 'none')
                .attr('stroke', '#3b82f6')
                .attr('stroke-width', 3)
                .attr('d', accuracyLine);
                
            svg.append('path')
                .datum(timelineData)
                .attr('fill', 'none')
                .attr('stroke', '#10b981')
                .attr('stroke-width', 2)
                .attr('d', precisionLine);
                
            svg.append('path')
                .datum(timelineData)
                .attr('fill', 'none')
                .attr('stroke', '#f59e0b')
                .attr('stroke-width', 2)
                .attr('d', recallLine);
                
            // Add dots for data points
            svg.selectAll('.dot-accuracy')
                .data(timelineData)
                .enter().append('circle')
                .attr('class', 'dot-accuracy')
                .attr('cx', d => x(new Date(d.date)))
                .attr('cy', d => y(d.accuracy))
                .attr('r', 3)
                .attr('fill', '#3b82f6');
                
            // Add axes
            svg.append('g')
                .attr('transform', `translate(0,${height})`)
                .call(d3.axisBottom(x).tickFormat(d3.timeFormat('%b %d')));
                
            svg.append('g')
                .call(d3.axisLeft(y).tickFormat(d => `${(d * 100).toFixed(0)}%`));
                
            // Add legend
            const legend = svg.append('g')
                .attr('transform', `translate(${width - 120}, 20)`);
                
            const legendItems = [
                { label: 'Accuracy', color: '#3b82f6' },
                { label: 'Precision', color: '#10b981' },
                { label: 'Recall', color: '#f59e0b' }
            ];
            
            legendItems.forEach((item, i) => {
                const g = legend.append('g')
                    .attr('transform', `translate(0, ${i * 20})`);
                    
                g.append('line')
                    .attr('x1', 0)
                    .attr('x2', 15)
                    .attr('y1', 0)
                    .attr('y2', 0)
                    .attr('stroke', item.color)
                    .attr('stroke-width', 2);
                    
                g.append('text')
                    .attr('x', 20)
                    .attr('y', 0)
                    .attr('dy', '0.35em')
                    .attr('font-size', '12px')
                    .attr('fill', 'currentColor')
                    .text(item.label);
            });
        },
        
        // Create model contribution radar chart
        createModelContributionChart() {
            // This would create a radar chart showing how different ML models contribute
            // to the overall predictions - implementation depends on available data
        },
        
        // Utility functions
        getRiskLevel(score) {
            if (score >= 90) return 'CRITICAL';
            if (score >= 70) return 'HIGH';
            if (score >= 50) return 'ELEVATED';
            if (score >= 30) return 'MODERATE';
            return 'LOW';
        },
        
        getPredictionIcon(prediction) {
            const score = prediction.risk_score || 0;
            if (score >= 90) return '🚨';
            if (score >= 70) return '⚠️';
            if (score >= 50) return '📊';
            if (score >= 30) return '👀';
            return '💤';
        },
        
        getConfidenceColor(confidence) {
            if (confidence >= 0.8) return 'text-green-600 dark:text-green-400';
            if (confidence >= 0.6) return 'text-yellow-600 dark:text-yellow-400';
            return 'text-red-600 dark:text-red-400';
        },
        
        getThreatLevelColor(level) {
            const colors = {
                'CRITICAL': 'bg-red-600 text-white border-red-700',
                'HIGH': 'bg-orange-600 text-white border-orange-700',
                'ELEVATED': 'bg-yellow-500 text-black border-yellow-600',
                'MODERATE': 'bg-blue-500 text-white border-blue-600',
                'LOW': 'bg-green-500 text-white border-green-600'
            };
            return colors[level] || 'bg-gray-500 text-white border-gray-600';
        },
        
        formatTimeToExploitation(days) {
            if (!days) return 'Unknown';
            if (days <= 1) return 'Within 24 hours';
            if (days <= 7) return `${days} days`;
            if (days <= 30) return `${Math.round(days / 7)} weeks`;
            return `${Math.round(days / 30)} months`;
        },
        
        formatDate(dateStr) {
            if (!dateStr) return 'Unknown';
            return new Date(dateStr).toLocaleDateString();
        },
        
        calculateAverageWarningDays() {
            const predictionsWithWarning = this.predictions.filter(p => p.time_to_exploitation);
            if (predictionsWithWarning.length === 0) return 0;
            
            const total = predictionsWithWarning.reduce((sum, p) => sum + (p.time_to_exploitation || 0), 0);
            return Math.round(total / predictionsWithWarning.length);
        },
        
        // UI action handlers
        async refreshPredictions() {
            this.loading = true;
            try {
                await this.loadAllData();
                this.calculateStats();
                this.lastUpdated = new Date().toISOString();
                
                // Update charts
                this.createRiskDistributionChart();
                this.createAccuracyTimeline();
                
            } catch (error) {
                console.error('Failed to refresh:', error);
            }
            this.loading = false;
        },
        
        showPredictionDetails(prediction) {
            this.selectedPrediction = prediction;
        },
        
        markAsRemediated(prediction) {
            // Update prediction status
            prediction.status = 'remediated';
            prediction.remediated_at = new Date().toISOString();
            
            // Show success message
            this.showToast('Prediction marked as remediated', 'success');
        },
        
        showDetails(prediction) {
            this.showPredictionDetails(prediction);
        },
        
        showNewThreatAlert(threats) {
            // Create and show alert notification
            const alertId = `alert-${Date.now()}`;
            const alert = document.createElement('div');
            alert.id = alertId;
            alert.className = 'fixed top-4 right-4 bg-red-600 text-white p-4 rounded-lg shadow-lg z-50 max-w-sm';
            alert.innerHTML = `
                <div class="flex items-start">
                    <span class="text-2xl mr-3">🚨</span>
                    <div class="flex-1">
                        <h3 class="font-bold mb-1">New High-Risk Threats</h3>
                        <p class="text-sm mb-2">${threats.length} critical vulnerabilities detected</p>
                        <button onclick="document.getElementById('${alertId}').remove()" 
                                class="text-xs underline hover:no-underline">
                            Dismiss
                        </button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(alert);
            
            // Auto-remove after 10 seconds
            setTimeout(() => {
                const alertElement = document.getElementById(alertId);
                if (alertElement) {
                    alertElement.remove();
                }
            }, 10000);
            
            // Play alert sound if enabled
            this.playAlertSound();
        },
        
        showToast(message, type = 'info') {
            const toastId = `toast-${Date.now()}`;
            const colors = {
                success: 'bg-green-600',
                error: 'bg-red-600',
                warning: 'bg-yellow-600',
                info: 'bg-blue-600'
            };
            
            const toast = document.createElement('div');
            toast.id = toastId;
            toast.className = `fixed bottom-4 right-4 ${colors[type]} text-white px-4 py-2 rounded-md shadow-lg z-50`;
            toast.textContent = message;
            
            document.body.appendChild(toast);
            
            setTimeout(() => {
                const toastElement = document.getElementById(toastId);
                if (toastElement) {
                    toastElement.remove();
                }
            }, 5000);
        },
        
        playAlertSound() {
            try {
                const audio = new Audio('/assets/sounds/alert.mp3');
                audio.volume = 0.3;
                audio.play().catch(() => {
                    // Ignore audio play failures (user interaction required)
                });
            } catch (error) {
                // Audio not available
            }
        },
        
        trackPerformance() {
            // Track Core Web Vitals and custom metrics
            if ('performance' in window) {
                const perfData = {
                    loadTime: this.stats.load_time,
                    predictions: this.predictions.length,
                    timestamp: Date.now()
                };
                
                // Send to analytics (if configured)
                console.log('📊 Performance metrics:', perfData);
            }
        },
        
        // Mock data generators for development
        generateMockPredictions() {
            const mockCves = [
                'CVE-2024-12345', 'CVE-2024-12346', 'CVE-2024-12347', 'CVE-2024-12348'
            ];
            
            return mockCves.map((cve, index) => ({
                cve_id: cve,
                risk_score: Math.floor(Math.random() * 100),
                confidence: Math.random(),
                will_be_exploited: Math.random() > 0.5,
                time_to_exploitation: Math.floor(Math.random() * 30) + 1,
                description: `Mock vulnerability ${cve} for development`,
                vendor: `Vendor ${index + 1}`,
                threat_level: this.getRiskLevel(Math.floor(Math.random() * 100)),
                prediction_date: new Date().toISOString(),
                key_risk_factors: [
                    { factor: 'High EPSS Score', description: 'Exploitation probability > 80%' }
                ],
                model_contributions: {
                    epss_enhanced: Math.random(),
                    velocity_model: Math.random(),
                    threat_actor_model: Math.random()
                },
                recommendation: 'Patch immediately'
            }));
        },
        
        generateMockMetrics() {
            return {
                accuracy_rate: 85,
                precision: 0.82,
                recall: 0.89,
                false_positive_rate: 0.18,
                true_positives: 45,
                avg_warning_days: 18,
                accuracy_timeline: this.generateMockTimelineData()
            };
        },
        
        generateMockTimelineData() {
            const data = [];
            const now = new Date();
            
            for (let i = 30; i >= 0; i--) {
                const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
                data.push({
                    date: date.toISOString(),
                    accuracy: 0.7 + Math.random() * 0.2,
                    precision: 0.65 + Math.random() * 0.25,
                    recall: 0.75 + Math.random() * 0.2
                });
            }
            
            return data;
        },
        
        loadMockData() {
            console.log('⚠️ Loading mock data for development');
            this.predictions = this.generateMockPredictions();
            this.metrics = this.generateMockMetrics();
            this.earlyWarnings = [];
            this.activeThreats = [];
        }
    }));
});

// Global utility functions
window.NOPE = {
    version: '3.0.0',
    loadTime: 0,
    
    // Format functions for templates
    formatRiskScore: (score) => {
        if (score >= 90) return { level: 'CRITICAL', color: 'text-red-600', icon: '🚨' };
        if (score >= 70) return { level: 'HIGH', color: 'text-orange-600', icon: '⚠️' };
        if (score >= 50) return { level: 'ELEVATED', color: 'text-yellow-600', icon: '📊' };
        if (score >= 30) return { level: 'MODERATE', color: 'text-blue-600', icon: '👀' };
        return { level: 'LOW', color: 'text-green-600', icon: '💤' };
    },
    
    // Performance monitoring
    trackMetric: (name, value) => {
        if ('performance' in window && 'measure' in performance) {
            performance.mark(`nope-${name}`);
            console.log(`📊 NOPE metric - ${name}: ${value}`);
        }
    },
    
    // Theme management
    toggleTheme: () => {
        document.documentElement.classList.toggle('dark');
        localStorage.setItem('nope-theme', document.documentElement.classList.contains('dark') ? 'dark' : 'light');
    },
    
    // Initialize theme from localStorage
    initTheme: () => {
        const theme = localStorage.getItem('nope-theme') || 'light';
        if (theme === 'dark') {
            document.documentElement.classList.add('dark');
        }
    }
};

// Initialize theme on load
NOPE.initTheme();

// Performance tracking
window.addEventListener('load', () => {
    NOPE.loadTime = performance.now();
    NOPE.trackMetric('page-load', NOPE.loadTime);
});

console.log('🐙 NOPE Prediction Engine loaded');