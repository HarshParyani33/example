document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form');
    const scanProgress = document.getElementById('scan-progress');
    const progressBar = document.getElementById('progress-bar');
    const liveLog = document.getElementById('live-log');
    const summaryData = JSON.parse(document.getElementById('summary-data').textContent || '{}');
    const canvasEl = document.getElementById('summaryChart');
    const ctx = canvasEl ? canvasEl.getContext('2d') : null;
    const totalFindings = summaryData ? (summaryData.critical || 0) + (summaryData.high || 0) + (summaryData.medium || 0) + (summaryData.low || 0) : 0;
    const resultData = (document.getElementById('result-data') && JSON.parse(document.getElementById('result-data').textContent || '{}')) || {};
    const themeToggle = document.getElementById('theme-toggle');
    const themeIcon = document.querySelector('label[for="theme-toggle"] i');
    let summaryChart = null;

    // --- Chart Logic ---
    function createOrUpdateChart() {
        if (!ctx) return;

        const isDarkMode = document.body.classList.contains('dark-mode');
        const textColor = isDarkMode ? '#f8f9fa' : '#212529';

        const chartOptions = {
            plugins: {
                title: {
                    display: true,
                    text: 'Findings by severity' + (totalFindings ? ` (Total: ${totalFindings})` : ''),
                    color: textColor,
                },
                legend: {
                    position: 'bottom',
                    labels: {
                        color: textColor, // General color
                        generateLabels: function(chart) {
                            const data = chart.data;
                            if (!data.labels || !data.labels.length) return [];
                            const values = data.datasets[0].data;
                            const tot = values.reduce((a, b) => a + b, 0);
                            const meta = chart.getDatasetMeta(0);
                            return data.labels.map(function(label, i) {
                                const v = values[i] || 0;
                                const pct = tot ? ((v / tot) * 100).toFixed(1) : '0.0';
                                const style = meta.controller.getStyle(i);
                                return {
                                    text: `${label}: ${v} (${pct}%)`,
                                    fillStyle: style.backgroundColor,
                                    strokeStyle: style.borderColor,
                                    lineWidth: style.borderWidth,
                                    hidden: isNaN(values[i]) || meta.data[i].hidden,
                                    index: i,
                                    // This is the added line to fix the legend text color
                                    fontColor: textColor 
                                };
                            });
                        }
                    }
                },
                tooltip: {
                    bodyColor: textColor,
                    callbacks: {
                        label: function(context) {
                            const v = context.parsed;
                            const tot = totalFindings || 0;
                            const pct = tot ? ((v / tot) * 100).toFixed(1) : '0.0';
                            const sev = (context.label || '').toLowerCase();
                            const parts = severityContrib[sev] && severityContrib[sev].length ? ' — from ' + severityContrib[sev].join('; ') : '';
                            return `${context.label}: ${v} (${pct}%)` + parts;
                        }
                    }
                }
            },
            responsive: true,
            maintainAspectRatio: false
        };

        if (summaryChart) {
            summaryChart.options = chartOptions;
            summaryChart.update();
        } else {
            summaryChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        data: [
                            summaryData.critical || 0,
                            summaryData.high || 0,
                            summaryData.medium || 0,
                            summaryData.low || 0
                        ],
                        backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#198754'],
                    }]
                },
                options: chartOptions
            });
        }
    }

    // --- Theme Switcher Logic ---
    const currentTheme = localStorage.getItem('theme');
    if (currentTheme) {
        document.body.classList.add(currentTheme);
        if (currentTheme === 'dark-mode') {
            themeToggle.checked = true;
            themeIcon.classList.remove('fa-moon');
            themeIcon.classList.add('fa-sun');
        }
    }

    themeToggle.addEventListener('change', function() {
        if (this.checked) {
            document.body.classList.add('dark-mode');
            themeIcon.classList.remove('fa-moon');
            themeIcon.classList.add('fa-sun');
            localStorage.setItem('theme', 'dark-mode');
        } else {
            document.body.classList.remove('dark-mode');
            themeIcon.classList.remove('fa-sun');
            themeIcon.classList.add('fa-moon');
            localStorage.setItem('theme', 'light-mode');
        }
        createOrUpdateChart();
    });

    // --- Scan Option Button Logic ---
    const scanOptionButtons = document.querySelectorAll('.scan-option-btn');
    scanOptionButtons.forEach(button => {
        button.addEventListener('click', function() {
            this.classList.toggle('selected');
            const checkName = this.dataset.check;
            const hiddenInput = document.querySelector(`input[name="${checkName}"]`);
            hiddenInput.value = this.classList.contains('selected') ? 'true' : '';
        });
    });

    // --- Form Submission Logic ---
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        scanProgress.style.display = 'block';

        let progress = 0;
        const messages = [
            'Initializing scanners...',
            'Probing for open ports...',
            'Analyzing HTTP headers...',
            'Testing for XSS vulnerabilities...',
            'Checking for SQL injection points...',
            'Scanning for open redirects...',
            'Finalizing report...'
        ];

        const interval = setInterval(() => {
            progress += Math.random() * 15;
            if (progress > 100) progress = 100;
            progressBar.style.width = progress + '%';
            progressBar.textContent = Math.round(progress) + '%';
            liveLog.textContent = messages[Math.floor((progress / 100) * (messages.length - 1))];

            if (progress === 100) {
                clearInterval(interval);
                setTimeout(() => form.submit(), 500);
            }
        }, 400);
    });

    // --- Initial Chart Creation ---
    const severityContrib = buildSeverityContrib(resultData);
    createOrUpdateChart();

    function buildSeverityContrib(resultObj) {
        const contrib = { critical: [], high: [], medium: [], low: [] };
        if (!resultObj || typeof resultObj !== 'object') return contrib;
        if (resultObj.xss && resultObj.xss.vulnerable) {
            const n = (resultObj.xss.details || []).length || 1;
            contrib.critical.push(`XSS: ${n}`);
        }
        if (resultObj.sqli && resultObj.sqli.vulnerable) {
            const n = (resultObj.sqli.details || []).length || 1;
            contrib.high.push(`SQLi: ${n}`);
        }
        if (resultObj.redirect && resultObj.redirect.vulnerable) {
            const n = (resultObj.redirect.details || []).length || 1;
            contrib.high.push(`Open Redirect: ${n}`);
        }
        if (resultObj.cors && resultObj.cors.vulnerable) {
            const n = (resultObj.cors.details || []).length || 1;
            contrib.medium.push(`CORS: ${n}`);
        }
        if (resultObj.cookies && resultObj.cookies.vulnerable) {
            const n = (resultObj.cookies.details || []).length || 1;
            contrib.low.push(`Cookies: ${n}`);
        }
        if (resultObj.headers && resultObj.headers.missing_headers) {
            const missing = resultObj.headers.missing_headers || [];
            const buckets = { critical: [], high: [], medium: [], low: [] };
            missing.forEach(function(h){
                const sev = (h.severity || '').toLowerCase();
                if (sev && buckets[sev] !== undefined) buckets[sev].push(h.header || 'Header');
            });
            Object.keys(buckets).forEach(function(s){
                if (buckets[s].length) {
                    const names = buckets[s].slice(0,3).join(', ');
                    const more = buckets[s].length > 3 ? ` +${buckets[s].length - 3} more` : '';
                    contrib[s].push(`Headers: ${names}${more}`);
                }
            });
        }
        return contrib;
    }
});
