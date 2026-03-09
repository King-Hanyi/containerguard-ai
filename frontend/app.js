/* ============================================================
   ContainerGuard AI — 安全分析控制台 交互逻辑
   ============================================================ */

// ---- CVE 数据 ----
const CVE_DATA = {
    "CVE-2021-44228": {
        name: "Log4Shell",
        severity: "critical",
        description: "Apache Log4j2 JNDI injection vulnerability allows RCE via JndiLookup. CVSS 10.0.",
        intel: { severity: "critical", source: "NVD + GHSA", cvss: 10.0 },
        code: { found: true, query: "JndiLookup", files: ["JndiLookup.java", "JndiManager.java"], evidence: "GitHub API 搜索命中 3 个结果" },
        config: { found: true, package: "log4j-core", version: "2.14.0", vulnerable: true },
        vex: { status: "affected", confidence: 0.9, justification: "漏洞包存在于 SBOM 中且代码中发现漏洞函数调用", reasoning: "LLM 推理: log4j-core 2.14.0 < 2.17.0, JndiLookup 在代码路径上" }
    },
    "CVE-2022-22965": {
        name: "Spring4Shell",
        severity: "critical",
        description: "Spring Framework RCE via data binding on JDK 9+ with ClassPathResource. CVSS 9.8.",
        intel: { severity: "critical", source: "NVD + 内置情报库", cvss: 9.8 },
        code: { found: true, query: "ClassPathResource", files: ["AbstractBeanFactory.java"], evidence: "本地模式匹配: spring-beans, spring-webmvc" },
        config: { found: true, package: "spring-beans", version: "5.3.15", vulnerable: true },
        vex: { status: "affected", confidence: 0.9, justification: "漏洞包存在且代码调用路径可达", reasoning: "LLM 推理: spring-beans 5.3.15 < 5.3.18" }
    },
    "CVE-2014-0160": {
        name: "Heartbleed",
        severity: "high",
        description: "OpenSSL heartbeat extension vulnerability in dtls1_process_heartbeat. CVSS 7.5.",
        intel: { severity: "high", source: "NVD + 内置情报库", cvss: 7.5 },
        code: { found: true, query: "dtls1_process_heartbeat", files: ["ssl/d1_both.c", "ssl/t1_lib.c"], evidence: "本地模式匹配: SSL_read, dtls1_process_heartbeat" },
        config: { found: true, package: "openssl", version: "1.0.1f", vulnerable: true },
        vex: { status: "affected", confidence: 0.9, justification: "漏洞包存在且版本在受影响范围内", reasoning: "LLM 推理: OpenSSL 1.0.1f 在 1.0.1-1.0.1f 范围内" }
    },
    "CVE-2023-36632": {
        name: "Python parseaddr DoS",
        severity: "medium",
        description: "Python email.utils.parseaddr DoS via recursive parsing. CVSS 7.5.",
        intel: { severity: "medium", source: "NVD + 内置情报库", cvss: 7.5 },
        code: { found: true, query: "email.utils.parseaddr", files: [], evidence: "GitHub API 搜索: parseaddr 调用未发现" },
        config: { found: false, package: "python", version: "N/A", vulnerable: false },
        vex: { status: "not_affected", confidence: 0.8, justification: "vulnerable_code_not_in_execute_path: 容器中未调用 parseaddr", reasoning: "LLM 推理: SBOM 中无 cpython, 代码中无 parseaddr 调用" }
    }
};

// ---- 导航切换 ----
document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const section = link.dataset.section;

        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        link.classList.add('active');

        document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
        document.getElementById(section).classList.add('active');
    });
});

// ---- 饼图绘制 ----
function drawRiskChart() {
    const canvas = document.getElementById('risk-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const cx = 140, cy = 140, r = 100;

    const slices = [
        { value: 5, color: '#ef4444', label: 'Critical' },
        { value: 3, color: '#f59e0b', label: 'High' },
        { value: 2, color: '#3b82f6', label: 'Medium' },
    ];
    const total = slices.reduce((s, d) => s + d.value, 0);

    let startAngle = -Math.PI / 2;
    slices.forEach(slice => {
        const sliceAngle = (slice.value / total) * 2 * Math.PI;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, r, startAngle, startAngle + sliceAngle);
        ctx.closePath();
        ctx.fillStyle = slice.color;
        ctx.fill();

        // 添加间隔线
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, r, startAngle, startAngle + sliceAngle);
        ctx.strokeStyle = '#0a0e17';
        ctx.lineWidth = 3;
        ctx.stroke();

        startAngle += sliceAngle;
    });

    // 中心圆（甜甜圈效果）
    ctx.beginPath();
    ctx.arc(cx, cy, 55, 0, Math.PI * 2);
    ctx.fillStyle = '#1a1f35';
    ctx.fill();

    // 中心文字
    ctx.fillStyle = '#e2e8f0';
    ctx.font = '700 28px "JetBrains Mono"';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('10', cx, cy - 8);
    ctx.font = '400 12px Inter';
    ctx.fillStyle = '#94a3b8';
    ctx.fillText('CVEs', cx, cy + 14);
}

// ---- CVE 详情面板 ----
function renderCVEDetail(cveId) {
    const data = CVE_DATA[cveId];
    if (!data) return;

    const severityClass = data.severity;
    const statusIcon = data.vex.status === 'affected' ? '🔴' : '🟢';
    const statusBadgeClass = data.vex.status === 'affected' ? 'danger' : 'safe';

    document.getElementById('cve-panel').innerHTML = `
        <div class="detail-card">
            <div class="detail-card-header">🔍 Intel Agent 情报</div>
            <div class="detail-item"><span class="detail-key">严重级别</span><span class="detail-val ${severityClass}">${data.intel.severity.toUpperCase()}</span></div>
            <div class="detail-item"><span class="detail-key">CVSS</span><span class="detail-val">${data.intel.cvss}</span></div>
            <div class="detail-item"><span class="detail-key">数据来源</span><span class="detail-val">${data.intel.source}</span></div>
            <div class="detail-item"><span class="detail-key">描述</span><span class="detail-val" style="font-family:Inter;max-width:250px;text-align:right">${data.description.slice(0, 80)}...</span></div>
        </div>
        <div class="detail-card">
            <div class="detail-card-header">💻 Code Agent 代码搜索</div>
            <div class="detail-item"><span class="detail-key">漏洞函数</span><span class="detail-val">${data.code.query}</span></div>
            <div class="detail-item"><span class="detail-key">搜索结果</span><span class="detail-val ${data.code.found ? 'found' : 'not-found'}">${data.code.found ? '✅ 发现匹配' : '⬜ 未发现'}</span></div>
            <div class="detail-item"><span class="detail-key">匹配文件</span><span class="detail-val">${data.code.files.length > 0 ? data.code.files.join(', ') : 'N/A'}</span></div>
            <div class="detail-item"><span class="detail-key">证据</span><span class="detail-val" style="max-width:250px;text-align:right">${data.code.evidence}</span></div>
        </div>
        <div class="detail-card">
            <div class="detail-card-header">⚙️ Config Agent 依赖检查</div>
            <div class="detail-item"><span class="detail-key">包名</span><span class="detail-val">${data.config.package}</span></div>
            <div class="detail-item"><span class="detail-key">版本</span><span class="detail-val">${data.config.version}</span></div>
            <div class="detail-item"><span class="detail-key">发现</span><span class="detail-val ${data.config.found ? 'found' : 'not-found'}">${data.config.found ? '✅ 存在于 SBOM' : '⬜ 不在 SBOM 中'}</span></div>
            <div class="detail-item"><span class="detail-key">版本受影响</span><span class="detail-val ${data.config.vulnerable ? 'critical' : 'not-found'}">${data.config.vulnerable ? '是' : '否'}</span></div>
        </div>
        <div class="detail-card">
            <div class="detail-card-header">🤖 LLM 推理过程</div>
            <div class="detail-item"><span class="detail-key">模型</span><span class="detail-val" style="color:var(--accent)">llama-3.1-70b-instruct</span></div>
            <div class="detail-item"><span class="detail-key">推理</span><span class="detail-val" style="font-family:Inter;max-width:250px;text-align:right">${data.vex.reasoning}</span></div>
        </div>
        <div class="verdict-box" style="border-color: var(--${statusBadgeClass})">
            <div class="verdict-status">${statusIcon}</div>
            <div>
                <div class="verdict-label" style="color: var(--${statusBadgeClass})">${cveId}: ${data.vex.status.toUpperCase()}</div>
                <div class="verdict-justification">${data.vex.justification}</div>
            </div>
            <div class="verdict-confidence high">${Math.round(data.vex.confidence * 100)}%</div>
        </div>
    `;
}

// CVE tab 切换
document.querySelectorAll('.cve-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.cve-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        renderCVEDetail(tab.dataset.cve);
    });
});

// ---- 日志动画 ----
function animateLog() {
    const logEl = document.getElementById('agent-log');
    if (!logEl) return;
    const lines = logEl.querySelectorAll('.log-line');
    lines.forEach((line, i) => {
        line.style.opacity = '0';
        line.style.transform = 'translateX(-10px)';
        setTimeout(() => {
            line.style.transition = 'all 0.3s ease';
            line.style.opacity = '1';
            line.style.transform = 'translateX(0)';
        }, i * 200);
    });
}

// ---- 柱状图动画 ----
function animateBars() {
    document.querySelectorAll('.bar-fill').forEach(bar => {
        const width = bar.style.width;
        bar.style.width = '0%';
        requestAnimationFrame(() => {
            setTimeout(() => { bar.style.width = width; }, 100);
        });
    });
}

// ---- 指标数字动画 ----
function animateMetrics() {
    const targets = {
        'total-cves': 10,
        'affected-count': 8,
        'not-affected-count': 2,
    };

    Object.entries(targets).forEach(([id, target]) => {
        const el = document.getElementById(id);
        if (!el) return;
        let current = 0;
        const step = Math.ceil(target / 20);
        const timer = setInterval(() => {
            current = Math.min(current + step, target);
            el.textContent = current;
            if (current >= target) clearInterval(timer);
        }, 50);
    });
}

// ---- 节点高亮顺序动画 ----
function animateFlow() {
    const nodes = ['node-supervisor', 'node-intel', 'node-code', 'node-config', 'node-vex'];
    nodes.forEach((id, i) => {
        const el = document.getElementById(id);
        if (!el) return;
        setTimeout(() => {
            el.style.transition = 'all 0.5s ease';
            el.style.transform = 'scale(1.08)';
            el.style.boxShadow = '0 0 30px var(--accent-glow)';
            setTimeout(() => {
                el.style.transform = 'scale(1)';
                el.style.boxShadow = '';
            }, 600);
        }, i * 400);
    });
}

// ---- Section 切换时触发动画 ----
const observer = new MutationObserver(() => {
    if (document.getElementById('overview').classList.contains('active')) {
        animateMetrics();
        drawRiskChart();
    }
    if (document.getElementById('agents').classList.contains('active')) {
        animateLog();
        animateFlow();
    }
    if (document.getElementById('baseline').classList.contains('active')) {
        animateBars();
    }
});
document.querySelectorAll('.section').forEach(s => {
    observer.observe(s, { attributes: true, attributeFilter: ['class'] });
});

// ---- 从 API 加载数据 (通过 api_server.py 提供) ----
async function loadFromAPI() {
    try {
        const resp = await fetch('/api/results');
        if (resp.ok) {
            const data = await resp.json();
            if (data.ours) {
                const results = data.ours.results;
                const total = Object.keys(results).length;
                const affected = Object.values(results).filter(r => r.status === 'affected').length;
                const notAffected = total - affected;
                document.getElementById('total-cves').textContent = total;
                document.getElementById('affected-count').textContent = affected;
                document.getElementById('not-affected-count').textContent = notAffected;
                document.getElementById('accuracy-value').textContent = Math.round(data.ours.accuracy * 100) + '%';
                console.log('✅ API 数据加载成功:', total, 'CVEs');
            }
        }
    } catch (e) {
        console.log('ℹ️ API 不可用，使用默认数据 (启动 api_server.py 可接入实时数据)');
    }
}

// ---- 初始化 ----
document.addEventListener('DOMContentLoaded', () => {
    drawRiskChart();
    renderCVEDetail('CVE-2021-44228');
    animateMetrics();
    loadFromAPI();
});
