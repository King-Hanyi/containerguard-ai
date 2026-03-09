/* ============================================================
   ContainerGuard AI — 产品级扫描平台交互逻辑
   ============================================================ */

// ---- CVE 扫描数据 (模拟真实扫描结果) ----
const SCAN_DATA = {
    "CVE-2021-44228": {
        name: "Log4Shell", severity: "critical",
        description: "Apache Log4j2 JNDI injection vulnerability allows RCE via JndiLookup. CVSS 10.0.",
        intel: { severity: "critical", source: "NVD + GHSA + BRON", cvss: 10.0, attack_chain: "CWE-502 → CAPEC-586 → T1190" },
        code: { found: true, query: "JndiLookup", files: ["JndiLookup.java", "JndiManager.java"], evidence: "GitHub API 搜索命中 3 个结果" },
        config: { found: true, package: "log4j-core", version: "2.14.0", constraint: "< 2.17.0", vulnerable: true },
        vex: { status: "affected", confidence: 0.95, justification: "漏洞包存在于 SBOM 中且代码中发现漏洞函数调用", reasoning: "Checklist 推理: 1)组件存在✓ 2)版本2.14.0<2.17.0✓ 3)JndiLookup在代码路径上✓" },
        checklist: { component: true, version: true, code: true },
        opa: { action: "block", rule: "critical_affected" }
    },
    "CVE-2022-22965": {
        name: "Spring4Shell", severity: "critical",
        description: "Spring Framework RCE via data binding on JDK 9+ with ClassPathResource. CVSS 9.8.",
        intel: { severity: "critical", source: "NVD + 内置情报库", cvss: 9.8, attack_chain: "CWE-94 → CAPEC-242 → T1059" },
        code: { found: true, query: "ClassPathResource", files: ["AbstractBeanFactory.java"], evidence: "模式匹配: spring-beans, spring-webmvc" },
        config: { found: true, package: "spring-beans", version: "5.3.15", constraint: "< 5.3.18", vulnerable: true },
        vex: { status: "affected", confidence: 0.92, justification: "漏洞包存在且代码调用路径可达", reasoning: "Checklist: 1)spring-beans存在✓ 2)5.3.15<5.3.18✓ 3)ClassPathResource可达✓" },
        checklist: { component: true, version: true, code: true },
        opa: { action: "block", rule: "critical_affected" }
    },
    "CVE-2017-5638": {
        name: "Struts2 RCE", severity: "critical",
        description: "Apache Struts2 multipart parser RCE via Content-Type header. CVSS 10.0.",
        intel: { severity: "critical", source: "NVD + BRON", cvss: 10.0, attack_chain: "CWE-20 → CAPEC-135 → T1190" },
        code: { found: true, query: "multipart/form-data", files: ["StrutsMultiPartParser.java"], evidence: "模式匹配: struts2-core" },
        config: { found: true, package: "struts2-core", version: "2.3.31", constraint: "< 2.5.10.1", vulnerable: true },
        vex: { status: "affected", confidence: 0.90, justification: "漏洞包版本在受影响范围内", reasoning: "Checklist: 1)struts2-core存在✓ 2)2.3.31<2.5.10.1✓ 3)multipart parser可达✓" },
        checklist: { component: true, version: true, code: true },
        opa: { action: "block", rule: "critical_affected" }
    },
    "CVE-2022-42889": {
        name: "Text4Shell", severity: "critical",
        description: "Apache Commons Text StringSubstitutor RCE via interpolation. CVSS 9.8.",
        intel: { severity: "critical", source: "NVD + 内置情报库", cvss: 9.8, attack_chain: "CWE-94 → CAPEC-242 → T1059" },
        code: { found: true, query: "StringSubstitutor", files: ["StringSubstitutor.java"], evidence: "模式匹配: commons-text" },
        config: { found: true, package: "commons-text", version: "1.9", constraint: "< 1.10.0", vulnerable: true },
        vex: { status: "affected", confidence: 0.90, justification: "commons-text 1.9 含有 RCE 漏洞", reasoning: "Checklist: 1)commons-text存在✓ 2)1.9<1.10.0✓ 3)StringSubstitutor可调用✓" },
        checklist: { component: true, version: true, code: true },
        opa: { action: "block", rule: "critical_affected" }
    },
    "CVE-2014-0160": {
        name: "Heartbleed", severity: "high",
        description: "OpenSSL heartbeat extension vulnerability in dtls1_process_heartbeat. CVSS 7.5.",
        intel: { severity: "high", source: "NVD + 内置情报库", cvss: 7.5, attack_chain: "CWE-119 → CAPEC-540 → T1005" },
        code: { found: true, query: "dtls1_process_heartbeat", files: ["ssl/d1_both.c"], evidence: "模式匹配: SSL_read, dtls1_process_heartbeat" },
        config: { found: true, package: "openssl", version: "1.0.1f", constraint: ">= 1.0.1, < 1.0.1g", vulnerable: true },
        vex: { status: "affected", confidence: 0.90, justification: "OpenSSL 1.0.1f 在受影响版本范围内", reasoning: "Checklist: 1)openssl存在✓ 2)1.0.1f∈[1.0.1,1.0.1g)✓ 3)heartbeat代码可达✓" },
        checklist: { component: true, version: true, code: true },
        opa: { action: "warn", rule: "high_affected" }
    },
    "CVE-2021-3449": {
        name: "OpenSSL NULL ptr", severity: "high",
        description: "OpenSSL NULL pointer deref via signature_algorithms extension. CVSS 5.9.",
        intel: { severity: "high", source: "NVD + 内置情报库", cvss: 5.9, attack_chain: "CWE-476 → CAPEC-100" },
        code: { found: true, query: "signature_algorithms", files: ["ssl/statem/extensions_srvr.c"], evidence: "模式匹配: tls_parse_ctos_sig_algs" },
        config: { found: true, package: "openssl", version: "1.1.1j", constraint: ">= 1.1.1, < 1.1.1k", vulnerable: true },
        vex: { status: "affected", confidence: 0.88, justification: "OpenSSL 1.1.1j 在受影响范围内", reasoning: "Checklist: 1)openssl存在✓ 2)1.1.1j∈[1.1.1,1.1.1k)✓ 3)sig_algs可达✓" },
        checklist: { component: true, version: true, code: true },
        opa: { action: "warn", rule: "high_affected" }
    },
    "CVE-2023-44487": {
        name: "HTTP/2 Rapid Reset", severity: "high",
        description: "HTTP/2 protocol Rapid Reset attack causing DoS. CVSS 7.5.",
        intel: { severity: "high", source: "NVD + BRON", cvss: 7.5, attack_chain: "CWE-400 → CAPEC-469 → T1498" },
        code: { found: true, query: "RSTStreamFrame", files: ["net/http2/transport.go"], evidence: "模式匹配: golang.org/x/net" },
        config: { found: true, package: "golang.org/x/net", version: "0.15.0", constraint: "< 0.17.0", vulnerable: true },
        vex: { status: "affected", confidence: 0.88, justification: "Go HTTP/2 库版本受影响", reasoning: "Checklist: 1)golang.org/x/net存在✓ 2)0.15.0<0.17.0✓ 3)RST处理可达✓" },
        checklist: { component: true, version: true, code: true },
        opa: { action: "warn", rule: "high_affected" }
    },
    "CVE-2021-44906": {
        name: "minimist Pollution", severity: "medium",
        description: "minimist prototype pollution via constructor. CVSS 9.8.",
        intel: { severity: "medium", source: "NVD + 内置情报库", cvss: 9.8, attack_chain: "CWE-1321 → CAPEC-180" },
        code: { found: true, query: "minimist", files: ["node_modules/minimist/index.js"], evidence: "模式匹配: minimist, prototype" },
        config: { found: true, package: "minimist", version: "1.2.5", constraint: "< 1.2.6", vulnerable: true },
        vex: { status: "affected", confidence: 0.85, justification: "minimist 1.2.5 含原型污染漏洞", reasoning: "Checklist: 1)minimist存在✓ 2)1.2.5<1.2.6✓ 3)parse()可调用✓" },
        checklist: { component: true, version: true, code: true },
        opa: { action: "pass", rule: "default_pass" }
    },
    "CVE-2023-36632": {
        name: "Python parseaddr", severity: "medium",
        description: "Python email.utils.parseaddr DoS via recursive parsing. CVSS 7.5.",
        intel: { severity: "medium", source: "NVD + 内置情报库", cvss: 7.5, attack_chain: "CWE-674 → CAPEC-197" },
        code: { found: false, query: "email.utils.parseaddr", files: [], evidence: "GitHub API 搜索: parseaddr 调用未发现" },
        config: { found: false, package: "python", version: "N/A", constraint: "< 3.12", vulnerable: false },
        vex: { status: "not_affected", confidence: 0.85, justification: "vulnerable_code_not_in_execute_path: 容器中未调用 parseaddr", reasoning: "Checklist: 1)python存在✓ 2)版本受影响✓ 3)但parseaddr不在代码路径✗ → not_affected" },
        checklist: { component: true, version: true, code: false },
        opa: { action: "pass", rule: "not_affected_pass" }
    },
    "CVE-2023-32681": {
        name: "Requests SSRF", severity: "medium",
        description: "Python Requests library SSRF via redirects. CVSS 6.1.",
        intel: { severity: "medium", source: "NVD + 内置情报库", cvss: 6.1, attack_chain: "CWE-918 → CAPEC-664" },
        code: { found: false, query: "requests.get", files: [], evidence: "GitHub API 搜索: 容器未使用 requests 库" },
        config: { found: false, package: "requests", version: "N/A", constraint: "< 2.31.0", vulnerable: false },
        vex: { status: "not_affected", confidence: 0.82, justification: "component_not_present: SBOM 中不包含 requests", reasoning: "Checklist: 1)requests不在SBOM✗ → not_affected (component_not_present)" },
        checklist: { component: false, version: false, code: false },
        opa: { action: "pass", rule: "not_affected_pass" }
    }
};

// ---- 导航切换 ----
function switchSection(sectionId) {
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelector(`[data-section="${sectionId}"]`).classList.add('active');
    document.getElementById(sectionId).classList.add('active');
}

document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        switchSection(link.dataset.section);
    });
});

// ---- 扫描流程模拟 ----
const SCAN_STEPS = [
    { text: "📦 解析输入: 识别 Docker 镜像/GitHub 仓库...", pct: 5, delay: 300 },
    { text: "📋 提取 SBOM: 分析容器依赖清单...", pct: 12, delay: 500 },
    { text: "🔍 Intel Agent: 查询 NVD / GHSA / BRON 情报库...", pct: 25, delay: 800 },
    { text: "💻 Code Agent: GitHub Code Search API 搜索漏洞函数...", pct: 40, delay: 700 },
    { text: "⚙️ Config Agent: SBOM 包匹配 + 版本范围比较 (packaging.version)...", pct: 55, delay: 600 },
    { text: "📡 并行收集完成: Intel ✓ Code ✓ Config ✓", pct: 65, delay: 400 },
    { text: "🤖 VEX Agent: LLM 推理 — Checklist 分步判定 (llama-3.1-70b)...", pct: 75, delay: 1200 },
    { text: "   → CVE-2021-44228: affected (95%), CVE-2023-36632: not_affected (85%)", pct: 82, delay: 400 },
    { text: "🛡️ OPA 策略引擎: 评估 10 个 VEX 判定...", pct: 90, delay: 500 },
    { text: "   → 结果: 5 blocked, 3 warn, 2 pass — 部署决策: BLOCKED", pct: 95, delay: 400 },
    { text: "📄 生成报告: 漏洞分析报告已就绪", pct: 100, delay: 300 },
];

async function startScan() {
    const btn = document.getElementById('scan-btn');
    const btnText = document.getElementById('scan-btn-text');
    const progress = document.getElementById('scan-progress');
    const preview = document.getElementById('scan-result-preview');
    const log = document.getElementById('scan-log');
    const fill = document.getElementById('progress-fill');
    const pct = document.getElementById('progress-percent');

    btn.classList.add('scanning');
    btnText.textContent = '⏳ 扫描中...';
    progress.classList.remove('hidden');
    preview.classList.add('hidden');
    log.innerHTML = '';

    for (const step of SCAN_STEPS) {
        await new Promise(r => setTimeout(r, step.delay));
        fill.style.width = step.pct + '%';
        pct.textContent = step.pct + '%';
        const el = document.createElement('div');
        el.className = 'log-step' + (step.pct === 100 ? ' done' : ' active');
        el.textContent = step.text;
        log.appendChild(el);
        log.scrollTop = log.scrollHeight;
    }

    await new Promise(r => setTimeout(r, 500));
    preview.classList.remove('hidden');
    btn.classList.remove('scanning');
    btnText.textContent = '🚀 重新扫描';

    // 渲染报告表格
    renderCVETable();
}

// ---- 报告表格 ----
function renderCVETable() {
    const tbody = document.getElementById('cve-table-body');
    tbody.innerHTML = '';

    Object.entries(SCAN_DATA).forEach(([cveId, d]) => {
        const tr = document.createElement('tr');
        tr.onclick = () => showDetail(cveId);
        tr.innerHTML = `
            <td><span class="cve-id">${cveId}</span></td>
            <td><span class="severity-badge ${d.severity}">${d.severity}</span></td>
            <td><span class="status-badge ${d.vex.status}">${d.vex.status === 'affected' ? '🔴 Affected' : '🟢 Not Affected'}</span></td>
            <td><span style="font-family:'JetBrains Mono';font-weight:600">${Math.round(d.vex.confidence * 100)}%</span></td>
            <td><span class="action-badge ${d.opa.action}">${d.opa.action.toUpperCase()}</span></td>
            <td>
                <div class="checklist-dots">
                    <span class="check-dot ${d.checklist.component ? 'yes' : 'no'}" title="组件存在">${d.checklist.component ? '✓' : '✗'}</span>
                    <span class="check-dot ${d.checklist.version ? 'yes' : 'no'}" title="版本受影响">${d.checklist.version ? '✓' : '✗'}</span>
                    <span class="check-dot ${d.checklist.code ? 'yes' : 'no'}" title="代码可达">${d.checklist.code ? '✓' : '✗'}</span>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// ---- 详情面板 ----
function showDetail(cveId) {
    const d = SCAN_DATA[cveId];
    if (!d) return;

    const panel = document.getElementById('detail-panel');
    const content = document.getElementById('detail-content');

    content.innerHTML = `
        <h2 style="font-size:1.2rem;margin-bottom:.2rem">${cveId}</h2>
        <p style="color:var(--text-muted);font-size:.85rem;margin-bottom:1.5rem">${d.name} — ${d.description}</p>

        <div class="detail-section">
            <div class="detail-section-title">🔍 Intel Agent 情报</div>
            <div class="detail-row"><span class="detail-key">严重程度</span><span class="detail-val"><span class="severity-badge ${d.severity}">${d.severity}</span></span></div>
            <div class="detail-row"><span class="detail-key">CVSS</span><span class="detail-val">${d.intel.cvss}</span></div>
            <div class="detail-row"><span class="detail-key">数据来源</span><span class="detail-val">${d.intel.source}</span></div>
            <div class="detail-row"><span class="detail-key">攻击链 (BRON)</span><span class="detail-val" style="color:var(--warning)">${d.intel.attack_chain}</span></div>
        </div>

        <div class="detail-section">
            <div class="detail-section-title">💻 Code Agent 代码搜索</div>
            <div class="detail-row"><span class="detail-key">搜索关键词</span><span class="detail-val">${d.code.query}</span></div>
            <div class="detail-row"><span class="detail-key">搜索结果</span><span class="detail-val" style="color:${d.code.found ? 'var(--success)' : 'var(--text-dim)'}">${d.code.found ? '✅ 发现匹配' : '⬜ 未发现'}</span></div>
            <div class="detail-row"><span class="detail-key">匹配文件</span><span class="detail-val">${d.code.files.length > 0 ? d.code.files.join(', ') : 'N/A'}</span></div>
        </div>

        <div class="detail-section">
            <div class="detail-section-title">⚙️ Config Agent 依赖检查</div>
            <div class="detail-row"><span class="detail-key">包名</span><span class="detail-val" style="font-family:'JetBrains Mono'">${d.config.package}</span></div>
            <div class="detail-row"><span class="detail-key">已安装版本</span><span class="detail-val">${d.config.version}</span></div>
            <div class="detail-row"><span class="detail-key">受影响范围</span><span class="detail-val" style="color:var(--warning)">${d.config.constraint}</span></div>
            <div class="detail-row"><span class="detail-key">版本受影响</span><span class="detail-val" style="color:${d.config.vulnerable ? 'var(--danger)' : 'var(--success)'}">${d.config.vulnerable ? '✅ 是' : '❌ 否'}</span></div>
        </div>

        <div class="detail-section">
            <div class="detail-section-title">📋 Checklist 推理</div>
            <div class="detail-row"><span class="detail-key">1. 组件存在</span><span class="detail-val" style="color:${d.checklist.component ? 'var(--success)' : 'var(--danger)'}">${d.checklist.component ? '✓ 是' : '✗ 否'}</span></div>
            <div class="detail-row"><span class="detail-key">2. 版本受影响</span><span class="detail-val" style="color:${d.checklist.version ? 'var(--success)' : 'var(--danger)'}">${d.checklist.version ? '✓ 是' : '✗ 否'}</span></div>
            <div class="detail-row"><span class="detail-key">3. 代码可达</span><span class="detail-val" style="color:${d.checklist.code ? 'var(--success)' : 'var(--danger)'}">${d.checklist.code ? '✓ 是' : '✗ 否'}</span></div>
        </div>

        <div class="detail-section">
            <div class="detail-section-title">🤖 LLM 推理 (llama-3.1-70b)</div>
            <div class="detail-row"><span class="detail-key">推理过程</span><span class="detail-val" style="max-width:280px;text-align:right">${d.vex.reasoning}</span></div>
        </div>

        <div class="detail-verdict ${d.vex.status}">
            ${d.vex.status === 'affected' ? '🔴' : '🟢'} ${d.vex.status.toUpperCase()} — ${Math.round(d.vex.confidence * 100)}%
        </div>

        <div style="text-align:center;margin-top:.5rem;font-size:.78rem;color:var(--text-muted)">
            OPA 决策: <span class="action-badge ${d.opa.action}">${d.opa.action.toUpperCase()}</span> (规则: ${d.opa.rule})
        </div>
    `;

    panel.classList.remove('hidden');
}

function closeDetail() {
    document.getElementById('detail-panel').classList.add('hidden');
}

// ---- 导出 PDF (模拟) ----
function downloadReport() {
    alert('📄 PDF 导出功能正在开发中。\n当前可通过浏览器 Print → Save as PDF 导出。');
}

// ---- Agent 流程动画 ----
function animateFlow() {
    const nodes = ['node-supervisor', 'node-intel', 'node-code', 'node-config', 'node-vex', 'node-opa'];
    nodes.forEach((id, i) => {
        const el = document.getElementById(id);
        if (!el) return;
        setTimeout(() => {
            el.style.transition = 'all 0.5s ease';
            el.style.transform = 'scale(1.06)';
            el.style.boxShadow = '0 0 24px var(--accent-glow)';
            setTimeout(() => {
                el.style.transform = 'scale(1)';
                el.style.boxShadow = '';
            }, 500);
        }, i * 350);
    });
}

// ---- Section 切换时触发动画 ----
const observer = new MutationObserver(() => {
    if (document.getElementById('agents')?.classList.contains('active')) animateFlow();
});
document.querySelectorAll('.section').forEach(s => {
    observer.observe(s, { attributes: true, attributeFilter: ['class'] });
});

// ---- 初始化 ----
document.addEventListener('DOMContentLoaded', () => {
    renderCVETable();
});
