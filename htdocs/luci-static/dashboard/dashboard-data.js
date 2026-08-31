(function(root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.DashboardData = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
    function toArray(value) {
        return Array.isArray(value) ? value : [];
    }

    function toPositiveNumber(value) {
        const number = Number(value);
        return Number.isFinite(number) && number > 0 ? number : 0;
    }

    function toRateNumber(value) {
        const number = Number(value);
        return Number.isFinite(number) && number >= 0 ? number : null;
    }

    function isLikelyDomain(value) {
        const domain = String(value || '').trim().toLowerCase();
        if (!domain || domain.length > 253 || !domain.includes('.') || /^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
            return false;
        }

        const labels = domain.split('.');
        if (labels.length < 2) return false;

        for (const label of labels) {
            if (!label || label.length > 63 || !/^[a-z0-9-]+$/.test(label) || label.startsWith('-') || label.endsWith('-')) {
                return false;
            }
        }

        const tld = labels[labels.length - 1];
        if (!/^[a-z]/.test(tld)) return false;
        if (!tld.startsWith('xn--') && !/^[a-z-]+$/.test(tld)) return false;
        if (isBlockedDomainToken(labels, tld)) return false;

        return labels.some((label) => /[a-z]/.test(label));
    }

    function isBlockedDomainToken(labels, tld) {
        const blockedFileSuffixes = new Set([
            'cfg', 'conf', 'css', 'dat', 'eot', 'gz', 'ipk', 'js', 'json',
            'ko', 'list', 'lock', 'log', 'lua', 'map', 'pid', 'rules', 'sh', 'so',
            'tar', 'tmp', 'ttf', 'txt', 'woff', 'woff2', 'zip',
        ]);
        const syslogFacilities = new Set([
            'auth', 'authpriv', 'cron', 'daemon', 'kern', 'kernel', 'local0',
            'local1', 'local2', 'local3', 'local4', 'local5', 'local6',
            'local7', 'mail', 'news', 'syslog', 'user', 'uucp',
        ]);
        const syslogLevels = new Set([
            'alert', 'crit', 'debug', 'emerg', 'err', 'error', 'info',
            'notice', 'warn', 'warning',
        ]);

        return blockedFileSuffixes.has(tld) || (syslogLevels.has(tld) && syslogFacilities.has(labels[0]));
    }

    function filterDomainRows(rows) {
        return toArray(rows).filter((item) => item && isLikelyDomain(item.domain));
    }

    function pickActiveAppState(databus, oafData) {
        const databusApps = toArray(databus && databus.online_apps && databus.online_apps.list);
        const databusRecognition = (databus && databus.app_recognition) || {};
        let databusClassStats = toArray(databusRecognition.class_stats);

        // 如果分类统计数据为空，但活跃应用列表不为空，则基于应用分类自动聚合生成
        if (databusClassStats.length === 0 && databusApps.length > 0) {
            const statsMap = {};
            databusApps.forEach(app => {
                const rawClass = app.class_label || app.class || 'others';
                const weight = 1;
                statsMap[rawClass] = (statsMap[rawClass] || 0) + weight;
            });
            databusClassStats = Object.keys(statsMap).map(key => ({
                name: key,
                time: statsMap[key]
            }));
        }

        const databusAvailable = Boolean(databusRecognition.available) || databusApps.length > 0 || databusClassStats.length > 0;

        if (databusAvailable) {
            return {
                apps: databusApps,
                classStats: databusClassStats,
                available: databusAvailable,
                source: databusRecognition.source || (databusApps[0] && databusApps[0].source) || 'databus',
                engine: databusRecognition.engine || '',
                featureVersion: databusRecognition.feature_version || '',
            };
        }

        const oafApps = toArray(oafData && oafData.active_apps);
        let oafClassStats = toArray(oafData && oafData.class_stats);

        // 在 OAF 数据降级中同样支持自聚合
        if (oafClassStats.length === 0 && oafApps.length > 0) {
            const statsMap = {};
            oafApps.forEach(app => {
                const rawClass = app.class_label || app.class || 'others';
                const weight = 1;
                statsMap[rawClass] = (statsMap[rawClass] || 0) + weight;
            });
            oafClassStats = Object.keys(statsMap).map(key => ({
                name: key,
                time: statsMap[key]
            }));
        }

        return {
            apps: oafApps,
            classStats: oafClassStats,
            available: oafApps.length > 0 || oafClassStats.length > 0,
            source: (oafData && (oafData.active_source || oafData.source)) || 'oaf',
            engine: (oafData && oafData.engine) || '',
            featureVersion: (oafData && oafData.current_version) || '',
        };
    }

    /**
     * 推断设备类型（移动端 / 路由器 / 电脑 / 智能家居等）。
     * 修复点（对照 luci-app-quickstart 与 OAF 新版的设备识别思路）：
     * 1. 新增 MAC OUI 厂商前缀识别（Apple/华为/小米等 OUI → mobile）
     * 2. 修复 "fast" 误判路由器（fast 也可能是电视/设备名，如 "Fast-TV"）
     * 3. 修复 "smart" 误判手机（smart 前缀更多出现在智能电视/音箱）
     * 4. "pad/tab" 归为平板（mobile 内部分支），"tv/box/projector" 归为 tv
     * 5. 无名字设备通过 MAC OUI 判断，不再一律 laptop
     */
    const MOBILE_OUI = new Set([
        'f0:18:98', 'a4:83:e7', 'ac:bc:32', '28:16:ad', 'f8:5c:7d', 'd8:d7:7f',
        '5c:f9:38', 'b0:e5:ed', 'd4:3a:2c', 'f0:63:91', '8c:85:90', '34:c9:f0',
        '34:12:98', 'd8:5d:4c', '58:8a:5a', '70:7d:b9', 'b8:27:eb', '0c:7a:c5',
        'd4:85:64', 'a8:7c:01', '64:77:91', '90:cd:b6', 'c8:9a:8f', '48:8d:36',
    ]);
    const ROUTER_OUI = new Set([
        '00:14:6c', '00:1a:b9', '00:1a:c5', '00:24:a5', '00:26:86', 'd8:5d:e2',
        'c0:be:c9', '84:d9:31', 'a4:2b:b0', '50:64:2b', '18:31:bf', 'f4:83:cd',
    ]);

    function classifyDevice(device, gatewayIp) {
        if (!device || typeof device !== 'object') return 'laptop';
        const rawName = String(device.name || '').trim();
        const nameLower = rawName.toLowerCase();
        const macRaw = String(device.mac || '').replace(/[:-]/g, '').toLowerCase().slice(0, 6);
        const macOui = macRaw.replace(/(..)(?=.)/g, '$1:');
        let type = 'laptop';

        // 网关 IP 对比：100% 是上级路由器
        if (device.ip && gatewayIp && device.ip === gatewayIp && gatewayIp !== '-' && gatewayIp !== '') {
            return 'router';
        }

        // 路由器品牌关键词（不含裸 "fast"：Fast/FastCombo 等是电视常见名）
        const routerKeywords = ['router', 'openwrt', 'tplink', 'tp-link', 'dlink', 'd-link', 'netgear',
            'linksys', 'mercury', 'tenda', 'totolink', 'miwifi', 'ikuai', 'phicomm', 'gl-inet', 'gl.inet',
            'repeater', 'extender', 'ap-', '-ap', 'xiaomi router', 'huawei router'];
        // 手机品牌关键词
        const mobileKeywords = ['iphone', 'ipad', 'android', 'phone', 'mobile', 'huawei', 'honor',
            'xiaomi', 'redmi', 'oppo', 'vivo', 'oneplus', 'samsung', 'meizu', 'realme', 'iqoo',
            'galaxy', 'yi-jia', 'yijia', 'pixel', 'poco', 'nokia', 'sony', 'zte', 'lenovo phone'];
        // 平板关键词（仍属 mobile 类图标）
        const padKeywords = ['pad', 'tab', 'tablet'];
        // 电视/盒子/投影（独立类型 tv）
        const tvKeywords = ['tv', 'television', 'box', 'projector', 'mi box', 'xiaomi tv', 'hisense',
            'skyworth', 'tcl', 'konka', 'letv', 'sony bravia', 'amazon fire', 'roku', 'apple tv'];

        if (nameLower && routerKeywords.some(k => nameLower.includes(k))) {
            type = 'router';
        } else if (nameLower && tvKeywords.some(k => nameLower.includes(k))) {
            type = 'tv';
        } else if (nameLower && mobileKeywords.some(k => nameLower.includes(k))) {
            type = 'mobile';
        } else if (nameLower && padKeywords.some(k => nameLower.includes(k))) {
            type = 'mobile';
        } else if (macOui && MOBILE_OUI.has(macOui)) {
            type = 'mobile';
        } else if (macOui && ROUTER_OUI.has(macOui)) {
            type = 'router';
        } else if (!nameLower && macOui && /^(f0|a4|ac|28|d8|b0|34|8c|70|58)/.test(macOui)) {
            type = 'mobile';
        }

        return type;
    }

    function deriveTrafficSnapshot(sample, previousState, nowMs) {
        const nextState = {
            interface: sample && sample.interface ? String(sample.interface) : '',
            tx_bytes: toPositiveNumber(sample && sample.tx_bytes),
            rx_bytes: toPositiveNumber(sample && sample.rx_bytes),
            at: toPositiveNumber(nowMs),
        };

        const backendTxRate = toRateNumber(sample && sample.tx_rate);
        const backendRxRate = toRateNumber(sample && sample.rx_rate);
        if (backendTxRate !== null || backendRxRate !== null) {
            return {
                txRate: backendTxRate !== null ? backendTxRate : 0,
                rxRate: backendRxRate !== null ? backendRxRate : 0,
                nextState: nextState,
            };
        }

        if (!previousState || !previousState.interface || !nextState.interface || previousState.interface !== nextState.interface) {
            return {
                txRate: 0,
                rxRate: 0,
                nextState: nextState,
            };
        }

        const previousAt = toPositiveNumber(previousState.at);
        if (!previousAt || nextState.at <= previousAt) {
            return {
                txRate: 0,
                rxRate: 0,
                nextState: nextState,
            };
        }

        const txDelta = nextState.tx_bytes - toPositiveNumber(previousState.tx_bytes);
        const rxDelta = nextState.rx_bytes - toPositiveNumber(previousState.rx_bytes);
        if (txDelta < 0 || rxDelta < 0) {
            return {
                txRate: 0,
                rxRate: 0,
                nextState: nextState,
            };
        }

        const diffSeconds = (nextState.at - previousAt) / 1000;
        if (!(diffSeconds > 0)) {
            return {
                txRate: 0,
                rxRate: 0,
                nextState: nextState,
            };
        }

        return {
            txRate: txDelta / diffSeconds,
            rxRate: rxDelta / diffSeconds,
            nextState: nextState,
        };
    }

    return {
        pickActiveAppState: pickActiveAppState,
        deriveTrafficSnapshot: deriveTrafficSnapshot,
        isLikelyDomain: isLikelyDomain,
        filterDomainRows: filterDomainRows,
        classifyDevice: classifyDevice,
    };
});
