export function detectReport(name) {
    const n = String(name || '').toLowerCase();
    if (/\.(ima|bin|rom|mtd|uefi|fd|img)$/.test(n)) return 'artifact';
    if (/coverity/i.test(n) && n.endsWith('.html')) return 'coverity';
    if (/(_guidance|_details|blackduck|bd_output)/i.test(n) && n.endsWith('.csv')) return 'blackduck';
    if (n.endsWith('.html')) return 'html';
    if (n.endsWith('.csv')) return 'csv';
    return 'other';
}

export function looksLikeCoverity(text) {
    const head = String(text).slice(0, 20000);
    return /coverity|缺陷明細|Coverity 缺陷報表/i.test(head) || /id="det"/.test(head);
}

export function looksLikeBlackDuck(text) {
    if (!/CVE-20\d{2}/.test(String(text).slice(0, 50000))) return false;
    const head = String(text).slice(0, 2000);
    return /(漏洞編號|CVSS|修復狀態|severity)/i.test(head) || /,(CVE-\d)/.test(head);
}
