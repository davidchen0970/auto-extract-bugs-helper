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

export function isTarBytes(u8) {
    if (!u8 || u8.length < 512) return false;
    // ustar magic lives in the first header at offset 257..262 ("ustar\0" or "ustar  \0")
    return (
        u8[257] === 0x75 && u8[258] === 0x73 &&
        u8[259] === 0x74 && u8[260] === 0x61 &&
        u8[261] === 0x72
    );
}

export function looksLikeBlackDuck(text) {
    if (!/CVE-20\d{2}/.test(String(text).slice(0, 50000))) return false;
    const head = String(text).slice(0, 2000);
    return /(漏洞編號|修復狀態|severity)/i.test(head) || /,(CVE-\d)/.test(head);
}
