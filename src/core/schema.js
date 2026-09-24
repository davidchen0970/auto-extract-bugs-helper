export const SEV = {
	CRITICAL: 'CRITICAL',
	HIGH: 'HIGH',
	MEDIUM: 'MEDIUM',
	LOW: 'LOW',
	INFO: 'INFO',
};
export const sevOrder = [SEV.CRITICAL, SEV.HIGH, SEV.MEDIUM, SEV.LOW, SEV.INFO];
export const sevLabel = {
	CRITICAL: 'Critical',
	HIGH: 'High',
	MEDIUM: 'Medium',
	LOW: 'Low',
	INFO: 'Info',
};

export function emptyTotals() {
	return { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
}

export function mapSev(s) {
	const u = String(s || '').trim().toUpperCase();
	if (u === 'CRITICAL') return SEV.CRITICAL;
	if (u === 'HIGH') return SEV.HIGH;
	if (u === 'MED' || u === 'MEDIUM') return SEV.MEDIUM;
	if (u === 'LOW') return SEV.LOW;
	return null;
}

export function sevFromBD(s) {
	const u = String(s || '').trim().toUpperCase();
	if (u.startsWith('CRIT')) return SEV.CRITICAL;
	if (u.startsWith('H')) return SEV.HIGH;
	if (u.startsWith('MED')) return SEV.MEDIUM;
	if (u === 'LOW') return SEV.LOW;
	if (u.startsWith('L')) return SEV.LOW;
	if (u) return SEV.INFO;
	return SEV.LOW;
}
