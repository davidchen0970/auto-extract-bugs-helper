const RE_PREFIX = 345;
const RE_SIZE = 124;
const RE_TYPE = 156;
const dec = new TextDecoder('utf-8', { fatal: false });

function parseOctal(u8, off, len) {
	if (u8[off] & 0x80) {
		let v = u8[off] & 0x7f;
		for (let i = 1; i < len; i++) v = v * 256 + u8[off + i];
		return v;
	}
	let v = 0,
		seen = false;
	for (let i = 0; i < len; i++) {
		const c = u8[off + i];
		if (c === 0 || c === 0x20) break;
		v = v * 8 + (c - 0x30);
		seen = true;
	}
	return seen ? v : 0;
}

function parsePax(str) {
	const out = {};
	let i = 0;
	const n = str.length;
	while (i < n) {
		const sp = str.indexOf(' ', i);
		if (sp < 0) break;
		const len = parseInt(str.slice(i, sp), 10);
		if (!len || i + len > n) break;
		const rec = str.substr(sp + 1, len - (sp - i + 1));
		const eq = rec.indexOf('=');
		if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
		i = sp + 1 + len;
	}
	return out;
}

function parseTar(buf) {
	const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
	const readStr = (o, l) => {
		let e = o;
		while (e < o + l && e < u8.length && u8[e] !== 0) e++;
		return dec.decode(u8.subarray(o, e));
	};

	const entries = [];
	let off = 0,
		longName = null,
		pax = null;

	while (off + 512 <= u8.length) {
		let zeros = true;
		for (let i = 0; i < 512; i++)
			if (u8[off + i] !== 0) {
				zeros = false;
				break;
			}
		if (zeros) break;

		const type = readStr(off + RE_TYPE, 1) || '\0';
		const size = parseOctal(u8, off + RE_SIZE, 12);
		const dataOff = off + 512;
		const pad = Math.ceil(size / 512) * 512;
		const dataEnd = Math.min(dataOff + size, u8.length);
		const data = u8.slice(dataOff, dataEnd);
		const hdrOff = off;
		off = dataOff + pad;

		if (type === 'L') {
			longName = dec.decode(data).split('\0')[0];
			pax = null;
			continue;
		}
		if (type === 'x' || type === 'g') {
			pax = parsePax(dec.decode(data));
			continue;
		}
		if (type === '5') {
			const prefix = readStr(hdrOff + RE_PREFIX, 155),
				nf = readStr(hdrOff, 100);
			let name = (prefix ? prefix + '/' : '') + nf;
			if (longName) {
				name = longName;
				longName = null;
			}
			if (pax && pax.path) name = pax.path;
			pax = null;
			continue;
		}
		if (!(type === '0' || type === '\0' || type === '7')) continue;

		const prefix = readStr(hdrOff + RE_PREFIX, 155),
			nf = readStr(hdrOff, 100);
		let name = (prefix ? prefix + '/' : '') + nf;
		if (longName) {
			name = longName;
			longName = null;
		}
		if (pax && pax.path) name = pax.path;
		pax = null;
		if (!name.replace(/\/+$/, '')) continue;
		entries.push({
			name: name.replace(/\/{2,}/g, '/'),
			type: 'file',
			size,
			data: new Uint8Array(data),
		});
	}
	return entries;
}

export { parseTar, parseOctal, parsePax };
