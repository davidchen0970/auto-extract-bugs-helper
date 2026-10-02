// CWE handbook — category: 19 Data Processing Errors
export default [
	{
		cat: "19 Data Processing Errors",
		id: "CWE-443",
		name: "DEPRECATED: HTTP response splitting",
		lang: "-",
		status: "Deprecated",
		what: "本條目已被官方標記廢棄（DEPRECATED）：它原名「HTTP 回應切割（HTTP response splitting）」，但該弱點內容 已整併到 CWE-113（\"Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')\"）。 現在的建議是改用 CWE-113 來標記「未正確中和 HTTP 標頭中的 CRLF 序列」這類問題——即攻擊者把 注入回應產出， 讓單一回應被切割成兩個、把使用者導到注入的額外回應。保留此條僅保持 id 連續，實務請以 CWE-113 為準。",
		problem: "// 已廢棄 -> 請參照 CWE-113 (HTTP Request/Response Splitting / CRLF injection)",
		fixed: "// 已廢棄 -> 依 CWE-113 修法:過濾所有進到回應標頭與 Location 的 CR/LF 序列",
		patch: "@@\n  // This entry is deprecated; see CWE-113 for HTTP response splitting.",
		refs: ["CWE-443","CWE-113"],
		tags: ["deprecated","http-splitting","crlf"],
	},
];
