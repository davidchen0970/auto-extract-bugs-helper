// CWE handbook — category: 320 Key Management Errors
export default [
	{
		cat: "320 Key Management Errors",
		id: "CWE-322",
		name: "Key Exchange without Entropy of Peer",
		lang: "python",
		status: "Complete",
		what: "金鑰交換時未利用對端（peer）的熵。在 ECDH／DH／ECDHE 等金鑰交換 協定中，若其中一方把自己的私鑰、隨機亂數或 nonce 寫死成常數或全零值， 或以可預測的種子產生，握手產生的共享祕密就沒有真正的不確定性， 任何人若知道該固定值，即可推導出整個工作階段的會話金鑰並解密通訊。 建議做法是私鑰一律來自密碼學安全亂數，處理 ECDH 使用 secrets／os.urandom 產生每根連線獨立、不可預測的私鑰，不複用、不寫死。",
		problem: "# 不安全寫法：把 ECDH 私鑰寫死成常數，共享金鑰完全可被推導\nimport os\nfrom cryptography.hazmat.primitives.asymmetric import ec\n\n# <-- 私鑰寫死，等同沒有熵；任何人知道它就能推出共享祕密\nstatic_private = ec.derive_private_key(1, ec.SECP256R1())\n\ndef handshake(peer_pub):\n    shared = static_private.exchange(ec.ECDH(), peer_pub)  # 每條連線同一把金鑰\n    return shared",
		fixed: "# 安全寫法：用 os.urandom 產生真正隨機的私鑰，每條連線各自獨立、不可預測\nimport os\nfrom cryptography.hazmat.primitives.asymmetric import ec\n\ndef handshake(peer_pub):\n    # 私鑰由 OS 熵池隨機產生，不寫死、不複用，共享金鑰無法被預測\n    ephem = ec.generate_private_key(ec.SECP256R1())\n    shared = ephem.exchange(ec.ECDH(), peer_pub)[:32]\n    return shared, ephem.public_key()   # 記錄公鑰供雙方確認、簽名綁定",
		patch: "@@\n-  import os\n-  from cryptography.hazmat.primitives.asymmetric import ec\n-\n-  # <-- 私鑰寫死，等同沒有熵；任何人知道它就能推出共享祕密\n-  static_private = ec.derive_private_key(1, ec.SECP256R1())\n-\n-  def handshake(peer_pub):\n-      shared = static_private.exchange(ec.ECDH(), peer_pub)  # 每條連線同一把金鑰\n-      return shared\n+  import os\n+  from cryptography.hazmat.primitives.asymmetric import ec\n+\n+  def handshake(peer_pub):\n+      # 私鑰由 OS 熵池隨機產生，不寫死、不複用，共享金鑰無法被預測\n+      ephem = ec.generate_private_key(ec.SECP256R1())\n+      shared = ephem.exchange(ec.ECDH(), peer_pub)[:32]\n+      return shared, ephem.public_key()   # 記錄公鑰供雙方確認、簽名綁定",
		refs: ["OWASP-Crypto","CWE-322"],
		tags: ["key-exchange","ecdhe","entropy","nonce","predictable"],
	},
];
