// CWE chunk — 類別:程式碼與資料管理品質缺陷（Code, Data & Resource Management Quality Defects）
// 補齊官方 CWE v4.20 中手冊原本缺漏的 Base/Variant 品質類條目
export default [
	{
		id: 'CWE-1057',
		name: 'Data Access Operations Outside of Expected Data Manager Component',
		lang: 'java',
		status: 'Complete',
		what: `資料存取動作繞過預期的資料管理元件（Data Access Operations Outside of Expected Data Manager Component）。
		設計上要求所有資料存取都必須透過單一、集中的資料管理元件（如 DAO、Repository、資料存取層）進行，但程式某些程式碼
		卻直接對後端資料來源下指令，繞過了這個統一介面。成因是「圖方便」直接寫 JDBC／raw SQL、或另一段程式重造存取邏輯，
		結果同一個實體的多種讀寫路徑散落各處。後果是稽核與安全控制（權限、加密、稽核日誌）在這些繞過點完全失效，也難以統一
		修改。修法是讓所有資料作業都只走同一個管理元件，繞過的直接查詢一律改派到該層。`,
		problem: `// 不安全寫法：業務程式直接對資料來源下指令，繞過 DAO 集中管理
public void markInactive(int uid) throws SQLException {
    Connection c = DriverManager.getConnection(CONN, U, P);
    c.prepareStatement("UPDATE users SET active=0 WHERE id=?").setInt(1, uid).executeUpdate();
}`,
		fixed: `// 安全寫法：所有寫入都委派給單一資料管理元件（Repository / DAO）
repository.updateUserActiveFlag(uid, false);   // 稽核、權限在一處集中處理`,
		patch: `@@
-    Connection c = DriverManager.getConnection(CONN, U, P);
-    c.prepareStatement("UPDATE users SET active=0 WHERE id=?").setInt(1, uid).executeUpdate();
+    repository.updateUserActiveFlag(uid, false);`,
		refs: ['CWE-1057', 'OWASP'],
		tags: ['data-access', 'layer-bypass', 'architecture', 'dao'],
	},
	{
		id: 'CWE-1058',
		name: 'Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element',
		lang: 'java',
		status: 'Complete',
		what: `多執行緒環境中被呼叫的控制單元持有非 final 的 static／成員資料（Invokable Control Element in Multi-Thread Context
		with non-Final Static Storable or Member Element）。程式裡某個函式或方法運作於多執行緒環境，卻擁有一份共享、可變、且非
		final 的靜態欄位或成員資料，執行緒之間互相搶著讀寫。成因是為了「快取」把計數器、旗標或暫存物件塞進 static 欄位又沒加鎖。
		後果是資料競逐（data race）、單一執行緒的狀態波及其他執行緒、偶發的錯誤結果與難以重現的當機。修法是將該欄位改為
		final、用 ThreadLocal 或鎖保護共用狀態，或根本改用不可變物件。`,
		problem: `// 不安全寫法：static 計數器在無鎖下被多執行緒競逐
static long counter;                 // 非 final、可變、共享
public void hit() { counter++; }     // read-modify-write 不具原子性`,
		fixed: `// 安全寫法：用 Atomic 型別取代可變 static 欄位，消除競逐
static final AtomicLong counter = new AtomicLong();
public void hit() { counter.incrementAndGet(); }`,
		patch: `@@
- static long counter;
+ static final AtomicLong counter = new AtomicLong();
  public void hit() {
-     counter++;
+     counter.incrementAndGet();
  }`,
		refs: ['CWE-1058', 'OWASP'],
		tags: ['concurrency', 'race-condition', 'static-field', 'thread-safety'],
	},
	{
		id: 'CWE-1060',
		name: 'Excessive Number of Inefficient Server-Side Data Accesses',
		lang: 'java',
		status: 'Complete',
		what: `伺服器端過多而低效的資料存取（Excessive Number of Inefficient Server-Side Data Accesses）。伺服器端在同一次
		請求的處理過程中，發出過多筆資料查詢，卻沒有善用資料庫既有的高效能力，例如 stored procedure、批量操作或索引。成因常是把
		N＋1 查詢寫進迴圈——每一筆主資料都再查一次關聯——或在應用層面逐筆回填。後果是資料庫連線與查詢量暴增，回應時間與伺服器
		負載被拖垮，容易成為效能式阻斷服務（DoS）的放大器。修法是將逐筆查詢改為批量化 JOIN／一次取得，把常用邏輯收斂到
		stored procedure 或視圖中執行。`,
		problem: `// 不安全寫法：在迴圈內逐筆執行 N+1 查詢
for (Order o : orders) {            // orders 本身已一次取回
    o.items = dao.findItemsByOrder(o.id);   // 每筆又多查一次
}`,
		fixed: `// 安全寫法：一次取得全部關聯資料再於記憶體組裝
Map<Long,List<Item>> byOrder = dao.findItemsByOrderIn(ids);
for (Order o : orders) o.items = byOrder.getOrDefault(o.id, emptyList());`,
		patch: `@@
  for (Order o : orders) {
-     o.items = dao.findItemsByOrder(o.id);
+     o.items = byOrder.getOrDefault(o.id, emptyList());
  }`,
		refs: ['CWE-1060', 'OWASP'],
		tags: ['performance', 'n-plus-one', 'database', 'denial-of-service'],
	},
	{
		id: 'CWE-1062',
		name: 'Parent Class with References to Child Class',
		lang: 'java',
		status: 'Complete',
		what: `父類別引用子類別（Parent Class with References to Child Class）。繼承體系中，父類別（超類別）的程式碼卻對某個
		子類別、它的方法或成員做了引用。這條關係反轉則造成強耦合：父類別已無法獨立存在，新增任何子類別都會回過頭改造父類別，
		繼承就失去抽象與復用意義。成因是急著共用而把「特定子型別才能提供的行為」寫進父類別。後果是修改父類別會波及其他所有
		子類別，單元測試、DI 與替身（mock）都難以替換該父類別。修法是將共同行為上移到父類別，讓親子關係由父指向抽象介面，
		子類別實作細節不再回頭影響父類別。`,
		problem: `// 不安全寫法：父類別直接 new 出並引用特定子類別
class Animal {
    public Dog pet() { return new Dog(); }   // 父型別硬引用子型別 Dog
}`,
		fixed: `// 安全寫法：共同能力抽成抽象，子類別自訂實作
class Animal { public Animal pet() { return new Self(); } }  // 不再 new 具體子類別`,
		patch: `@@
- class Animal { public Dog pet() { return new Dog(); } }
+ class Animal { public Animal pet() { return new Self(); } }`,
		refs: ['CWE-1062', 'OWASP'],
		tags: ['inheritance', 'tight-coupling', 'design', 'class-hierarchy'],
	},
	{
		id: 'CWE-1063',
		name: 'Creation of Class Instance within a Static Code Block',
		lang: 'java',
		status: 'Complete',
		what: `在靜態程式區塊（static initializer）內建立類別實例（Creation of Class Instance within a Static Code Block）。
		static 初始區塊在類別載入時執行，是 JVM 或執行環境「最前期的階段」，此時堆積、執行緒與其他服務可能尚未就緒。若在此
		區塊內建立類別實例、連線或檔案等資源，其初始化失敗會轉成 ExceptionInInitializerError，直接讓整個類別不可用，或觸發
		惡性依賴——類別間靜態初始化彼此互相建立。後果是啟動期報錯、類別載入失敗、出乎意料的偶發錯誤。修法是不要在 static
		初始區塊建立具狀態實例，改以 lazy singleton 或明確的初始化階段在執行時期完成。`,
		problem: `// 不安全寫法：類別載入時就在 static 區塊建立資源實例
static {
    db = new Database(CONN);      // 載入即連線，失敗拋 ExceptionInInitializerError
}`,
		fixed: `// 安全寫法：延遲到第一次真正使用時才初始化
static Database db;
static Database db() {
    if (db == null) db = new Database(CONN);
    return db;
}`,
		patch: `@@
- static { db = new Database(CONN); }
+ static Database db;
+ static Database db() {
+     if (db == null) db = new Database(CONN);
+     return db;
+ }`,
		refs: ['CWE-1063', 'OWASP'],
		tags: ['static-initializer', 'classloading', 'lifecycle', 'initialization'],
	},
	{
		id: 'CWE-1064',
		name: 'Invokable Control Element with Signature Containing an Excessive Number of Parameters',
		lang: 'go',
		status: 'Complete',
		what: `可呼叫控制單元的簽名包含過多參數（Invokable Control Element with Signature Containing an Excessive Number
		of Parameters）。函式、子常式或方法簽名列了過多、且不必要的參數，某些只為了一路轉交底層或滿足特定呼叫方。成因是沒
		有把一組常同時出現的參數收成一個結構，或持續把新需求用「再加一個參數」方式塞進去。後果是呼叫處難以閱讀與組合
		（參數順序錯誤）、測試必須假造大量輸入、出錯的耦合面變大。修法是將一群邏輯相關參數打包成單一結構體參數，或拆成
		語意清晰的方法職責。`,
		problem: `// 不安全寫法：一字排開一堆容易搞錯順序的參數
func Send(userName, email, city, country string, age int,
          campaignsEnabled, isPremium, optedIn bool) error`,
		fixed: `// 安全寫法：把相關欄位收成單一結構體
type UserState struct { Name, Email, City, Country string; Age int }
func Send(u UserState, Prefs struct{ Campaigns, Premium, OptIn bool }) error`,
		patch: `@@
- func Send(userName, email, city, country string, age int,
-           campaignsEnabled, isPremium, optedIn bool) error
+ type UserState struct { Name, Email, City, Country string; Age int }
+ func Send(u UserState, Prefs struct{ Campaigns, Premium, OptIn bool }) error`,
		refs: ['CWE-1064', 'OWASP'],
		tags: ['function-signature', 'design', 'param-smell', 'maintainability'],
	},
	{
		id: 'CWE-1065',
		name: 'Runtime Resource Management Control Element in a Component Built to Run on Application Servers',
		lang: 'java',
		status: 'Complete',
		what: `部署於應用伺服器的元件卻用低階指令自行管理執行時期資源（Runtime Resource Management Control Element in a
		Component Built to Run on Application Servers）。專案使用應用伺服器（如 J2EE／Servlet 容器）提供的元件，但在程式
		裡卻自己動手用底層 API 管理資源——自己建執行緒池、自己管理連線、直接對資料來源做 low-level 操作——而沒有使用容器
		提供的資源管理 API（JMS／DataSource／容器執行緒）。成因是不熟悉或想繞過容器的標準機制。後果是資源不受容器管控、
		缺少連線回收與交易與安全整合，容易漏釋放資源或與容器的評估衝撞。修法是改用容器或框架提供的高層資源管理 API。`,
		problem: `// 不安全寫法：在伺服器元件內自己 new 執行緒與連線
public void handle(Order o) {
    new Thread(() -> db.handleOrder(o)).start();   // 自建執行緒，非容器執行緒池
}`,
		fixed: `// 安全寫法：交由容器／框架提供的執行緒池與受管資源
ExecutorService pool = AppExecutor.getPool();       // 容器管理的 pool
pool.execute(() -> orderService.handle(o));`,
		patch: `@@
-     new Thread(() -> db.handleOrder(o)).start();
+     pool.execute(() -> orderService.handle(o));`,
		refs: ['CWE-1065', 'OWASP'],
		tags: ['application-server', 'resource-management', 'thread-pool', 'enterprise'],
	},
	{
		id: 'CWE-1066',
		name: 'Missing Serialization Control Element',
		lang: 'java',
		status: 'Complete',
		what: `缺少序列化控制單元（Missing Serialization Control Element）。程式宣告了可序列化的資料元素，卻沒有為它提供對應
		的序列化方法。當資料要被持久化或傳輸時，框架只能用反射／預設的方式猜測怎麼把每個欄位「吐」成資料流，而無法決定哪些欄位
		要被排除或如何處理敏感值。成因是只掛了 Serializable 標籤卻未自訂 writeObject／readObject 或未遵守序列化規範。後果是
		內部欄位（密碼、token）被一併序列化出去、反序列化時未做校驗引入惡意內容、格式變更後相容性斷裂。修法是實作並善用
		序列化方法，明確定義要曝露的欄位，並在反序列化端做白名單驗證。`,
		problem: `// 不安全寫法：僅宣告 Serializable，卻透過預設機制把內部欄位一起序列化出去
public class Session implements Serializable {
    public String sessionId;
    public String passwordHash;    // 預設序列化把雜湊也外帶
}`,
		fixed: `// 安全寫法：自訂 writeObject/readObject，排除敏感欄位並做校驗
private void writeObject(ObjectOutputStream o) throws IOException {
    o.writeObject(sessionId);           // 只輸出白名單欄位
}
private void readObject(ObjectInputStream i) throws IOException, ClassNotFoundException {
    sessionId = (String) i.readObject();
}`,
		patch: `@@
  public class Session implements Serializable {
      public String sessionId;
-     public String passwordHash;
+     private void writeObject(ObjectOutputStream o) throws IOException { o.writeObject(sessionId); }
+     private void readObject(ObjectInputStream i) throws IOException, ClassNotFoundException {
+         sessionId = (String) i.readObject();
+     }
  }`,
		refs: ['CWE-1066', 'OWASP'],
		tags: ['serialization', 'insecure-deserialization', 'data-exposure', 'object-serialization'],
	},
	{
		id: 'CWE-1067',
		name: 'Excessive Execution of Sequential Searches of Data Resource',
		lang: 'sql',
		status: 'Complete',
		what: `資料資源被過度地以循序搜尋方式存取（Excessive Execution of Sequential Searches of Data Resource）。程式對
		SQL 資料表或視圖發出的查詢，其 WHERE 條件沒有可利用的索引，導致資料庫只能對整個資料表做全表循序掃描（full scan）。
		成因是資料表缺乏相應索引、或索引與查詢條件不匹配（例如函式包住欄位使索引失效）。後果是在資料量增長後，每次查詢都
		拖著整張表跑，回應時間線性惡化，容易拖垮資料庫與整個服務。修法是針對查詢條件建立符合的索引、避免在索引欄位上套函式，
		並用執行計畫（EXPLAIN）確認查詢落到索引而非 seq scan。`,
		problem: `// 不安全寫法：對大表做無索引條件查詢，觸發全表掃描
SELECT * FROM orders WHERE UPPER(customer_email) = 'ALICE@EX.COM';  -- 函式使 email 索引失效`,
		fixed: `// 安全寫法：改用可命中索引的等值比較
SELECT * FROM orders WHERE customer_email = 'alice@ex.com';          -- 對應 email 欄位的索引`,
		patch: `@@
- SELECT * FROM orders WHERE UPPER(customer_email) = 'ALICE@EX.COM';
+ SELECT * FROM orders WHERE customer_email = 'alice@ex.com';`,
		refs: ['CWE-1067', 'OWASP'],
		tags: ['sql-injection-scan', 'index', 'performance', 'full-table-scan'],
	},
	{
		id: 'CWE-1068',
		name: 'Inconsistency Between Implementation and Documented Design',
		lang: 'text',
		status: 'Complete',
		what: `實作與文件描述設計不一致（Inconsistency Between Implementation and Documented Design）。程式的實作內容與
		文件（規格、設計文件、原始碼註解）描述的行為不一致。成因是文件未隨程式演化更新、或實作時偷改成與規格不同的做法又沒
		同步文件。後果是團隊與工具依據錯誤的文件做出錯誤的判斷——測試以文件為準驗出「假通過」、稽核者把實際有誤的行為當成符合
		規格，導致問題被長期隱埋。修法是讓規格文件與實作維持單一來源（single source of truth），變更程式時同時更新對應文件，
		並在 CI 中對關鍵行為加上對照文件的契約測試。`,
		problem: `// 文件說密碼規則「最少 12 碼」，實作卻只驗 6 碼
function validate(pw) { return pw.length >= 6; }      // 與文件規格 12 不一致`,
		fixed: `// 修法：讓實作對齊文件規格，並以契約測試保證一致
function validate(pw) { return pw.length >= 12; }      // 與文件一致`,
		patch: `@@
- function validate(pw) { return pw.length >= 6; }
+ function validate(pw) { return pw.length >= 12; }`,
		refs: ['CWE-1068', 'OWASP'],
		tags: ['documentation', 'spec-drift', 'consistency', 'design'],
	},
	{
		id: 'CWE-1069',
		name: 'Empty Exception Block',
		lang: 'java',
		status: 'Complete',
		what: `空白的例外處理區塊（Empty Exception Block）。catch 區塊裡面一個字都沒有，把例外靜悄悄地吞掉。成因是開發者認為
		該例外「不會發生」、或急著先讓編譯過就留空。後果是錯誤資訊完全遺失：出錯時程式繼續走錯路、日誌沒有任何線索、還留下
		資源沒關閉等隱憂，是最難除錯的來源之一。修法是任何例外都要處理——至少記錄下來（log）、決定是否重拋，或明確地關帳後退出。
		絕不要留下空白的 catch。`,
		problem: `// 不安全寫法：空 catch，例外被無聲吞掉
try {
    conn.close();
} catch (SQLException e) {
    // do nothing —— 錯誤消失在空氣中
}`,
		fixed: `// 安全寫法：記錄例外並處理資源關閉失敗
catch (SQLException e) {
    log.error("close database connection failed", e);
    throw new DataAccessException(e);
}`,
		patch: `@@
  } catch (SQLException e) {
-     // do nothing
+     log.error("close database connection failed", e);
+     throw new DataAccessException(e);
  }`,
		refs: ['CWE-1069', 'OWASP'],
		tags: ['empty-catch', 'exception-handling', 'error-handling', 'swallow'],
	},
	{
		id: 'CWE-1070',
		name: 'Serializable Data Element Containing non-Serializable Item Elements',
		lang: 'java',
		status: 'Complete',
		what: `可序列化資料元素卻含不可序列化的子元素（Serializable Data Element Containing non-Serializable Item Elements）。
		某個欄位或成員宣告成可序列化（implements Serializable），但它所持有的另一個成員型別卻沒有實作序列化。序列化執行時被這顆
		絆腳石砸到，通常拋出 NotSerializableException，整個持久化或傳輸作業失敗。成因是忘了為內嵌型別加上 Serializable、或加了
		一個不可序列化的依賴（如 Thread、Socket、資料庫連線）。後果是把物件寫進 session／快取或傳輸時，執行時期才爆出例外，
		請求功敗垂成。修法是讓所有內嵌成員都可序列化，或把這些欄位標成 transient 並用靜態／不分發方式重建。`,
		problem: `// 不安全寫法：Session 可序列化，但其內嵌 SocketPool 不可序列化
public class Session implements Serializable {
    public SocketPool pool = new SocketPool();   // SocketPool 未實作 Serializable
}`,
		fixed: `// 安全寫法：把不可序列化欄位標 transient，重建成員
public class Session implements Serializable {
    public transient SocketPool pool;            // 不參與序列化
}`,
		patch: `@@
  public class Session implements Serializable {
-     public SocketPool pool = new SocketPool();
+     public transient SocketPool pool;
  }`,
		refs: ['CWE-1070', 'OWASP'],
		tags: ['serialization', 'nonserializable', 'notserializable-exception'],
	},
	{
		id: 'CWE-1071',
		name: 'Empty Code Block',
		lang: 'c',
		status: 'Complete',
		what: `空白的程式碼區塊（Empty Code Block）。原始碼中存在一個完全不包含任何程式碼的區塊——空的區塊主體（{}）、空的條件
		或空的分支。成因是留待日後實作的暫留結構、或除錯時把內容刪掉。後果是那些「看起來有處理」的路徑實際上什麼都沒做，容易
		造成邏輯空轉、沒關閉資源、或讓後續維護者誤以為已有邏輯。空的迴圈或條件結合非預期輸入常發展成真實弱點。修法是刪除無實質
		內容的空區塊，若只是尚未實作則明確標記 TODO／拋出 NotImplemented，讓意圖清楚且被工具捕捉。`,
		problem: `// 不安全寫法：條件成立卻什麼都不做的空區塊
if (user != null) {
    // TODO later —— 完全空白
}`,
		fixed: `// 安全寫法：明示未實作行為，避免「空處理」誤解
if (user == null) { return -1; }
applyGrant(user);`,
		patch: `@@
  if (user != null) {
-     // TODO later
+     return applyGrant(user);
  }`,
		refs: ['CWE-1071', 'OWASP'],
		tags: ['empty-block', 'dead-code', 'code-quality'],
	},
	{
		id: 'CWE-1072',
		name: 'Data Resource Access without Use of Connection Pooling',
		lang: 'java',
		status: 'Complete',
		what: `存取資料資源卻未使用連線池（Data Resource Access without Use of Connection Pooling）。程式每次需要資料庫服務時都
		重新建立一個全新的資料庫連線，用完即丟，沒有使用連線池（connection pool）機制。建立與拆解資料庫連線是昂貴的握手協定，
		在高併發下反覆建立連線不但慢，且連線數會瞬間撐爆資料庫上限。成因是連線池設定錯誤、或直接在程式碼裡反覆
		DriverManager.getConnection。後果是回應延遲惡化、資料庫端連線耗盡並拒絕服務、甚至成為間接 DoS。修法是統一透過連線池
		（如 HikariCP／容器 DataSource）取得連線，並讓連線歸還池中重用。`,
		problem: `// 不安全寫法：每個請求都自己開一顆全新連線再放掉
public void run(User u) {
    Connection c = DriverManager.getConnection(URL, U, P);   // 無池化，每次重握
    use(c); c.close();
}`,
		fixed: `// 安全寫法：透過連線池取得並歸還連線
try (Connection c = dataSource.getConnection()) {   // 池裡重用
    use(c);
}`,
		patch: `@@
-     Connection c = DriverManager.getConnection(URL, U, P);
-     use(c); c.close();
+     try (Connection c = dataSource.getConnection()) { use(c); }`,
		refs: ['CWE-1072', 'OWASP'],
		tags: ['connection-pool', 'database', 'resource-leak', 'performance'],
	},
	{
		id: 'CWE-1073',
		name: 'Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses',
		lang: 'java',
		status: 'Complete',
		what: `非 SQL 的被呼叫控制單元卻帶過多的資料資源存取（Non-SQL Invokable Control Element with Excessive Number of Data
		Resource Accesses）。用戶端某個函式或方法在單一呼叫流程中，透過資料管理元件發出一大串資料存取／查詢，而沒有用資料庫
		仍舊掌握的高效能力（JOIN、批量、stored procedure 等）。成因是把需要在資料庫內完成的聚合動作拆碎，在應用端一筆筆取回。
		後果是網路往返暴增、資料庫負載被無意義放大，回應時間隨資料量退化。修法是集中多次查詢為一次完整 SQL（JOIN／subquery），
		讓資料庫做篩選與聚合，用戶端只取需要的結果。`,
		problem: `// 不安全寫法：客戶端一個方法內對資料管理元件發十幾次查詢
List id = dm.fetchAllOrderIds(customer);
for (Integer oid : id) dm.fetchOrderLines(oid);   // 每訂單又查一次`,
		fixed: `// 安全寫法：單一查詢由資料庫完成 join 與聚合
List rows = dm.fetchOrdersWithLines(customerId);    // 一次 SQL 拿全部`,
		patch: `@@
- for (Integer oid : dm.fetchAllOrderIds(customer)) dm.fetchOrderLines(oid);
+ List rows = dm.fetchOrdersWithLines(customerId);`,
		refs: ['CWE-1073', 'OWASP'],
		tags: ['chattiness', 'database', 'join-instead', 'performance'],
	},
	{
		id: 'CWE-1074',
		name: 'Class with Excessively Deep Inheritance',
		lang: 'java',
		status: 'Complete',
		what: `繼承深度過深的類別（Class with Excessively Deep Inheritance）。某個類別的繼承階層太深，擁有很長一串父類別鏈。
		成因是持續用「再加一層父類別」的方式提取共同邏輯。後果是行為被稀釋並散落在多層，定位某個方法到底由哪一層提供非常困難；
		new 出一顆物件會間接執行一整串父類別建構子，出錯時難以追蹤；替換或測試其中一層牽一髮動全身。修法是限制繼承深度，
		用組合（composition）取代過深的「is-a」鏈，或靠介面與預設方法（default method）把共同行為集中。`,
		problem: `// 不安全寫法：parent 一層層堆到十幾層
class AextendsBase extends Base9 extends Base8 ... extends Base0 { }`,
		fixed: `// 安全寫法：把深層繼承改為組合，只保留必要的一兩層介面
class AextendsBase implements Capable {      // 能力用實作組合，不多層繼承
    private final Engine engine;
}`,
		patch: `@@
- class A extends B extends C extends D ... { }
+ class A implements Capable { private final Engine engine; }`,
		refs: ['CWE-1074', 'OWASP'],
		tags: ['inheritance-depth', 'composition-over-inheritance', 'design'],
	},
	{
		id: 'CWE-1075',
		name: 'Unconditional Control Flow Transfer outside of Switch Block',
		lang: 'c',
		status: 'Complete',
		what: `在 switch 區塊之外使用未受條件約束的控制流轉移（Unconditional Control Flow Transfer outside of Switch Block）。
		程式在非 switch ／非分支的結構內撰寫了無條件跳轉，例如「goto」直接跳到別的標籤。成因是為了躲避巢狀迴圈或錯誤路徑
		管理而到處放 goto。後果是可讀性崩壞、跳轉路徑跳過資源釋放或初始化、在除錯與靜態分析上也難追蹤，還容易造成越過
		特定清理程式碼而洩漏資源或破壞狀態。修法是改用結構化控制流程而非 goto，唯一的例外是語言既定且受控的跳轉（如 guard
		clause 或語言規範的 break/return）。`,
		problem: `// 不安全寫法：在一般程式內用 goto 跳出巢狀結構，跳過清理
for (...) {
    for (...) {
        goto done;          // 未受 switch 保護的無條件跳轉
    }
}
done: printf("leak: fd not closed");`,
		fixed: `// 安全寫法：用結構化的 return/旗標控制流程
if (found) { return; }    // 以 return 明確結束，避免無條件長距離跳轉`,
		patch: `@@
- for (...) { for (...) { goto done; } } done: printf("...");
+ if (found) { return; }`,
		refs: ['CWE-1075', 'OWASP'],
		tags: ['goto', 'control-flow', 'code-quality', 'structure'],
	},
	{
		id: 'CWE-1077',
		name: 'Floating Point Comparison with Incorrect Operator',
		lang: 'c',
		status: 'Complete',
		what: `用不當的運算子比較浮點數（Floating Point Comparison with Incorrect Operator）。程式以相等（==）或其它直接運算子
		比較兩個浮點數值，卻沒有考慮浮點數表示法必然存在的精度損失。浮點數在轉成二進位時多為近似值，累加、除法後兩者算起來
		明明相同結果卻不「等於」。成因是直接用直覺的 == 判斷精確等值。後果是邏輯判斷錯誤：條件永真／永假、邊界值出不來，
		在安全敏感處（總額、金額、權限門檻）可能被利用而誤判。修法改用預設容差（epsilon）比較兩值之差的絕對值，而非直接
		比相等。`,
		problem: `// 不安全寫法：直接以 == 比較浮點運算結果
if ((a / 3.0) * 3.0 == a) { use(); }   // 精度損失使比較恆假`,
		fixed: `// 安全寫法：以容差 epsilon 比較接近程度
if (fabs((a / 3.0) * 3.0 - a) < 1e-9) { use(); }`,
		patch: `@@
- if ((a / 3.0) * 3.0 == a) { use(); }
+ if (fabs((a / 3.0) * 3.0 - a) < 1e-9) { use(); }`,
		refs: ['CWE-1077', 'OWASP'],
		tags: ['floating-point', 'precision', 'numeric-comparison', 'epsilon'],
	},
	{
		id: 'CWE-1079',
		name: 'Parent Class without Virtual Destructor Method',
		lang: 'cpp',
		status: 'Complete',
		what: `父類別沒有虛擬解構子（Parent Class without Virtual Destructor Method）。父類別有一個以上子類別，但父類別的解構子
		不是 virtual。當透過父類別指標刪除子類別物件時，C++ 只呼叫父類別的析構，子類別的解構不會被呼叫，造成子類別持有的
		動態資源漏失或未清理。成因是忘了在有多型用途的類別宣告解構子為 virtual（或根本沒宣告）。後果是記憶體與資源洩漏、
		各種未定義行為、長時間運作的服務記憶體持續成長。修法是凡是搭配 virtual 函式／多型使用的父類別，都將解構子宣告為
		virtual（或讓類別不可被刪除）。`,
		problem: `// 不安全寫法：父類別解構子非 virtual，透過 base 指標釋放衍生物件漏掉資源
class Base { public: ~Base() {} };
class Derived : public Base { public: int* p = new int[100]; ~Derived() { delete[] p; } };
Base* o = new Derived(); delete o;   // 只跑 ~Base，Derived 的解構沒執行`,
		fixed: `// 安全寫法：父類別解構子宣告 virtual，確保分工釋放
class Base { public: virtual ~Base() {} };`,
		patch: `@@
- class Base { public: ~Base() {} };
+ class Base { public: virtual ~Base() {} };`,
		refs: ['CWE-1079', 'OWASP'],
		tags: ['virtual-destructor', 'cpp', 'resource-leak', 'polymorphism'],
	},
	{
		id: 'CWE-1080',
		name: 'Source Code File with Excessive Number of Lines of Code',
		lang: 'text',
		status: 'Complete',
		what: `單一原始碼檔行數過多（Source Code File with Excessive Number of Lines of Code）。單一支原始碼檔包含過多行程式碼。
		成因是把一大堆類別、公用函式或業務邏輯全部塞進同一個檔案。後果是難以閱讀與維護、code review 覆蓋不足、改錯的機率升高、
		模組職責模糊，導致檢驗與重構成本大增。修法是依單一職責拆分檔案與模組，將共用功能移到獨立且可測試的小單元，符合低耦合
		高內聚的設計。可用工具（圈複雜度、行數檢查）在 CI 上設門檻強制。`,
		problem: `// 不安全寫法：一個檔擠進上千行程式與十幾個無關函式
// giant.c —— utilities、net、db、UI 全在一個檔`,
		fixed: `// 安全寫法：依職責拆分成可各自測試的小檔
// db.c / net.c / ui.c —— 每個檔單一職責`,
		patch: `@@
- // giant.c 上千行
+ // 依職責拆分成 db.c / net.c / ui.c`,
		refs: ['CWE-1080', 'OWASP'],
		tags: ['code-size', 'maintainability', 'refactor', 'single-responsibility'],
	},
	{
		id: 'CWE-1082',
		name: 'Class Instance Self Destruction Control Element',
		lang: 'cpp',
		status: 'Complete',
		what: `類別實例自行刪除／銷毀自己（Class Instance Self Destruction Control Element）。某個類別實例在其成員函式內呼叫
		delete this（或其它自我銷毀指令），在成員函式尚未結束或之後還繼續使用該物件時，就是對已釋放記憶體的存取，屬未定義行為。
		成因是為了省物件生命週期管理而讓物件在函式內自爆。後果是懸空指標、double-free、當機，且極難重現。修法是明確由擁有者
		在物件生命週期真正結束時刪除，避免「自己刪自己」的模式；若確需自我管理，也必須確保刪除後絕不再使用且不重入其他成員。`,
		problem: `// 不安全寫法：成員函式內 delete this 後還回讀 this 的欄位
void Task::run() { 
    delete this;                 // 物件已釋放
    printf("%s", worker);        // worker 是懸空讀
}`,
		fixed: `// 安全寫法：由擁有者負責釋放，物件不自行銷毀
void Task::run() { owner->finished(this); }   // 由擁有者刪除，之後不再觸碰 this`,
		patch: `@@
  void Task::run() {
-     delete this spons;
-     printf("%s", worker);
+     owner->finished(this);
  }`,
		refs: ['CWE-1082', 'OWASP'],
		tags: ['delete-this', 'use-after-free', 'lifetime', 'cpp'],
	},
	{
		id: 'CWE-1083',
		name: 'Data Access from Outside Expected Data Manager Component',
		lang: 'sql',
		status: 'Complete',
		what: `資料存取發生於預期資料管理元件之外（Data Access from Outside Expected Data Manager Component）。系統設計上規定
		資料存取必須由某個資料管理元件（關聯式或非 SQL 資料庫的特定 DAO／服務層）統一執行，但某段程式卻直接對資料來源下指令，
		脫離了這個既定元件。成因與 CWE-1057 同族但角度相反——此條強調「資料從元件外面被打」。後果是集中管制的權限、加密、
		稽核日誌在這些範圍外全面失效，且同一張表的存取方式分裂成多種途徑，難以統一更動與治理。修法是把存取點全部收斂回
		資料管理元件，所有對資料來源的操作一律透過它轉發。`,
		problem: `// 不安全寫法：手寫 SQL 直接打外部資料來源，脫離資料管理元件
db.rawExec("UPDATE accounts SET balance=balance+100 WHERE acct='A1'");`,
		fixed: `// 安全寫法：一律改由資料管理元件提供的方法執行
accountRepo.credit("A1", 100);   // 所有更新皆經統一元件`,
		patch: `@@
- db.rawExec("UPDATE accounts SET balance=balance+100 WHERE acct='A1'");
+ accountRepo.credit("A1", 100);`,
		refs: ['CWE-1083', 'OWASP'],
		tags: ['data-access', 'governance', 'dao', 'layer-bypass'],
	},
	{
		id: 'CWE-1084',
		name: 'Invokable Control Element with Excessive File or Data Access Operations',
		lang: 'java',
		status: 'Complete',
		what: `被呼叫的控制單元帶過多的檔案或資料存取操作（Invokable Control Element with Excessive File or Data Access
		Operations）。某個函式或方法在其本體中，包含過多會用到資料管理元件或檔案的作業。成因是把本該由多步驟分工的工作全部
		塞進一個方法。後果是該方法與外部資源的耦合過深，執行緩慢、難以測試（測試時要準備一大堆假檔案／假資料）、出錯時失敗
		的分界模糊。修法是將功能拆為職責單一的若干小方法，各方法各自負責一種資源作業，整體組合成清晰的工作流。`,
		problem: `// 不安全寫法：一個方法內連續開檔寫檔讀庫十多次
void doReport() { open(log); write(log); open(db); query(db); write(db); hash(); ... }`,
		fixed: `// 安全寫法：拆分單一職責，各方法只做一種資源作業
void doReport() { List rows = loadRows(); writeFile(rows); }   // 各職責各一函式`,
		patch: `@@
- void doReport() { open(log); write(log); open(db); query(db); write(db); hash(); ... }
+ void doReport() { List rows = loadRows(); writeFile(rows); }`,
		refs: ['CWE-1084', 'OWASP'],
		tags: ['design', 'single-responsibility', 'cohesion', 'code-quality'],
	},
	{
		id: 'CWE-1085',
		name: 'Invokable Control Element with Excessive Volume of Commented-out Code',
		lang: 'c',
		status: 'Complete',
		what: `被呼叫的控制單元內塞入過多被註解的程式碼（Invokable Control Element with Excessive Volume of Commented-out Code）。
		某函式、方法或程序本體裡，有大量程式碼被註解掉而「躺」在原地。成因是在多次嘗試修正時用註解保留舊版本。後果是註解大量
		註解程式碼把真正邏輯淹沒，閱讀成本上升、舊片段老舊但看起來像真的、掃描工具與人容易誤判；錯誤地取消註解可能重新把舊的
		有缺陷邏輯復活。修法是使用版本控制管理過往版本，把不再需要的程式碼直接刪除，需要留存歷程時查 git log 即可，而不是
		留在原始碼裡。`,
		problem: `// 不安全寫法：半個函式都被註解的舊實作佔滿
int calc(int x) {
    // int r = x * 2 + oldTax;      <- 舊版
    // return r + extra + fee;       <- 舊版
    return x < 0 ? 0 : x + fee(x);
}`,
		fixed: `// 安全寫法：刪除註解掉的舊程式碼，歷史交給版本控制
int calc(int x) { return x < 0 ? 0 : x + fee(x); }`,
		patch: `@@
  int calc(int x) {
-     // ... 一排被註解的舊實作
      return x < 0 ? 0 : x + fee(x);
  }`,
		refs: ['CWE-1085', 'OWASP'],
		tags: ['commented-code', 'dead-code', 'maintainability', 'version-control'],
	},
	{
		id: 'CWE-1086',
		name: 'Class with Excessive Number of Child Classes',
		lang: 'java',
		status: 'Complete',
		what: `子類別數量過多的類別（Class with Excessive Number of Child Classes）。某個類別直接或間接擁有多到不必要的子類別群。
		成因是父類別沒有良好設計，讓每個不同情境都必須用「繼承」來擴充。後果是父類別的修改會同時引爆一群子類別的改變，測試
		與維護成本成倍成長，新增子類別容易互相踩踏到共同行為。修法是以介面配合組合（composition）與策略（strategy）模式取代
		過度擴張的子類別樹，只在真的有「是（is-a）」關係時才用繼承。`,
		problem: `// 不安全寫法：父類別下有幾十個幾乎無差異的子類別
class Button {} class RedButton extends Button {} class BlueButton extends Button {} /* …數十個 */`,
		fixed: `// 安全寫法：用組合／屬性取代大量子類別
class Button { private Color color; }    // 以欄位描述差異，不必每個顏色一個子類別`,
		patch: `@@
- class RedButton extends Button {} class BlueButton extends Button {} // …
+ class Button { private Color color; }`,
		refs: ['CWE-1086', 'OWASP'],
		tags: ['subclass-fanout', 'class-design', 'composition', 'maintainability'],
	},
	{
		id: 'CWE-1087',
		name: 'Class with Virtual Method without a Virtual Destructor',
		lang: 'cpp',
		status: 'Complete',
		what: `類別含 virtual 方法卻沒有對應的 virtual 解構子（Class with Virtual Method without a Virtual Destructor）。
		類別內宣告了虛擬方法（virtual method）表明它會被當多型基底使用，但卻沒有同為 virtual 的解構子。透過基底指標刪除
		衍生物件時，只呼叫基底解構，衍生資源漏失，落入未定義行為。成因是在加 virtual 方法時忘了同步把解構子也宣告 virtual。
		後果是記憶體／資源洩漏、錯誤清理順序，長時間運行就出問題。修法是引進第一個 virtual 方法時，必然把解構子也宣告
		virtual，否則考慮讓類別不可被多型刪除。`,
		problem: `// 不安全寫法：有 virtual 方法，但解構子非 virtual
class Shape { public: virtual void draw() {} ~Shape() {} };`,
		fixed: `// 安全寫法：補上 virtual 解構子
class Shape { public: virtual void draw() {} virtual ~Shape() {} };`,
		patch: `@@
- class Shape { public: virtual void draw() {} ~Shape() {} };
+ class Shape { public: virtual void draw() {} virtual ~Shape() {} };`,
		refs: ['CWE-1087', 'OWASP'],
		tags: ['virtual-destructor', 'cpp', 'polymorphism', 'resource-leak'],
	},
	{
		id: 'CWE-1088',
		name: 'Synchronous Access of Remote Resource without Timeout',
		lang: 'java',
		status: 'Complete',
		what: `同步存取遠端資源卻未設逾時（Synchronous Access of Remote Resource without Timeout）。程式對遠端資源（網路、外部
		服務、資料庫）做同步呼叫，卻沒有設定逾時，或把逾時設成「無限」。成因是預設外部服務一定乖乖回應而略過 timeout 設定。
		後果是當遠端服務卡住、網路斷線時，執行緒會永無止盡地等待，吃光執行緒池與連線，讓整個服務癱瘓並耗盡資源——典型的
		阻斷服務放大點。修法是為所有遠端同步呼叫設定合理且明確的逾時與錯誤處理，並在逾時時優雅降級而非死等。`,
		problem: `// 不安全寫法：沒有 timeout 的同步呼叫，對方卡住即永遠等待
Response r = client.execute(axiosRequest);   // 無 timeout 設定`,
		fixed: `// 安全寫法：明確設定 connect/read timeout，逾時走降級
client.setConnectTimeout(2000); client.setReadTimeout(3000);
try (Response r = client.execute(req)) { ... }
catch (SocketTimeoutException e) { log.warn("call timed out"); }`,
		patch: `@@
- Response r = client.execute(axiosRequest);
+ client.setConnectTimeout(2000); client.setReadTimeout(3000);
+ try (Response r = client.execute(req)) { ... } catch (SocketTimeoutException e) { }`,
		refs: ['CWE-1088', 'OWASP'],
		tags: ['timeout', 'remote-call', 'denial-of-service', 'hung-thread'],
	},
	{
		id: 'CWE-1089',
		name: 'Large Data Table with Excessive Number of Indices',
		lang: 'sql',
		status: 'Complete',
		what: `大型資料表帶過多的索引（Large Data Table with Excessive Number of Indices）。一張大型資料表上堆了非常多的索引。
		索引能加速查詢數增加會等值提高寫入成本、佔用大量儲存、之後病史維護。成因是看到某個查詢變慢就無腦加一個索引，長期累積出
		一大堆。後果是 INSERT／UPDATE／DELETE 都要同步維護每個索引而變慢，索引也衝高記憶體使用，某些索引甚至幾乎沒被查詢用到。
		修法是先量測實際使用——（透過自動計畫與 pg_stat_user_indexes）確認哪些索引被用，刪除多餘的組合索引，用複合索引取代
		多個單欄索引。`,
		problem: `// 不安全寫法：為了穩妥狂加一堆單欄索引，寫入成本被拖垮
CREATE INDEX idx_t_a ON t(a); CREATE INDEX idx_t_b ON t(b);
CREATE INDEX idx_t_c ON t(c); CREATE INDEX idx_t_d ON t(d); /* …10+ 個 */`,
		fixed: `// 安全寫法：依實際查詢模式收斂為少數複合索引
CREATE INDEX idx_t_ab ON t(a, b);   -- 涵蓋常用查詢，檔案量小、寫入輕`,
		patch: `@@
- CREATE INDEX idx_t_a ON t(a); CREATE INDEX idx_t_b ON t(b); /* 一堆 */
+ CREATE INDEX idx_t_ab ON t(a, b);`,
		refs: ['CWE-1089', 'OWASP'],
		tags: ['indexes', 'database-design', 'write-overhead', 'schema'],
	},
	{
		id: 'CWE-1090',
		name: 'Method Containing Access of a Member Element from Another Class',
		lang: 'java',
		status: 'Complete',
		what: `方法直接存取別個類別的成員元素（Method Containing Access of a Member Element from Another Class）。某類別的方法對
		另一類別的成員——欄位或內部細節——做直接存取，而不是呼叫公開的介面。成因是為了方便直接掏對物件的內部欄位代替稍長的方法
		呼叫。後果是破壞封裝，兩類別強耦合，後續變更內部表示時此方法也會跟著壞，測試與重構成重。修法是只透過對方公開的
		API／存取子（getter/setter）或行為方法互動，維持資訊隱藏的封裝邊界。`,
		problem: `// 不安全寫法：直接掏另一類別的公開欄位改內部狀態
CartLayout.total += item.price;   // 直接改 CartLayout 的 total 欄位，繞過封裝`,
		fixed: `// 安全寫法：呼叫對方公開行為方法以更新狀態
cart.add(item);                  // CartLayout 自己管理 total 的計算`,
		patch: `@@
- CartLayout.total += item.price;
+ cart.add(item);`,
		refs: ['CWE-1090', 'OWASP'],
		tags: ['encapsulation', 'coupling', 'information-hiding', 'design'],
	},
	{
		id: 'CWE-1091',
		name: 'Use of Object without Invoking Destructor Method',
		lang: 'cpp',
		status: 'Complete',
		what: `使用了物件卻未呼叫其析構／finalize 方法（Use of Object without Invoking Destructor Method）。某方法使用了一個物件、
		之後卻沒有呼叫該元素的關閉／析構方法，讓它被「用完即棄」但未真正釋放。成因是忘了對需要清理的資源物件呼叫 delete、
		close 或釋放函式。後果是記憶體、連線、檔案描述子等資源逐步洩漏，長時間服務記憶體膨脹或資源耗盡而當機。修法是確保
		使用後一定呼叫對應的析構／釋放方法，最好是採用 RAII、資源封閉在 with（C#）或 try-with-resources（Java）這類作用域
		自動清理的語法，讓例外路徑也不會漏。`,
		problem: `// 不安全寫法：開了檔案卻在使用後不關閉
void dump() {
    FILE* f = fopen(path, "w");     // fopen 記到
    fputs("x", f);                  // fclose 從未呼叫 —— 句柄洩漏
}`,
		fixed: `// 安全寫法：透過 RAII 讓 destructor 自動關閉
void dump() { std::ofstream f(path); f << "x"; }   // 離開作用域即自動關閉`,
		patch: `@@
- FILE* f = fopen(path, "w"); fputs("x", f);
+ std::ofstream f(path); f << "x";`,
		refs: ['CWE-1091', 'OWASP'],
		tags: ['resource-leak', 'destructor', 'raii', 'file-handle'],
	},
	{
		id: 'CWE-1092',
		name: 'Use of Same Invokable Control Element in Multiple Architectural Layers',
		lang: 'java',
		status: 'Complete',
		what: `同一個被呼叫控制單元被用在多個架構層（Use of Same Invokable Control Element in Multiple Architectural Layers）。
		同一個函式或方法同時被用於好幾個不同的架構層分享於… 對架構層級對影響。例如把資料存取用的方法擺到 UI 或 controller 直接呼叫，
		或核心邏輯方法直接由網頁層當成 API。成因是沒有依職責分層、共享常被「哪層需要就全叫」。後果是層與層互相穿透、Where
		誰呼叫誰難以掌握、改動該方法會同時影響展示層與資料層等眾多層而爆出跨層衝擊。修法是每個架構層定義並呼叫自己那一層的
		介面，跨層邊界只透過明確契約（API／DTO）往來，避免同一個內部方法被多層共用。`,
		problem: `// 不安全寫法：資料層的低階方法被 UI 直接呼叫
// 網頁 UI 直接呼叫 database 裡的私有語意方法
render(bestPrice(db.executePriceQuery(product)));   // controller 層直接用 DB 查詢`,
		fixed: `// 安全寫法：各層只和自己的服務層透過介面互動
render(catalogService.getBestPrice(product));        // controller 只呼叫 service 層 API`,
		patch: `@@
- render(bestPrice(db.executePriceQuery(product)));
+ render(catalogService.getBestPrice(product));`,
		refs: ['CWE-1092', 'OWASP'],
		tags: ['layering', 'architecture', 'separation-of-concerns', 'design'],
	},
	{
		id: 'CWE-1094',
		name: 'Excessive Index Range Scan for a Data Resource',
		lang: 'sql',
		status: 'Complete',
		what: `對資料資源做過度的索引範圍掃描（Excessive Index Range Scan for a Data Resource）。對大型資料表執行索引範圍
		（index range）掃描，但掃描範圍能涵蓋到非常多的列。使用索引雖優於全表掃，但當範圍條件（如 a BETWEEN/>=）命中的行數
		佔表很大比例時，索引範圍掃描仍要回表搬回大量記錄，成本不輸全表。成因是範圍條件寫得過寬或統計資料誤導最佳化器。
		後果是查詢在資料量增長後變得很慢，更容易在尖峰拖累。修法是確認實際需要取的範圍，細化 WHERE（縮小邊界、加分頁）、
		用更精準的複合索引涵蓋範圍，並以執行計畫確認掃描深度合理。`,
		problem: `// 不安全寫法：範圍條件過寬，索引掃描涵蓋近乎整張表
SELECT * FROM logs WHERE ts >= '2000-01-01';   -- 幾乎全表都在範圍`,
		fixed: `// 安全寫法：加較嚴格的邊界或用時間窗口分頁，縮小掃描深度
SELECT * FROM logs WHERE ts BETWEEN '2024-01-01' AND '2024-01-31' AND page=?`,
		patch: `@@
- SELECT * FROM logs WHERE ts >= '2000-01-01';
+ SELECT * FROM logs WHERE ts BETWEEN '2024-01-01' AND '2024-01-31' AND page=?`,
		refs: ['CWE-1094', 'OWASP'],
		tags: ['index-range-scan', 'performance', 'query-tuning', 'database'],
	},
	{
		id: 'CWE-1095',
		name: 'Loop Condition Value Update within the Loop',
		lang: 'c',
		status: 'Complete',
		what: `迴圈的條件值在迴圈本體中被更新（Loop Condition Value Update within the Loop）。迴圈的控制條件依賴某個值，而這個值在
		迴圈本體內部被改動。這樣一來迴圈會走幾圈不再由邊界決定，而取決於本體執行的副作用順序。成因是把「更新指標／計數」混進
		本體邏輯中。後果是迴圈次數不可預期、條件與更新互相干擾導致無窮迴圈或提早結束，配合非預期輸入更容易造成越界或死迴圈。
		修法是讓迴圈的控制變數只由迴圈的第三次子句更新，本體內不要再改動影響條件的值。`,
		problem: `// 不安全寫法：本體裡又改 i 又改 len，條件被副作用竄動
for (i = 0; i < len; i++) { if (buf[i]) buf[len++] = 0; }`,
		fixed: `// 安全寫法：控制變數僅由 for 的增量更新，本體不動條件值
for (i = 0; i < n; i++) process(buf[i]);`,
		patch: `@@
- for (i = 0; i < len; i++) { if (buf[i]) buf[len++] = 0; }
+ for (i = 0; i < n; i++) process(buf[i]);`,
		refs: ['CWE-1095', 'OWASP'],
		tags: ['loop-control', 'infinite-loop', 'control-flow', 'correctness'],
	},
	{
		id: 'CWE-1096',
		name: 'Singleton Class Instance Creation without Proper Locking or Synchronization',
		lang: 'java',
		status: 'Complete',
		what: `單例（Singleton）建立未做正確鎖定或同步（Singleton Class Instance Creation without Proper Locking or
		Synchronization）。程式以 Singleton 設計模式實作，卻沒有使用適當的鎖或其它同步機制保證它真的只被建立一次。最常見的是
		雙重檢查鎖（double-checked locking）用錯了同步、或乾脆讓多執行緒同進建構子。成因是為了效能而省略鎖、或對 volatile
		理解錯誤。後果是多個執行緒各自建立一份實例、共享狀態彼此覆寫、取得「單例」的方式不穩定，進一步造成一時一致一時錯亂。
		修法採用已保證安全的方式：enum singleton、static holder 初始化，或確實地對整段建立＆發佈用鎖＋volatile（C++11 後
		亦可用 magic static／call_once）。`,
		problem: `// 不安全寫法：雙重檢查鎖漏 volatile，多執行緒可能建立多顆
static Singleton inst;
public static Singleton get() {
    if (inst == null) synchronized (Singleton.class) {
        if (inst == null) inst = new Singleton();   // 未 volatile，可見性不足
    }
    return inst;
}`,
		fixed: `// 安全寫法：用 static holder 交錯初始化，天然執行緒安全
static class Holder { static final Singleton INST = new Singleton(); }
public static Singleton get() { return Holder.INST; }`,
		patch: `@@
- static Singleton inst;
- public static Singleton get() { if (inst == null) synchronized (Singleton.class) { if (inst == null) inst = new Singleton(); } return inst; }
+ static class Holder { static final Singleton INST = new Singleton(); }
+ public static Singleton get() { return Holder.INST; }`,
		refs: ['CWE-1096', 'OWASP'],
		tags: ['singleton', 'synchronization', 'double-checked-locking', 'thread-safety'],
	},
	{
		id: 'CWE-1097',
		name: 'Persistent Storable Data Element without Associated Comparison Control Element',
		lang: 'java',
		status: 'Complete',
		what: `持久可儲存的資料元素卻缺少對應的比較控制單元（Persistent Storable Data Element without Associated Comparison
		Control Element）。某個會被存取的資料型別，沒有提供完整支持比較所需的方法／函式（equals、hashCode、compareTo 等）。
		成因是只寫了欄位與 getter 就忘了比對語意的實作。後果是當它放入 Set／Map／排序時，套用了物件的預設身分比較而非「值
		相等」，兩顆內容相同的實例被視為不同，查重複、去重、索引鍵與集合操作結果錯亂。鍵值類尤其關鍵——資料被當主鍵時錯誤比較
		會導致資料遺失或錯綁。修法是為依值的型別一併實作 equals＋hashCode＋compareTo，並遵守三者一致性的規範。`,
		problem: `// 不安全寫法：資料類別只有欄位，沒有 equals/hashCode，Set 照身分比
class Acct { String id; }   // 兩顆 id 相同物件在 Set 中算「不同」`,
		fixed: `// 安全寫法：補上依值比較的 equals 與一致的 hashCode
class Acct { String id;
  public boolean equals(Object o){ return o instanceof Acct a && a.id.equals(id); }
  public int hashCode(){ return id.hashCode(); } }`,
		patch: `@@
- class Acct { String id; }
+ class Acct { String id;
+   public boolean equals(Object o){ return o instanceof Acct a && a.id.equals(id); }
+   public int hashCode(){ return id.hashCode(); } }`,
		refs: ['CWE-1097', 'OWASP'],
		tags: ['equals-hashcode', 'comparison', 'persistent-data', 'collections'],
	},
	{
		id: 'CWE-1098',
		name: 'Data Element containing Pointer Item without Proper Copy Control Element',
		lang: 'cpp',
		status: 'Complete',
		what: `含指標的資料元素缺少正確的複製控制單元（Data Element containing Pointer Item without Proper Copy Control Element）。
		某個資料元素持有指標，卻沒有對應的複製（copy constructor／複製運算子）或建構方法，導致複製時只淺拷貝「指標本身」而非
		它所指的內容。成因是用了預設複製語意而沒有自訂複製控制。後果是兩份物件共享同一份指標指向的資源，各自解構重複釋放造成
		double-free、淺拷貝的一方事後去值得來錯誤或懸空的內容。修法是遵循 Rule of Three/Five：有指標成員就提供自訂的
		複製建構、複製運算與解構，或改用 std::unique_ptr／std::shared_ptr 管理所有權。`,
		problem: `// 不安全寫法：指標成員走預設淺拷貝 + 各持一份解構
class Buf { char* data; public: ~Buf(){ delete[] data; } };   // copy 時共享 data，解構雙釋放`,
		fixed: `// 安全寫法：改用標準庫管理所有權，杜絕淺拷貝與雙釋放
class Buf { std::vector<char> data; };   // RAII 自動深度管理`,
		patch: `@@
- class Buf { char* data; public: ~Buf(){ delete[] data; } };
+ class Buf { std::vector<char> data; };`,
		refs: ['CWE-1098', 'OWASP'],
		tags: ['rule-of-three', 'copy-control', 'double-free', 'pointer'],
	},
	{
		id: 'CWE-1099',
		name: 'Inconsistent Naming Conventions for Identifiers',
		lang: 'text',
		status: 'Complete',
		what: `識別字命名慣例不一致（Inconsistent Naming Conventions for Identifiers）。程式碼、文件或其它產物對變數、可呼叫、
		一組相關可呼叫、I/O 能力、資料型別、檔名等元素沒有一致地使用同套命名慣例。成因是多人協作且沒有明訂且強制的命名規範。
		後果是可讀性與可檢索性下降，混淆易生（a 大小寫與下底線混用）、容易誤認變數的角色，長期下來人與工具都難以為常，間接
		提高誤用與錯改的風險。修法是訂定並統一命名規範（如 Java 的 camelCase、C 的 snake_case），用 linter 在 CI 中強制
		執行，且保證同一套慣例跨程式碼、文件與檔名一致。`,
		problem: `// 不一致：同樣是「使用者數」卻 wrote 三種寫法
int userCount; int user_count; int Usercount;   // 命名散亂`,
		fixed: `// 一致：統一同一套慣例（此處 snake_case）
int user_count; int login_count; int order_count;`,
		patch: `@@
- int userCount; int user_count; int Usercount;
+ int user_count; int login_count; int order_count;`,
		refs: ['CWE-1099', 'OWASP'],
		tags: ['naming-convention', 'style', 'readability', 'linter'],
	},
	{
		id: 'CWE-1100',
		name: 'Insufficient Isolation of System-Dependent Functions',
		lang: 'c',
		status: 'Complete',
		what: `系統相依功能隔離不足（Insufficient Isolation of System-Dependent Functions）。系統相依的能力——作業系統呼叫、檔案路徑、
		換行、編碼、特定平台的 API——沒有被抽成獨立、各自的模組，而是散落在業務程式碼各處。成因是開發時直接用平台結合寫法就地解決。
		後果是可攜性差：換個 OS、編譯器或部署環境就要改一堆地方，且平台特異風險（路徑分隔、大小寫敏感性、換行）在每個使用處
		都可能踩雷，難以替換模擬替身做測試。修法是建立統一的抽象層（如 PIMPL、介面包裝）集中系統呼叫，平台細節只有該層知道，
		業務程式透過抽象使用。`,
		problem: `// 不安全寫法：業務邏輯直接指名 Unix 平台呼叫與路徑分隔
FILE* f = fopen("/etc/" + filename, "r");   // 路徑寫死在 Unix 慣例，難移植`,
		fixed: `// 安全寫法：系統相依溝通集中到抽象層
fileio *h = platform_fopen(configDir(), filename);   // 統一介面，平台實作各自封裝`,
		patch: `@@
- FILE* f = fopen("/etc/" + filename, "r");
+ fileio *h = platform_fopen(configDir(), filename);`,
		refs: ['CWE-1100', 'OWASP'],
		tags: ['portability', 'abstraction', 'platform-dependent', 'modularity'],
	},
];
