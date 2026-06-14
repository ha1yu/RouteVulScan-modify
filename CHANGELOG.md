# 更新日志 / Changelog

本文件记录 RouteVulScan 的重要变更,格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)。

## [Unreleased]
### 修复(Fixes)
- **UI 控件文字被遮挡**:`Config` 面板顶部 `Head_On`、`DomainScan_On`、`Bypass_On`、`Update`、`Load Yaml` 按钮及 `Thread Numbers` 标签在中文/高 DPI 环境下文字被裁切。根因是 `JButton` 默认 margin(左右约 14px)从内部挤占文字空间,单纯加宽无效。统一 `setMargin(new Insets(1,6,1,6))` 压掉内边距,并按文字长度重排 `setBounds`(`DomainScan` 150→160 容纳 `DomainScan_Off`,面板总宽 1180→1320)。

### 文档(Docs)
- README 补充 `Filter_Host` 输入框说明:被动扫描专用、`.`/`*` 通配符→正则转换规则、`Pattern.find` 部分匹配语义、常见用法对照表及子串误匹配注意事项;清理功能介绍中误删图片残留的空列表项。

### 安全(Security)
- **SnakeYAML 反序列化(CVE-2022-1471)**:`snakeyaml 1.28 → 2.2`,`YamlUtil` 读取/解析路径统一走显式 `SafeConstructor(new LoaderOptions())`,杜绝默认 Constructor 对(含远程拉取的)YAML 触发任意类构造。

### 修复(Fixes)
- **id 类型不统一崩溃**:新增 `YamlUtil.safeParseId(Object)` 统一转换入口,替换 `Config.Add_Button_Yaml` 的 `(int) cast`(遇 String id 直接 `ClassCastException`)、`View`/`Config.Edit`/`TabTitleEditListener.renameTabTitle` 的 `Integer.parseInt`(遇非数字抛 `NumberFormatException`);`MergerUpdateYamlFunc` 的 maxId 计算改用 `safeParseId`,覆盖 String 形式的合法数字 id。
- **模板标记数组越界**:`ProcTemplateLanguag` 对 `{{request}}`/`{{request.head}}` 等缺子键/缺 header 名的标记加索引守卫,原样返回而非 `ArrayIndexOutOfBoundsException`。
- **状态码解析崩溃**:`StatusCodeProc` 兜底分支对非数字(乱码/空串)异常兜底返回空集合;`any`/`all`/`*` 视为匹配全部 HTTP 状态码(100-599),让 Config UI 默认占位 `any` 真正生效;范围/单值解析失败静默跳过该段。

### 重构(Refactor)
- **`vulscan` 重型构造器**:构造器瘦身为仅做字段初始化 + 创建线程池;原扫描逻辑(POST 转换、删参、读 YAML、`LaunchPath` 两轮、`finally shutdown`)移至新增的 `public void scan()`。调用点改为 `new vulscan(...).scan()`(仅 `BurpExtender` 两处)。可读性/可测性提升,`threads` 与现有 static 方法/`Unsafe.allocateInstance` 测试不受影响。

### 构建(Build)
- 构建系统由 Gradle 迁移至 Maven:新增 `pom.xml`,移除 `build.gradle`。
- `maven-shade-plugin`(替代 Shadow)打 fat jar,`maven-surefire-plugin 3.5.2` 运行 JUnit 5 测试。
- 构建命令:`mvn clean package` → `target/RouteVulScan-1.6.0.jar`。
- 清理 Gradle 残留目录:`build/`、`.gradle/`、`lib/`(rt.jar 已于 1.6.0 移除);`.gitignore` 新增 `lib`。
- **Java 字节码目标 1.8 → 21**:Burp 自 2024.2.1 起最低内置 JRE 即为 Java 21(最新版已捆绑 Java 26),1.8 兼容理由已失效。升级后字节码主版本号 = 65,消除全部 "源值/目标值 8 已过时" 编译警告(WARNING 13 → 7)。

### 测试(Tests)
- 单元测试 49 → 61 例(全绿):新增 `StatusCodeProcTest`(`any`/`*`/`null`/乱码)、`ProcTemplateLanguagTest`(`{{request}}`/`{{request.head}}` 越界守卫)、`SafeParseIdTest`(Integer/String/空白/非数字/null)。

## [1.6.0] - 2026-06-13

### 修复(Fixes)
- **POST 请求转换失效**:`vulscan` 中以 `==` 比较字符串导致 POST→GET 转换恒不生效,改为 `"POST".equals(...)`。
- **线程池泄漏与竞态**:重构 `vulscan` 线程池生命周期——按次扫描创建私有池并在 `finally` 中 `shutdown()`;层间等待由忙等待(`Thread.sleep` + `shutdownNow` + 重建池)改为 `Future.get(30s)` 超时仅取消单个任务,消除池反复重建导致的线程泄漏。移除 `BurpExtender`、右键菜单中对共享 `ThreadPool` 的重复赋值。
- **共享请求头被多线程就地修改**:`threads` 任务内对共享 `heads` 列表的 `remove/add` 会互相污染并破坏原始头,改为每线程拷贝一份再修改。
- **header 解析崩溃**:`vulscan.AnalysisHeaders` 与 `Bfunc.ProceHead` 在遇到无冒号的畸形头行时 `substring(0,-1)` 崩溃,改为跳过非法行;`ProceHead` 不再假设冒号后必有一个空格(`Host:xxx` 等场景不再丢首字符)。
- **去重容器无上限**:`history_url` 由 `LinkedList` 改为 `ConcurrentHashMap.newKeySet()`,新增 `MAX_HISTORY_URL = 50000` 上限,避免长会话内存膨胀。

### 变更(Changed)
- **解除 JDK 8 / 内部 API 耦合**:`threads` 由 `implements com.sun.jmx.snmp.tasks.Task`(JDK 内部类,导致必须 JDK 8 编译)改为 `implements Runnable`;移除捆绑的 68 MB `lib/rt.jar`。项目现可在 JDK 21 编译。
- **在线规则更新性能**:`YamlUtil.MergerUpdateYamlFunc` 消除循环内重复读文件(O(n²) → 单次读写)。
- 清理死代码(`Bfunc.AnalyHost` 未使用变量)与废弃 API(`new Integer(...)` → 自动装箱)。

### 构建(Build)
- 升级 Shadow 插件 `com.github.johnrengelman.shadow:5.2.0` → `com.gradleup.shadow:8.3.1`,以兼容 Gradle 9 / JDK 21。
- 依赖配置由已移除的 `compile` 改为 `implementation`;删除 `lib` 目录的 `fileTree`。
- 设定 Java 8 字节码目标(`sourceCompatibility` / `targetCompatibility = 1.8`)以兼容 Burp 内置 JRE。
- JUnit 由 `5.7.0` 升至 `5.10.2`,并显式声明 `junit-platform-launcher:1.10.2`(5.7 在 Gradle 9 的 launcher 下无法启动)。

### 测试(Tests)
- 新增 8 个 JUnit 5 纯函数单元测试(共 49 例全绿),覆盖 `StatusCodeProc`、`AnalyHost`、`ProceHead`、`AnalysisHeaders`、`AnalysisHost`、`CustomHelpers.isJson`、`UrlRepeat`,以及模板替换 `ProcTemplateLanguag`(用 JDK `Unsafe`/`Proxy` 桩,零外部依赖)。

## [1.5.4] - 2024-03-07
- 展示面板加入排序,优化 bypass 功能。
