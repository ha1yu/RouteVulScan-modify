# 更新日志 / Changelog

本文件记录 RouteVulScan 的重要变更,格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)。

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
