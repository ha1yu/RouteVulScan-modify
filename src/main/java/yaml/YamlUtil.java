package yaml;

import burp.BurpExtender;
import func.init_Yaml_thread;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import javax.swing.*;
import java.io.*;
import java.util.*;

public class YamlUtil {

    // 反序列化统一走安全构造器,杜绝 CVE-2022-1471(默认 Constructor 可触发任意类构造)。
    // 2.0+ 默认 new Yaml() 已继承 SafeConstructor,这里显式传入以表明意图、不依赖版本默认行为。
    private static final SafeConstructor SAFE_CONSTRUCTOR = new SafeConstructor(new LoaderOptions());

    public static void init_Yaml(BurpExtender burp, JPanel one) {
        new init_Yaml_thread(burp, one).start();

    }

    public static Map<String, Object> readYaml(String file_path) {
        File file = new File(file_path);
        Map<String, Object> data = null;
        try {
            InputStream inputStream = new FileInputStream(file);
            Yaml yaml = new Yaml(SAFE_CONSTRUCTOR);
            data = yaml.load(inputStream);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return data;
    }

    public static void writeYaml(Map<String, Object> data, String filePath) {
        Yaml yaml = new Yaml();
        try {
            PrintWriter writer = new PrintWriter(new File(filePath));
            yaml.dump(data, writer);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void removeYaml(String id, String filePath) {
        Map<String, Object> Yaml_Map = YamlUtil.readYaml(filePath);
        List<Map<String, Object>> List1 = (List<Map<String, Object>>) Yaml_Map.get("Load_List");
        ArrayList<Map<String, Object>> List2 = new ArrayList<Map<String, Object>>();
        for (Map<String, Object> zidian : List1) {
            if (!zidian.get("id").toString().equals(id)) {
                List2.add(zidian);
            }
        }
        Map<String, Object> save = (Map<String, Object>) new HashMap<String, Object>();
        save.put("Load_List", List2);
        save.put("Bypass_List", Yaml_Map.get("Bypass_List"));
        YamlUtil.writeYaml(save, filePath);
    }

    public static void updateYaml(Map<String, Object> up, String filePath) {
        Map<String, Object> Yaml_Map = YamlUtil.readYaml(filePath);
        List<Map<String, Object>> List1 = (List<Map<String, Object>>) Yaml_Map.get("Load_List");
        List<Map<String, Object>> List2 = new ArrayList<Map<String, Object>>();
        for (Map<String, Object> zidian : List1) {
            if (zidian.get("id").toString().equals(up.get("id").toString())) {
                List2.add(up);
            } else {
                List2.add(zidian);
            }
        }
        Map<String, Object> save = (Map<String, Object>) new HashMap<String, Object>();
        save.put("Load_List", List2);
        save.put("Bypass_List", Yaml_Map.get("Bypass_List"));
        YamlUtil.writeYaml(save, filePath);

    }

    public static void addYaml(Map<String, Object> add, String filePath) {
        Map<String, Object> Yaml_Map = YamlUtil.readYaml(filePath);
        List<Map<String, Object>> List1 = (List<Map<String, Object>>) Yaml_Map.get("Load_List");
        int panduan = 0;
        for (Map<String, Object> zidian : List1) {
            if (zidian.get("id").toString().equals(add.get("id").toString())) {
                panduan += 1;
            }
        }
        if (panduan == 0) {
            Map<String, Object> save = (Map<String, Object>) new HashMap<String, Object>();
            List1.add(add);
            save.put("Load_List", List1);
            save.put("Bypass_List", Yaml_Map.get("Bypass_List"));
            YamlUtil.writeYaml(save, filePath);
        }

    }

    public static Map<String, Object> readStrYaml(String str){
        Map<String, Object> data = null;
        Yaml yaml = new Yaml(SAFE_CONSTRUCTOR);
        // 剥掉开头的 BOM。两种形态都要处理:
        //   1) 标准 \uFEFF(UTF-8 正确解码后的单字符 BOM)
        //   2) U+00EF U+00BB U+00BF(Latin-1 误解码后的三字符 BOM,即 bytesToString 默认字符集导致)
        // SnakeYAML 2.x 会把这些当作非法 special characters 拒绝。
        if (str != null) {
            while (!str.isEmpty()) {
                char c0 = str.charAt(0);
                if (c0 == '\uFEFF') {
                    str = str.substring(1);
                } else if (str.length() >= 3 && c0 == '\u00EF' && str.charAt(1) == '\u00BB' && str.charAt(2) == '\u00BF') {
                    str = str.substring(3);
                } else {
                    break;
                }
            }
        }
        data = yaml.load(str);
        return data;
    }


    public static void MergerUpdateYamlFunc(Map<String, Object> newYaml){
        // 覆盖模式:完全以远程仓库为最高标准,本地文件 = 远程文件。
        // 不再做合并追加(旧逻辑会把本地自定义规则和远程规则去重合并,
        // 导致远程删改的规则在本地仍残留,且远程新增字段如 filter_host/black_host
        // 在旧本地文件缺失时无法补齐)。
        Map<String, Object> save = new HashMap<String, Object>();

        // Load_List:用远程规则覆盖,重新分配连续 id(1,2,3...)
        List<Map<String, Object>> newYamlList = (List<Map<String, Object>>)newYaml.get("Load_List");
        if (newYamlList == null) {
            newYamlList = new ArrayList<Map<String, Object>>();
        }
        int id = 0;
        for (Map<String, Object> rule : newYamlList) {
            id += 1;
            rule.put("id", id);
        }
        save.put("Load_List", newYamlList);

        // Bypass_List / filter_host / black_host:全部以远程为准
        save.put("Bypass_List", newYaml.get("Bypass_List"));
        if (newYaml.get("filter_host") != null) {
            save.put("filter_host", newYaml.get("filter_host"));
        }
        if (newYaml.get("black_host") != null) {
            save.put("black_host", newYaml.get("black_host"));
        }

        YamlUtil.writeYaml(save, BurpExtender.Yaml_Path);
    }

    public static boolean inYamlList(List<Map<String, Object>> mapList,Map<String, Object> oneMap){
        for (Map<String, Object> i : mapList){
            if (YamlUtil.ifmapEqual(i,oneMap)){
                return true;
            }
        }
        return false;

    }

    public static boolean ifmapEqual(Map<String, Object> i, Map<String, Object> oneMap){
        boolean mapEqual = true;
        for (String key : i.keySet()){
            if (!key.equals("loaded") && !key.equals("id") && !key.equals("type")){
                // null 安全比较:任一侧为 null 时,只有两侧都 null 才算相等,避免 NPE
                Object v1 = i.get(key);
                Object v2 = oneMap.get(key);
                if (v1 == null ? v2 != null : !v1.equals(v2)) {
                    mapEqual = false;
                    break;
                }
            }
        }
        return mapEqual;
    }


    /**
     * 把任意类型的 id 安全转为 int;无法解析(含 null、空串、非数字)时返回 -1,
     * 调用方按"跳过该条"处理。
     *
     * <p>统一 id 在 YAML(Integer)、内存 LogEntry(String)、UI 输入(String)间的类型差异,
     * 替代散落各处的 {@code (int) cast} / {@code Integer.parseInt},避免 ClassCastException / NumberFormatException。
     */
    public static int safeParseId(Object idObj) {
        if (idObj == null) {
            return -1;
        }
        try {
            return Integer.parseInt(String.valueOf(idObj).trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }



}


