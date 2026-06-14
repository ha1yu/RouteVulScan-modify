package burp;


import func.vulscan;
import yaml.YamlUtil;

import javax.swing.*;
import java.util.*;
import java.util.regex.Pattern;

public class Bfunc {

    public static Map<String, View> Get_Views() {
        Map<String, View> views = new Hashtable<String, View>();
        Map<String, Object> jieguo = YamlUtil.readYaml(BurpExtender.Yaml_Path);
        List<Map<String, Object>> rule_list = (List<Map<String, Object>>) jieguo.get("Load_List");
        for (Map<String, Object> zidian : rule_list) {
            String type = (String) zidian.get("type");
            String id = String.valueOf(zidian.get("id"));
            String name = (String) zidian.get("name");
            String url = (String) zidian.get("url");
            String re = (String) zidian.get("re");
            String info = (String) zidian.get("info");
            String state = (String) zidian.get("state");
            String method = (String) zidian.get("method");
            boolean loaded = Boolean.parseBoolean(String.valueOf(zidian.get("loaded")));

            if (type == null && !loaded) {
                zidian.put("type", "default");
                zidian.put("loaded", true);
                YamlUtil.updateYaml(zidian, BurpExtender.Yaml_Path);
                type = "default";
                loaded = true;
            }

            if (views.containsKey(type)) {
                View view_one = views.get(type);
                view_one.log.add(new View.LogEntry(id, type, loaded, name, method, url, re, info, state));
                views.put(type, view_one);
            } else {
                View view_one = new View();
                view_one.log.add(new View.LogEntry(id, type, loaded, name, method, url, re, info, state));
                views.put(type, view_one);
            }
        }
        return views;

    }

    public static void show_yaml_view(BurpExtender burp, View view, String type) {
        if (view == null) {
            show_yaml(burp);
        } else {
            List<View.LogEntry> log = view.log;
            synchronized (log) {
                log.clear();
                int row = log.size();
                Map<String, Object> Dict_Yaml = YamlUtil.readYaml(BurpExtender.Yaml_Path);
                List<Map<String, Object>> rule_list = (List<Map<String, Object>>) Dict_Yaml.get("Load_List");
                for (Map<String, Object> zidian : rule_list) {
                    String type2 = String.valueOf(zidian.get("type"));
                    if (type2.equals(type)) {
                        String id = String.valueOf(zidian.get("id"));
                        boolean loaded = Boolean.parseBoolean(String.valueOf(zidian.get("loaded")));
                        String name = (String) zidian.get("name");
                        String url = (String) zidian.get("url");
                        String re = (String) zidian.get("re");
                        String info = (String) zidian.get("info");
                        String state = (String) zidian.get("state");
                        String method = (String) zidian.get("method");
                        log.add(new View.LogEntry(id, type, loaded, name, method, url, re, info, state));
                        view.fireTableRowsInserted(row, row);
                    }
                }
            }
//            burp.views = Get_Views();
        }
    }

    public static void show_yaml(BurpExtender burp) {
        burp.views = Get_Views();
        burp.Config_l.ruleTabbedPane.removeAll();
        for (String key : burp.views.keySet()) {
            burp.Config_l.ruleTabbedPane.addTab(key, burp.views.get(key).Get_View());
        }
        burp.Config_l.ruleTabbedPane.addTab("...", new JLabel());


    }

    public static Collection<Integer> StatusCodeProc(String state){
        // null/空串:无法判定,返回空集合(规则静默失效,不崩溃)
        if (state == null || state.trim().isEmpty()) {
            return new ArrayList<Integer>();
        }
        String trimmed = state.trim();
        Collection<Integer> stateList = new ArrayList<Integer>();
        // any/all/* 视为匹配全部 HTTP 状态码(让 Config UI 默认占位 "any" 真正生效)
        if (trimmed.equalsIgnoreCase("any") || trimmed.equals("*") || trimmed.equalsIgnoreCase("all")) {
            for (int i = 100; i <= 599; i++) {
                stateList.add(i);
            }
            return stateList;
        }
        if (state.length() != 3 && (state.contains(",") || state.contains("-"))){
            if (state.contains(",")){
                String[] states = state.split(",");
                for (String OneState:states){
                    if (OneState.contains("-")){
                        String[] parts = OneState.split("-");
                        try {
                            int start = Integer.parseInt(parts[0]);
                            int end = Integer.parseInt(parts[1]);
                            for (int i = start; i <= end; i++) {
                                stateList.add(i);
                            }
                        } catch (NumberFormatException ignore) {
                            // 范围格式非法(如 "abc-def"),跳过该段
                        }
                    }else if (OneState.length() == 3){
                        try {
                            stateList.add(Integer.valueOf(OneState));
                        } catch (NumberFormatException ignore) {
                            // 单值非数字,跳过
                        }
                    }
                }
            }else if (state.contains("-")){
                String[] parts = state.split("-");
                try {
                    int start = Integer.parseInt(parts[0]);
                    int end = Integer.parseInt(parts[1]);
                    for (int i = start; i <= end; i++) {
                        stateList.add(i);
                    }
                } catch (NumberFormatException ignore) {
                    // 范围格式非法,返回空集合
                }
            }
        }else {
            try {
                stateList.add(Integer.valueOf(trimmed));
            } catch (NumberFormatException ignore) {
                // 兜底:非数字(如 "any" 以外的乱码)返回空集合,规则静默失效而非崩溃整个扫描线程
            }
        }
        return stateList;

    }



    public static String ProcTemplateLanguag(String url, IHttpRequestResponse HttpRequestResponse, vulscan vul,Boolean escape){



        if (url.contains("{{") && url.contains("}}")){
            String marking = url.substring(url.indexOf("{{"), url.lastIndexOf("}}") + 2);
            String markingContent = marking.replace("{{", "").replace("}}", "").toLowerCase();
            String[] parts = markingContent.split("\\.");
            // 守卫:形如 {{request}}(无子键)直接原样返回,避免访问 parts[1] 越界
            if (parts.length < 2) {
                return url;
            }
            IHttpService httpservice = HttpRequestResponse.getHttpService();
            switch (parts[0]){
                case "request":
                    IRequestInfo request = vul.burp.help.analyzeRequest(HttpRequestResponse);
                    switch (parts[1]){
                        case "head":
                            // {{request.head}}(无 header 名)无法取值,原样返回
                            if (parts.length < 3) {
                                return url;
                            }
                            Map<String, String> heads = Bfunc.ProceHead(request.getHeaders());
                            if (parts[2].equals("host") && parts.length >3){
                                switch (parts[3]){
                                    case "main":
                                        return replaceOn(url,marking,Bfunc.AnalyHost(heads.get("host"),"main"),escape);
                                    case "name":
                                        return replaceOn(url,marking,Bfunc.AnalyHost(heads.get("host"),"name"),escape);
                                }
                            }
                            return replaceOn(url,marking,heads.get(parts[2]),escape);
                        case "method":
                            return replaceOn(url,marking,request.getMethod(),escape);
                        case "path":
                            return replaceOn(url,marking,request.getUrl().getPath().substring(1),escape);
                        case "url":
                            return replaceOn(url,marking,request.getUrl().toString(),escape);
                        case "protocol":
                            return replaceOn(url,marking,httpservice.getProtocol(),escape);
                        case "port":
                            return replaceOn(url,marking,String.valueOf(httpservice.getPort()),escape);
                    }

                case "response":
                    byte[] xiangying = HttpRequestResponse.getResponse();
                    if (xiangying != null){
                        IResponseInfo response = vul.burp.help.analyzeResponse(xiangying);
                        switch (parts[1]){
                            case "head":
                                // {{response.head}}(无 header 名)无法取值,原样返回
                                if (parts.length < 3) {
                                    return url;
                                }
                                Map<String, String> heads = Bfunc.ProceHead(response.getHeaders());
                                return replaceOn(url,marking,heads.get(parts[2]),escape);
                            case "status":
                                return replaceOn(url,marking,String.valueOf(response.getStatusCode()),escape);
                        }
                    }



            }

        }
            
            

        return url;
    }

    private static String replaceOn(String url,String one,String two,Boolean escape){
        if (two != null) {
            if (escape) {
                return url.replace(one, Pattern.quote(two));
            } else {
                return url.replace(one, two);
            }
        }
        return url.replace(one, "");
    }

    public static String AnalyHost(String host, String mode){
        String domain = host.split(":")[0];
        if (host.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$")) {
            return host;
        }
        String[] parts = domain.split("\\.");

        if (parts[parts.length-1].equals("cn") && parts[parts.length-2].equals("com")){
            if (mode.equals("main")){
                domain = parts[parts.length-3] + "." + parts[parts.length-2] + "." + parts[parts.length-1];
                return domain;
            }else if(mode.equals("name")){
                return parts[parts.length - 3];
            }

        }else {
            if (mode.equals("main")){
                domain = parts[parts.length-2] + "." + parts[parts.length-1];
                return  domain;
            }else if(mode.equals("name")){
                return parts[parts.length - 2];
            }

        }
        return domain;
    }


    public static Map<String,String> ProceHead(List<String> heads){
        heads.remove(heads.get(0));
        Map<String,String> headmap = new HashMap<String,String>();
        for (String head:heads){
            int idx = head.indexOf(":");
            if (idx < 0) {
                // 不含冒号的非法头行,跳过避免 substring 崩溃
                continue;
            }
            String key = head.substring(0, idx).trim().toLowerCase();
            String value = head.substring(idx + 1).trim();
            headmap.put(key,value);
        }
        return headmap;

    }



}
