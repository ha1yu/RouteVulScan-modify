package func;

import burp.*;
import yaml.YamlUtil;

import javax.swing.*;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

public class init_Yaml_thread extends Thread {
    private BurpExtender burp;
    private JPanel one;

    public init_Yaml_thread(BurpExtender burp, JPanel one) {
        this.burp = burp;
        this.one = one;


    }

    public void run() {

        URL Url = null;
        try {
            Url = new URL(BurpExtender.Download_Yaml_protocol, BurpExtender.Download_Yaml_host, BurpExtender.Download_Yaml_port, BurpExtender.Download_Yaml_file);

            byte[] request = this.burp.help.buildHttpRequest(Url);
            byte[] YamlResponse = this.burp.call.makeHttpRequest(BurpExtender.Download_Yaml_host, BurpExtender.Download_Yaml_port, true, request);

            if (YamlResponse != null) {
                IResponseInfo AnalyzeYamlResponse = this.burp.help.analyzeResponse(YamlResponse);
                // 用 UTF-8 解码 body(而非 bytesToString 的默认字符集),否则中文规则名会乱码,
                // 且 BOM 会变成 3 个 Latin-1 字符 U+EF/BB/BF,SnakeYAML 2.x 会拒绝。
                String ResponseBody = new String(YamlResponse, java.nio.charset.StandardCharsets.UTF_8).substring(AnalyzeYamlResponse.getBodyOffset());

                Map<String, Object> NewYaml = YamlUtil.readStrYaml(ResponseBody);
                YamlUtil.MergerUpdateYamlFunc(NewYaml);

//                FileOutputStream file = new FileOutputStream(BurpExtender.Yaml_Path);
//                file.write(this.burp.help.stringToBytes(ResponseBody));
//                file.close();

                Bfunc.show_yaml(burp);
                // 刷新 host 过滤输入框(Update 会重写 yaml,需让 UI 反映最新值)
                Map<String, Object> persisted = YamlUtil.readYaml(BurpExtender.Yaml_Path);
                if (persisted != null) {
                    Object filterHost = persisted.get("filter_host");
                    Object blackHost = persisted.get("black_host");
                    this.burp.Host_txtfield.setText(filterHost != null ? String.valueOf(filterHost) : "*");
                    this.burp.Black_Host_txtfield.setText(blackHost != null ? String.valueOf(blackHost) : "");
                }
                JOptionPane.showMessageDialog(one, "Update successful", "Tips ", 1);
            } else {
                JOptionPane.showMessageDialog(one, "Request failed, please try to use proxy", "Error ", 0);
            }
        } catch (MalformedURLException e) {
            JOptionPane.showMessageDialog(one, "URL creation failed", "Error ", 0);
        } catch (Exception e) {
            // 兜底:任何其它异常(网络/解析/IO)都要给用户可见反馈,避免静默失败
            // 同时把响应体前 80 字符的 codepoint 打到 Burp output,便于定位特殊字符
            StringBuilder diag = new StringBuilder();
            diag.append("Update failed: ").append(e.getClass().getSimpleName()).append(" - ").append(e.getMessage());
            try {
                byte[] req = this.burp.help.buildHttpRequest(new URL(BurpExtender.Download_Yaml_protocol, BurpExtender.Download_Yaml_host, BurpExtender.Download_Yaml_port, BurpExtender.Download_Yaml_file));
                byte[] resp = this.burp.call.makeHttpRequest(BurpExtender.Download_Yaml_host, BurpExtender.Download_Yaml_port, true, req);
                if (resp != null) {
                    int bodyOff = this.burp.help.analyzeResponse(resp).getBodyOffset();
                    String body = this.burp.help.bytesToString(resp).substring(bodyOff);
                    StringBuilder cps = new StringBuilder("body codepoints[0..80]: ");
                    for (int i = 0; i < Math.min(80, body.length()); i++) {
                        cps.append("U+").append(Integer.toHexString(body.charAt(i)).toUpperCase()).append(" ");
                    }
                    this.burp.call.printError(cps.toString());
                    this.burp.call.printError("body length: " + body.length());
                }
            } catch (Exception ignore) {}
            this.burp.call.printError(diag.toString());
            e.printStackTrace();
            JOptionPane.showMessageDialog(one, diag.toString(), "Error ", 0);
        }


    }
}
