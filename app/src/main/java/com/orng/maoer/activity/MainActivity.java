package com.orng.maoer.activity;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Button;
import android.widget.Toast;

import androidx.fragment.app.FragmentActivity;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.jingle.hook.R;
import com.orng.maoer.utils.LogUtils;

public class MainActivity extends FragmentActivity {
    public static String packageName = "com.tencent.tmgp.pubgmhd";
    private Button start;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initView();
    }

    private void initView() {
        start = findViewById(R.id.start);
        start.setOnClickListener(v -> inject(packageName));
    }

    public static byte[] readInputStream(InputStream ins, boolean close) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            int i = -1;
            byte[] buf = new byte[1024];
            while ((i = ins.read(buf)) != -1) {
                bos.write(buf, 0, i);
            }
            if (close) {
                ins.close();
                bos.close();
            }
            return bos.toByteArray();
        } catch (Throwable th) {
            return Log.getStackTraceString(th).getBytes();
        }
    }


    public static String shell(String command, boolean isRoot) {
        try {
            Process process = Runtime.getRuntime().exec(isRoot ? "su -mm" : "sh");
            InputStream ins = process.getInputStream();
            InputStream es = process.getErrorStream();
            OutputStream ous = process.getOutputStream();
            ous.write("\n".getBytes());
            ous.flush();
            ous.write(command.getBytes());
            ous.flush();
            ous.write("\n".getBytes());
            ous.flush();
            ous.write("exit".getBytes());
            ous.flush();
            ous.write("\n".getBytes());
            ous.flush();
            byte[] result = readInputStream(ins, false);
            byte[] error = readInputStream(es, false);
            process.waitFor();
            ins.close();
            es.close();
            ous.close();
            if (new String(error).trim().isEmpty()) {
                return new String(result);
            } else {
                String msg = "Shell Result : \n" + new String(result) + "\n" + "Shell Error : \n" + new String(error) + "\n";
                return msg;
            }
        } catch (Throwable th) {

            return "Application Error : \n" + Log.getStackTraceString(th);
        }
    }

    private void copyFile(String from, String to) {
        shell("cp -f " + from + " " + to, true);
    }

    private void loadAssets(String sock) {
        String pathf = getFilesDir().toString() + "/" + sock;
        try {
            OutputStream myOutput = new FileOutputStream(pathf);
            byte[] buffer = new byte[1024];
            int length;
            InputStream myInput = getAssets().open(sock);
            while ((length = myInput.read(buffer)) > 0) {
                myOutput.write(buffer, 0, length);
            }
            myInput.close();
            myOutput.flush();
            myOutput.close();
        } catch (IOException e) {
        }
        String Path = getFilesDir().toString() + "/" + sock;
        try {
            Runtime.getRuntime().exec("chmod 777 " + Path);
        } catch (IOException e) {
        }
    }

    private void inject(String packageName) {

        String libName = "libnative-lib.so";
        String libName2 = "ptrace";
        String injectPath2 = "/data/data/" + packageName + "/cache/";
        loadAssets(libName2);
        shell("mkdir -p " + injectPath2, true);
        copyFile(getFilesDir().toString() + "/" + libName2, injectPath2 + "/" + libName2);
        shell("chmod -R 0777 " + injectPath2, true);
        if (!shell("ls " + injectPath2, true).contains(libName2)) {
            Toast.makeText(this, "初始化环境失败！", Toast.LENGTH_LONG).show();
            return;
        }
        shell("setenforce 0", true);
        //copy so
        copyFile(getApplicationInfo().nativeLibraryDir + "/" + libName, injectPath2 + "/" + libName);
        //chmod
        shell("chmod -R 0777 " + injectPath2 + "/*", true);
        //force stop
        shell("am force-stop " + packageName, true);

        shell("am start com.tencent.tmgp.pubgmhd/com.epicgames.ue4.SplashActivity", true);

        new Thread(() -> new Handler(Looper.getMainLooper()).post(() -> {
            try {
                Thread.sleep(3000);
                LogUtils.E("GameInject", packageName);
                String ret = shell("cd " + injectPath2 + " &&./" + libName2 + " -n " + packageName + " -so " + injectPath2 + libName, true);

          /*      shell("rm -r " + getFilesDir().toString() + "/*", true);
                shell("rm -r " + injectPath2 + libName, true);
                shell("rm -r " + injectPath2 + libName2, true);
                shell("rm -r /data/local/tmp/*", true);
                shell("rm -r " + injectPath2 + "*", true);*/
                start.setText("完成");
            } catch (InterruptedException e) {
                start.setText("异常");
                e.printStackTrace();
            }
        })).start();
    }
}





