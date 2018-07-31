package com.very.shuai;

import java.util.List;

import android.app.ActivityManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class BootReceiver extends BroadcastReceiver {

	@Override
	public void onReceive(Context context, Intent arg1) {
		// TODO Auto-generated method stub

		boolean isRun = isServiceRun(context, "com.very.shuai.SmSserver");
		Log.i("phone", "server_"+isRun);
		if(!isRun){
			Intent intent=new Intent(context,SmSserver.class);
			intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
			context.startService(intent);
		}
	}

	public static boolean isServiceRun(Context mContext, String className) {
		boolean isRun = false;
		ActivityManager activityManager = (ActivityManager) mContext
			.getSystemService(Context.ACTIVITY_SERVICE);
		List<ActivityManager.RunningServiceInfo> serviceList = activityManager
			.getRunningServices(40);
		int size = serviceList.size();
		for (int i = 0; i < size; i++) {
			if (serviceList.get(i).service.getClassName().equals(className) == true) {
				isRun = true;
				break;
			}
		}
		return isRun;
	}

}

//源码群494564275