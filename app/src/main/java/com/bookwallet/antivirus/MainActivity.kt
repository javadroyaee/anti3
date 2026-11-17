package com.bookwallet.antivirus

import android.Manifest
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.provider.Telephony
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.*
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

data class ThreatItem(
    val title: String,
    val description: String,
    val type: String, // "APP", "FILE", "SMS", "WIFI"
    val targetPathOrPackage: String,
    val isHighRisk: Boolean
)

class MainActivity : AppCompatActivity() {

    private lateinit var tvSubscriptionBadge: TextView
    private lateinit var tvStatusTitle: TextView
    private lateinit var tvStatusSub: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var btnSmartScan: Button
    private lateinit var recyclerResults: RecyclerView

    private val threatList = mutableListOf<ThreatItem>()
    private lateinit var adapter: ThreatAdapter

    private val PAY_URL = "https://jrweb.ir/wp-json/bookwallet/v1/pay"
    private val VERIFY_URL = "https://jrweb.ir/wp-json/bookwallet/v1/verify"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initViews()
        requestAllSecurityPermissions()
        handleIncomingIntents(intent)
        refreshSubscriptionStatus()
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        intent?.let { handleIncomingIntents(it) }
    }

    private fun initViews() {
        tvSubscriptionBadge = findViewById(R.id.tvSubscriptionBadge)
        tvStatusTitle = findViewById(R.id.tvStatusTitle)
        tvStatusSub = findViewById(R.id.tvStatusSub)
        progressBar = findViewById(R.id.progressBar)
        btnSmartScan = findViewById(R.id.btnSmartScan)
        recyclerResults = findViewById(R.id.recyclerResults)

        adapter = ThreatAdapter(threatList) { item ->
            handleItemAction(item)
        }
        recyclerResults.layoutManager = LinearLayoutManager(this)
        recyclerResults.adapter = adapter

        btnSmartScan.setOnClickListener { runFullSecurityScan() }
        findViewById<CardView>(R.id.cardScanApps).setOnClickListener { scanInstalledAppsAndMalware() }
        findViewById<CardView>(R.id.cardSmsGuard).setOnClickListener { scanSmsInboxForLinks() }
        findViewById<CardView>(R.id.cardNetworkGuard).setOnClickListener { inspectWifiAndNetwork() }
        findViewById<CardView>(R.id.cardScanFiles).setOnClickListener { scanFilesAndPhotos() }
        findViewById<CardView>(R.id.cardPermissions).setOnClickListener { checkUnreasonablePermissions() }
        findViewById<CardView>(R.id.cardActivate).setOnClickListener { showActivationDialog() }

        findViewById<Button>(R.id.menuHome).setOnClickListener { runFullSecurityScan() }
        findViewById<Button>(R.id.menuSms).setOnClickListener { scanSmsInboxForLinks() }
        findViewById<Button>(R.id.menuWifi).setOnClickListener { inspectWifiAndNetwork() }
        findViewById<Button>(R.id.menuPerms).setOnClickListener { checkUnreasonablePermissions() }
    }

    private fun requestAllSecurityPermissions() {
        val permsToRequest = mutableListOf<String>()
        val required = arrayOf(
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_SMS,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
        )
        for (p in required) {
            if (ContextCompat.checkSelfPermission(this, p) != PackageManager.PERMISSION_GRANTED) {
                permsToRequest.add(p)
            }
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
                permsToRequest.add(Manifest.permission.READ_EXTERNAL_STORAGE)
                permsToRequest.add(Manifest.permission.WRITE_EXTERNAL_STORAGE)
            }
        }
        if (permsToRequest.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, permsToRequest.toTypedArray(), 100)
        }

        // مجوز نمایش فوری هشدار روی صفحه هنگام دریافت پیامک لینک‌دار
        if (!Settings.canDrawOverlays(this)) {
            try {
                val overlayIntent = Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName"))
                startActivity(overlayIntent)
            } catch (_: Exception) {
            }
        }

        // مجوز دسترسی کامل به فایل‌ها برای اسکن حافظه
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
            try {
                val storageIntent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName"))
                startActivity(storageIntent)
            } catch (_: Exception) {
            }
        }
    }

    private fun handleIncomingIntents(intent: Intent) {
        // ۱. اگر پیامک مشکوک حاوی لینک همین الان دریافت شده باشد، فوراً پنجره هشدار نشان بده
        if (intent.getBooleanExtra("PHISHING_ALERT", false)) {
            val sender = intent.getStringExtra("SMS_SENDER") ?: "ناشناس"
            val body = intent.getStringExtra("SMS_BODY") ?: ""
            val reason = intent.getStringExtra("SMS_REASON") ?: "لینک مشکوک شناسایی شد"

            AlertDialog.Builder(this)
                .setTitle("⚠️ هشدار امنیتی: پیامک حاوی لینک مشکوک!")
                .setMessage("فرستنده: $sender\n\nدلیل هشدار: $reason\n\nمتن پیامک:\n$body\n\nتوصیه می‌شود به هیچ وجه روی لینک داخل این پیامک کلیک نکنید.")
                .setPositiveButton("متوجه شدم (مسدودسازی)", null)
                .setNeutralButton("مشاهده همه پیامک‌های مشکوک") { _, _ -> scanSmsInboxForLinks() }
                .show()
        }

        // ۲. بازگشت از درگاه پرداخت
        val data: Uri? = intent.data
        if (data != null && data.scheme == "bookwallet" && data.host == "activate") {
            val phone = data.getQueryParameter("phone") ?: getSavedPhone()
            val status = data.getQueryParameter("status")
            if (!phone.isNullOrEmpty()) saveUserPhone(phone)
            if (status == "success") {
                setActivated(true)
                Toast.makeText(this, "پرداخت موفق! تمام سپرهای امنیتی فعال شدند.", Toast.LENGTH_LONG).show()
            }
            refreshSubscriptionStatus()
        }
    }

    // اسکن جامع (مشابه Smart Scan در ESET)
    private fun runFullSecurityScan() {
        threatList.clear()
        adapter.notifyDataSetChanged()
        progressBar.visibility = View.VISIBLE
        progressBar.progress = 10
        tvStatusTitle.text = "در حال انجام اسکن جامع نود امنیتی..."
        tvStatusSub.text = "بررسی شبکه، پیامک‌های لینک‌دار، بدافزارها و دسترسی‌ها"

        CoroutineScope(Dispatchers.IO).launch {
            val wifiReport = buildNetworkAuditItems()
            withContext(Dispatchers.Main) { progressBar.progress = 30 }

            val smsItems = performSmsScan()
            withContext(Dispatchers.Main) { progressBar.progress = 55 }

            val appItems = performAppMalwareScan()
            withContext(Dispatchers.Main) { progressBar.progress = 75 }

            val permItems = performPermissionAudit()
            withContext(Dispatchers.Main) { progressBar.progress = 90 }

            val fileItems = performFileAndPhotoScan()
            withContext(Dispatchers.Main) {
                progressBar.progress = 100
                progressBar.visibility = View.GONE
                threatList.addAll(wifiReport)
                threatList.addAll(smsItems)
                threatList.addAll(appItems)
                threatList.addAll(permItems)
                threatList.addAll(fileItems)
                adapter.notifyDataSetChanged()

                tvStatusTitle.text = "اسکن جامع تکمیل شد (${threatList.size} گزارش)"
                tvStatusSub.text = "نتایج بررسی شبکه، پیامک‌ها و فایل‌ها در لیست زیر نمایش داده شد."
            }
        }
    }

    // ۱. بررسی پیامک‌های دریافتی برای شناسایی لینک‌های خودکار و فیشینگ
    private fun scanSmsInboxForLinks() {
        threatList.clear()
        progressBar.visibility = View.VISIBLE
        progressBar.progress = 50
        tvStatusTitle.text = "در حال اسکن صندوق پیامک‌ها..."

        CoroutineScope(Dispatchers.IO).launch {
            val results = performSmsScan()
            withContext(Dispatchers.Main) {
                progressBar.visibility = View.GONE
                threatList.addAll(results)
                adapter.notifyDataSetChanged()
                tvStatusTitle.text = "بررسی پیامک‌ها تکمیل شد (${results.size} پیامک لینک‌دار)"
            }
        }
    }

    private fun performSmsScan(): List<ThreatItem> {
        val list = mutableListOf<ThreatItem>()
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_SMS) != PackageManager.PERMISSION_GRANTED) {
            list.add(ThreatItem("نیاز به مجوز پیامک", "برای شناسایی پیامک‌های لینک‌دار، مجوز خواندن SMS را تایید کنید.", "SMS", "", true))
            return list
        }

        try {
            val cursor = contentResolver.query(Telephony.Sms.Inbox.CONTENT_URI, arrayOf("address", "body"), null, null, "date DESC LIMIT 80")
            cursor?.use {
                val idxAddr = it.getColumnIndex("address")
                val idxBody = it.getColumnIndex("body")
                while (it.moveToNext()) {
                    val sender = it.getString(idxAddr) ?: "ناشناس"
                    val body = it.getString(idxBody) ?: ""
                    val analysis = PhishingAnalyzer.analyzeSms(sender, body)
                    if (analysis.isSuspicious) {
                        list.add(
                            ThreatItem(
                                title = "پیامک مشکوک از: $sender",
                                description = "${analysis.reason}\nمتن: ${body.take(90)}...",
                                type = "SMS",
                                targetPathOrPackage = body,
                                isHighRisk = true
                            )
                        )
                    }
                }
            }
        } catch (_: Exception) {
        }
        return list
    }

    // ۲. بازرس امنیت شبکه وای‌فای و اینترنت
    private fun inspectWifiAndNetwork() {
        threatList.clear()
        progressBar.visibility = View.VISIBLE
        progressBar.progress = 60
        tvStatusTitle.text = "در حال آنالیز امنیت وای‌فای و اینترنت..."

        CoroutineScope(Dispatchers.IO).launch {
            val results = buildNetworkAuditItems()
            withContext(Dispatchers.Main) {
                progressBar.visibility = View.GONE
                threatList.addAll(results)
                adapter.notifyDataSetChanged()
                tvStatusTitle.text = "بازرسی امنیت شبکه تکمیل شد"
            }
        }
    }

    private fun buildNetworkAuditItems(): List<ThreatItem> {
        val list = mutableListOf<ThreatItem>()
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork
        val caps = cm.getNetworkCapabilities(activeNetwork)

        if (caps == null) {
            list.add(ThreatItem("عدم اتصال به اینترنت", "دستگاه در حال حاضر به هیچ شبکه وای‌فای یا دیتای موبایل متصل نیست.", "WIFI", "", false))
            return list
        }

        val hasVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        if (hasVpn) {
            list.add(ThreatItem("هشدار تونل VPN / Proxy فعال", "ترافیک اینترنت شما از یک سرور واسط (VPN) عبور می‌کند؛ در هنگام تراکنش بانکی آن را خاموش کنید.", "WIFI", "", true))
        }

        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            @Suppress("DEPRECATION")
            val wifiInfo = wifiManager.connectionInfo
            @Suppress("DEPRECATION")
            val ssid = wifiInfo?.ssid?.replace("\"", "") ?: "شبکه وای‌فای"
            @Suppress("DEPRECATION")
            val ipInt = wifiInfo?.ipAddress ?: 0
            val ipStr = String.format("%d.%d.%d.%d", ipInt and 0xff, ipInt shr 8 and 0xff, ipInt shr 16 and 0xff, ipInt shr 24 and 0xff)

            var encryptionWarning = "رمزنگاری استاندارد WPA2/WPA3 برقرار است."
            var isRisk = false

            if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED) {
                @Suppress("DEPRECATION")
                val scanResults = wifiManager.scanResults
                val currentAp = scanResults.firstOrNull { it.SSID == ssid }
                val capStr = currentAp?.capabilities ?: ""
                if (capStr.contains("WEP") || (!capStr.contains("WPA") && !capStr.contains("RSN"))) {
                    encryptionWarning = "⚠️ خطر شنود بالا! این مودم فاقد رمز عبور یا دارای امنیت ضعیف (Open/WEP) است."
                    isRisk = true
                }
            }

            list.add(
                ThreatItem(
                    title = "بررسی وای‌فای متصل: $ssid",
                    description = "آی‌پی محلی: $ipStr | وضعیت امنیت: $encryptionWarning",
                    type = "WIFI",
                    targetPathOrPackage = "",
                    isHighRisk = isRisk
                )
            )
        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
            list.add(
                ThreatItem(
                    title = "اتصال از طریق اینترنت همراه (Mobile Data)",
                    description = "ارتباط مستقیم با اپراتور برقرار است و امنیت لایه انتقال در سطح مطلوب قرار دارد.",
                    type = "WIFI",
                    targetPathOrPackage = "",
                    isHighRisk = false
                )
            )
        }
        return list
    }

    // ۳. اسکن برنامه‌ها و بدافزارها
    private fun scanInstalledAppsAndMalware() {
        threatList.clear()
        progressBar.visibility = View.VISIBLE
        progressBar.progress = 50
        tvStatusTitle.text = "در حال اسکن برنامه‌های نصب‌شده..."

        CoroutineScope(Dispatchers.IO).launch {
            val results = performAppMalwareScan()
            withContext(Dispatchers.Main) {
                progressBar.visibility = View.GONE
                threatList.addAll(results)
                adapter.notifyDataSetChanged()
                tvStatusTitle.text = "اسکن برنامه‌ها تکمیل شد (${results.size} مورد)"
            }
        }
    }

    private fun performAppMalwareScan(): List<ThreatItem> {
        val list = mutableListOf<ThreatItem>()
        val pm = packageManager
        val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)

        for (appInfo in packages) {
            if ((appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0) continue
            if (appInfo.packageName == packageName) continue

            val appName = pm.getApplicationLabel(appInfo).toString()
            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(appInfo.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(appInfo.packageName)
            }

            val isUnknownSource = installer == null || (installer != "com.android.vending" && installer != "com.farsitel.bazaar" && installer != "ir.mservices.market")
            val hasSuspiciousKeyword = listOf("spy", "hack", "track", "keylog", "rat", "trojan", "adware").any {
                appInfo.packageName.lowercase().contains(it) || appName.lowercase().contains(it)
            }

            if (hasSuspiciousKeyword || isUnknownSource) {
                val reason = if (hasSuspiciousKeyword) "الگوی مشکوک به بدافزار یا جاسوس‌افزار" else "نصب شده از منبع ناشناس (خارج از مارکت‌های رسمی)"
                list.add(
                    ThreatItem(
                        title = "برنامه: $appName",
                        description = reason,
                        type = "APP",
                        targetPathOrPackage = appInfo.packageName,
                        isHighRisk = hasSuspiciousKeyword
                    )
                )
            }
        }
        return list
    }

    // ۴. بررسی منطقی بودن دسترسی‌ها
    private fun checkUnreasonablePermissions() {
        threatList.clear()
        progressBar.visibility = View.VISIBLE
        progressBar.progress = 50
        tvStatusTitle.text = "در حال تحلیل منطقی دسترسی‌ها..."

        CoroutineScope(Dispatchers.IO).launch {
            val results = performPermissionAudit()
            withContext(Dispatchers.Main) {
                progressBar.visibility = View.GONE
                threatList.addAll(results)
                adapter.notifyDataSetChanged()
                tvStatusTitle.text = "تحلیل دسترسی‌ها تکمیل شد (${results.size} مورد)"
            }
        }
    }

    private fun performPermissionAudit(): List<ThreatItem> {
        val list = mutableListOf<ThreatItem>()
        val pm = packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        for (pkgInfo in packages) {
            val appInfo = pkgInfo.applicationInfo ?: continue
            if ((appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0) continue
            if (pkgInfo.packageName == packageName) continue

            val appName = pm.getApplicationLabel(appInfo).toString()
            val perms = pkgInfo.requestedPermissions ?: continue

            val hasSms = perms.any { it.contains("READ_SMS") || it.contains("RECEIVE_SMS") }
            val hasContacts = perms.any { it.contains("READ_CONTACTS") }
            val hasCameraOrMic = perms.any { it.contains("CAMERA") || it.contains("RECORD_AUDIO") }
            val hasLocation = perms.any { it.contains("ACCESS_FINE_LOCATION") }

            val isUtilityApp = listOf("calc", "torch", "light", "clock", "alarm", "wallpaper", "theme", "note", "pdf", "reader", "book", "game", "player").any {
                pkgInfo.packageName.lowercase().contains(it) || appName.lowercase().contains(it)
            }

            if (isUtilityApp && (hasSms || hasContacts || hasCameraOrMic || hasLocation)) {
                val riskyList = mutableListOf<String>()
                if (hasSms) riskyList.add("خواندن پیامک‌ها")
                if (hasContacts) riskyList.add("مخاطبین")
                if (hasCameraOrMic) riskyList.add("دوربین/میکروفون")
                if (hasLocation) riskyList.add("موقعیت مکانی")

                list.add(
                    ThreatItem(
                        title = "دسترسی غیرمنطقی: $appName",
                        description = "این برنامه ابزار ساده است اما به [${riskyList.joinToString("، ")}] دسترسی دارد!",
                        type = "APP",
                        targetPathOrPackage = pkgInfo.packageName,
                        isHighRisk = true
                    )
                )
            } else if (hasSms && hasContacts && hasCameraOrMic) {
                list.add(
                    ThreatItem(
                        title = "دسترسی‌های حساس گسترده: $appName",
                        description = "دسترسی همزمان به پیامک، مخاطبین، دوربین و میکروفون.",
                        type = "APP",
                        targetPathOrPackage = pkgInfo.packageName,
                        isHighRisk = true
                    )
                )
            }
        }
        return list
    }

    // ۵. اسکن فایل‌ها و عکس‌ها
    private fun scanFilesAndPhotos() {
        threatList.clear()
        progressBar.visibility = View.VISIBLE
        progressBar.progress = 50
        tvStatusTitle.text = "در حال اسکن فایل‌ها و تصاویر..."

        CoroutineScope(Dispatchers.IO).launch {
            val results = performFileAndPhotoScan()
            withContext(Dispatchers.Main) {
                progressBar.visibility = View.GONE
                threatList.addAll(results)
                adapter.notifyDataSetChanged()
                tvStatusTitle.text = "اسکن فایل‌ها و عکس‌ها تکمیل شد (${results.size} مورد)"
            }
        }
    }

    private fun performFileAndPhotoScan(): List<ThreatItem> {
        val list = mutableListOf<ThreatItem>()
        val rootDir = Environment.getExternalStorageDirectory()
        val foldersToScan = listOf(
            File(rootDir, "Download"),
            File(rootDir, "DCIM"),
            File(rootDir, "Pictures"),
            File(rootDir, "Documents")
        )

        val dangerousExtensions = listOf(".apk", ".exe", ".bat", ".sh", ".vbs", ".scr", ".dex")

        for (folder in foldersToScan) {
            if (!folder.exists() || !folder.isDirectory) continue
            folder.walkTopDown().maxDepth(3).forEach { file ->
                if (file.isFile) {
                    val lowerName = file.name.lowercase()
                    val isDangerousExt = dangerousExtensions.any { lowerName.endsWith(it) }
                    val isDoubleExtension = (lowerName.contains(".jpg.") || lowerName.contains(".png.") || lowerName.contains(".mp4.")) && isDangerousExt
                    val isHiddenExecutable = lowerName.startsWith(".") && file.length() > 1024 * 50 && isDangerousExt

                    if (isDoubleExtension || isDangerousExt || isHiddenExecutable) {
                        val desc = when {
                            isDoubleExtension -> "فایل مخرب تغییر نام یافته با پسوند جعلی تصویر/ویدیو در پوشه ${folder.name}"
                            isHiddenExecutable -> "فایل اجرایی پنهان مشکوک در پوشه ${folder.name}"
                            else -> "فایل نصب‌کننده یا اجرایی پرخطر (${file.extension}) در پوشه ${folder.name}"
                        }
                        list.add(
                            ThreatItem(
                                title = "فایل مشکوک: ${file.name}",
                                description = desc,
                                type = "FILE",
                                targetPathOrPackage = file.absolutePath,
                                isHighRisk = true
                            )
                        )
                    }
                }
            }
        }
        return list
    }

    // عملیات دکمه حذف/بررسی روی هر آیتم
    private fun handleItemAction(item: ThreatItem) {
        when (item.type) {
            "APP" -> {
                val intent = Intent(Intent.ACTION_DELETE)
                intent.data = Uri.parse("package:${item.targetPathOrPackage}")
                startActivity(intent)
            }
            "FILE" -> {
                AlertDialog.Builder(this)
                    .setTitle("حذف فایل مخرب")
                    .setMessage("آیا از حذف دائمی فایل «${item.title}» مطمئن هستید؟")
                    .setPositiveButton("بله، حذف شود") { _, _ ->
                        val file = File(item.targetPathOrPackage)
                        if (file.exists() && file.delete()) {
                            threatList.remove(item)
                            adapter.notifyDataSetChanged()
                            Toast.makeText(this, "فایل با موفقیت حذف شد.", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(this, "خطا در حذف فایل.", Toast.LENGTH_SHORT).show()
                        }
                    }
                    .setNegativeButton("انصراف", null)
                    .show()
            }
            "SMS" -> {
                AlertDialog.Builder(this)
                    .setTitle("متن کامل پیامک مشکوک")
                    .setMessage(item.targetPathOrPackage)
                    .setPositiveButton("بستن", null)
                    .show()
            }
            "WIFI" -> {
                startActivity(Intent(Settings.ACTION_WIFI_SETTINGS))
            }
        }
    }

    private fun showActivationDialog() {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(50, 40, 50, 10)
        }

        val etName = EditText(this).apply { hint = "نام و نام خانوادگی" }
        val etPhone = EditText(this).apply {
            hint = "شماره موبایل (مثلاً 09120000000)"
            inputType = android.text.InputType.TYPE_CLASS_PHONE
        }

        layout.addView(etName)
        layout.addView(etPhone)

        AlertDialog.Builder(this)
            .setTitle("فعال‌سازی سپر امنیتی کامل")
            .setMessage("برای دسترسی نامحدود به تمام سپرهای حفاظتی، شماره موبایل خود را وارد کنید:")
            .setView(layout)
            .setPositiveButton("پرداخت و فعال‌سازی") { _, _ ->
                val name = etName.text.toString().trim()
                val phone = etPhone.text.toString().trim()
                if (phone.length >= 10) {
                    saveUserPhone(phone)
                    val payUri = Uri.parse(PAY_URL).buildUpon()
                        .appendQueryParameter("name", name)
                        .appendQueryParameter("phone", phone)
                        .build()
                    startActivity(Intent(Intent.ACTION_VIEW, payUri))
                } else {
                    Toast.makeText(this, "لطفاً شماره موبایل معتبر وارد کنید.", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("بستن", null)
            .show()
    }

    private fun refreshSubscriptionStatus() {
        val isActivated = getSharedPreferences("bw_prefs", Context.MODE_PRIVATE).getBoolean("activated", false)
        updateBadgeUI(isActivated)

        val savedPhone = getSavedPhone() ?: return
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val url = URL(VERIFY_URL)
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.doOutput = true

                val jsonBody = JSONObject().put("phone", savedPhone).toString()
                conn.outputStream.use { it.write(jsonBody.toByteArray()) }

                if (conn.responseCode == 200) {
                    val respText = conn.inputStream.bufferedReader().readText()
                    val active = JSONObject(respText).optBoolean("activated", false)
                    setActivated(active)
                    withContext(Dispatchers.Main) { updateBadgeUI(active) }
                }
            } catch (_: Exception) {
            }
        }
    }

    private fun updateBadgeUI(active: Boolean) {
        if (active) {
            tvSubscriptionBadge.text = "نسخه کامل (فعال)"
            tvSubscriptionBadge.setBackgroundColor(0xFF16A34A.toInt())
        } else {
            tvSubscriptionBadge.text = "نسخه پایه"
            tvSubscriptionBadge.setBackgroundColor(0xFFF97316.toInt())
        }
    }

    private fun saveUserPhone(phone: String) {
        getSharedPreferences("bw_prefs", Context.MODE_PRIVATE).edit().putString("phone", phone).apply()
    }

    private fun getSavedPhone(): String? {
        return getSharedPreferences("bw_prefs", Context.MODE_PRIVATE).getString("phone", null)
    }

    private fun setActivated(active: Boolean) {
        getSharedPreferences("bw_prefs", Context.MODE_PRIVATE).edit().putBoolean("activated", active).apply()
    }
}

class ThreatAdapter(
    private val items: List<ThreatItem>,
    private val onActionClick: (ThreatItem) -> Unit
) : RecyclerView.Adapter<ThreatAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvTitle: TextView = view.findViewById(R.id.tvItemTitle)
        val tvDesc: TextView = view.findViewById(R.id.tvItemDesc)
        val btnDelete: Button = view.findViewById(R.id.btnDeleteItem)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_threat, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        holder.tvTitle.text = item.title
        holder.tvDesc.text = item.description
        holder.btnDelete.text = when (item.type) {
            "SMS" -> "مشاهده"
            "WIFI" -> "تنظیمات"
            else -> "حذف"
        }
        holder.btnDelete.setOnClickListener { onActionClick(item) }
    }

    override fun getItemCount(): Int = items.size
}