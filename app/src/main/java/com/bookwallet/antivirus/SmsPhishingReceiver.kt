package com.bookwallet.antivirus

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class SmsPhishingReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Telephony.Sms.Intents.SMS_RECEIVED_ACTION) {
            val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
            for (sms in messages) {
                val sender = sms.originatingAddress ?: "ناشناس"
                val body = sms.messageBody ?: ""
                val analysis = PhishingAnalyzer.analyzeSms(sender, body)

                if (analysis.isSuspicious) {
                    PhishingAnalyzer.saveSuspiciousSms(context, sender, body, analysis.reason)

                    // باز کردن فوری صفحه هشدار روی تمام برنامه‌ها برای جلوگیری از باز شدن خودکار لینک
                    val alertIntent = Intent(context, MainActivity::class.java).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
                        putExtra("PHISHING_ALERT", true)
                        putExtra("SMS_SENDER", sender)
                        putExtra("SMS_BODY", body)
                        putExtra("SMS_REASON", analysis.reason)
                    }
                    context.startActivity(alertIntent)
                }
            }
        }
    }
}

object PhishingAnalyzer {
    data class Result(val isSuspicious: Boolean, val reason: String)

    fun analyzeSms(sender: String, body: String): Result {
        val lower = body.lowercase()
        val hasUrl = Regex("(https?://|www\\.|bit\\.ly|tinyurl|t\\.me|yun\\.ir|zil\\.ink|b2n\\.ir|[a-z0-9-]+\\.(xyz|top|tk|ml|ga|cf|gq|apk|club|online|site|link))").containsMatchIn(lower)
        val hasPhishingWords = listOf(
            "ابلاغیه", "ثنا", "قوه قضائیه", "سهام عدالت", "یارانه", "مسدود", "حساب بانکی",
            "بسته پستی", "کد رهگیری", "جریمه", "خلافی", "وام", "برنده", "رایگان", "نصب برنامه"
        ).any { lower.contains(it) }

        val isPersonalNumber = sender.startsWith("+989") || sender.startsWith("09") || (sender.length in 10..13 && sender.all { it.isDigit() || it == '+' })

        if (hasUrl && isPersonalNumber) {
            return Result(true, "ارسال لینک از شماره شخصی ($sender) — الگوی قطعی فیشینگ و بدافزار!")
        }
        if (hasUrl && hasPhishingWords) {
            return Result(true, "پیامک فریبنده بانکی/قضایی حاوی لینک مشکوک برای سرقت اطلاعات!")
        }
        if (lower.contains(".apk")) {
            return Result(true, "لینک دانلود مستقیم فایل نصب برنامه (.apk) در پیامک!")
        }
        if (hasUrl) {
            return Result(true, "پیامک حاوی لینک خارجی — از باز کردن خودکار یا لمس آن خودداری کنید.")
        }
        return Result(false, "")
    }

    fun saveSuspiciousSms(context: Context, sender: String, body: String, reason: String) {
        val prefs = context.getSharedPreferences("bw_sms_logs", Context.MODE_PRIVATE)
        val arr = JSONArray(prefs.getString("logs", "[]"))
        val obj = JSONObject().apply {
            put("sender", sender)
            put("body", body)
            put("reason", reason)
            put("time", SimpleDateFormat("HH:mm - yyyy/MM/dd", Locale.getDefault()).format(Date()))
        }
        arr.put(obj)
        prefs.edit().putString("logs", arr.toString()).apply()
    }
}