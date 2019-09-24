"""
Rule Format

1. desc - Description of the findings

2. type
   a. string
   b. regex

3. match
   a. single_regex - if re.findall(regex1, input)
   b .regex_and - if re.findall(regex1, input) and re.findall(regex2, input)
   c. regex_or - if re.findall(regex1, input) or re.findall(regex2, input)
   d. regex_and_perm - if re.findall(regex, input) and (permission in permission_list_from_manifest)
   e. single_string - if string1 in input
   f. string_and - if (string1 in input) and (string2 in input)
   g. string_or - if (string1 in input) or (string2 in input)
   h. string_and_or -  if (string1 in input) and ((string_or1 in input) or (string_or2 in input))
   i. string_or_and - if (string1 in input) or ((string_and1 in input) and (string_and2 in input))
   j. string_and_perm - if (string1 in input) and (permission in permission_list_from_manifest)
   k. string_or_and_perm - if ((string1 in input) or (string2 in input)) and (permission in permission_list_from_manifest)

4. level
   a. high
   b. warning
   c. info
   d. good

5. input_case
   a. upper
   b. lower
   c. exact

6. others
   a. string<no> - string1, string2, string3, string_or1, string_and1
   b. regex<no> - regex1, regex2, regex3
   c. perm - Permission

"""
RULES = [
    {#  检测第三方sdk
        'desc': '内网信息残留问题',
        'type': 'regex',
        'regex1': r'''(huobiapps\.com)|(hbtalk\.org)|(hwallet\.office)|(hottalk\.im)|(huobiidc)|(huobidev)|(huobiinc)''',
        'level': 'warning',
        'match': 'single_regex',
        'input_case': 'lower',
        'cvss': 1.1,
        'cwe': 'inter-inf'
    },
    {
        'desc': 'webview密码明文存储风险 ',
        'type': 'string',
        'string1': 'setSavePassword(true)',
        'level': 'warning',
        'match': 'single_string',
        'input_case': 'exact',
        'cvss': 8.8,
        'cwe': 'webview-Cleartext'
    },
    {
        'desc': 'zip文件解压目录遍历漏洞  请判断是否对../进行过滤 ',
        'type': 'string',
        'string1': 'zipEntry.getnName',
        'level': 'high',
        'match': 'single_string',
        'input_case': 'lower',
        'cvss': 8.5,
        'cwe': 'CWE-276'
    },
    {#  检测第三方sdk
        'desc': '第三方sdk',
        'type': 'regex',
        'regex1': r'''(import com\.alibaba\.sdk)|(import com\.google\.android)|(import com\.amap\.api)''',
        'level': 'warning',
        'match': 'single_regex',
        'input_case': 'lower',
        'cvss': 1.1,
        'cwe': 'CWE-test'
    },
    {#  敏感词信息
        'desc': 'FFmpeg  文件读取漏洞 ',
        'type': 'regex',
        'regex1': r'''libijkffmpeg\.so''',
        'level': 'warning',
        'match': 'single_regex',
        'input_case': 'lower',
        'cvss': 1.1,
        'cwe': 'CWE-test'
    },
        {
        'desc': 'Service组件导出风险',
        'type': 'string',
        'string1': 'service android:exported=true',
        'level': 'warning',
        'match': 'single_string',
        'input_case': 'exact',
        'cvss': 8.8,
        'cwe': 'service-export'
    },
    {
        'desc': '硬编码安全隐患  文件可能包含硬编码的敏感信息，如用户名 密码 密钥等',
        'type': 'regex',
        'regex1': r'''(password\s*=\s*['|"].+['|"]\s{0,5})|(pass\s*=\s*['|"].+['|"]\s{0,5})|(username\s*=\s*['|"].+['|"]\s{0,5})|(secret\s*=\s*['|"].+['|"]\s{0,5})|(key\s*=\s*['|"].+['|"]\s{0,5})''',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'lower',
        'cvss': 7.4,
        'cwe': 'CWE-312'
    },
    {
        'desc': 'IP地址泄露',
        'type': 'regex',
        'regex1': r'''(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})\.(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})\.(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})\.(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})''',   #修改匹配地址正则
        'level': 'warning',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 4.3,
        'cwe': 'CWE-200'
    },  
    {
        'desc': 'Hidden elements in view can be used to hide data from user. But this data can be leaked',
        'type': 'regex',
        'regex1': r'setVisibility\(View\.GONE\)|setVisibility\(View\.INVISIBLE\)',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 4.3,
        'cwe': 'CWE-919'
    },
    {
        'desc': '使用ECB加密方式加密风险. ECB是较弱的加密方式，相同明文生成的密文相同 ',
        'type': 'regex',
        'regex1': r'Cipher\.getInstance\(\s*"\s*AES\/ECB',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': 'CWE-327'
    },
    {
        'desc': 'RSA加密算法不安全使用漏洞 可能导致客户端隐私数据泄露，加密文件破解，传输数据被获取',
        'type': 'regex',
        'regex1': r'cipher\.getinstance\(\s*"rsa/.+/nopadding',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'lower',
        'cvss': 5.9,
        'cwe': 'CWE-RSA'
    },
    {
        'desc': 'MITM中间人攻击风险  APP信任所有证书或接受自签名证书',
        'type': 'regex',
        'regex1': r'javax\.net\.ssl',
        'regex2': r'TrustAllSSLSocket-Factory|AllTrustSSLSocketFactory|NonValidatingSSLSocketFactory|net\.SSLCertificateSocketFactory|ALLOW_ALL_HOSTNAME_VERIFIER|\.setDefaultHostnameVerifier\(|NullHostnameVerifier\(',
        'level': 'high',
        'match': 'regex_and',
        'input_case': 'exact',
        'cvss': 7.4,
        'cwe': 'CWE-295'
    },
    {
        'desc': 'Webview File同源策略绕过漏洞',
        'type': 'regex',
        'regex1': r'\.loadUrl\(.*getExternalStorageDirectory\(',
        'regex2': r'webkit\.WebView',
        'level': 'high',
        'match': 'regex_and',
        'input_case': 'exact',
        'cvss': 5.0,
        'cwe': 'webview-Homologous'
    },
    {
        'desc': 'The file is World Readable. Any App can read from the file',
        'type': 'regex',
        'regex1': r'MODE_WORLD_READABLE|Context\.MODE_WORLD_READABLE',
        'regex2': r'openFileOutput\(\s*".+"\s*,\s*1\s*\)',
        'level': 'high',
        'match': 'regex_or',
        'input_case': 'exact',
        'cvss': 4.0,
        'cwe': 'CWE-276'

    },
    {
        'desc': 'The file is World Writable. Any App can write to the file',
        'type': 'regex',
        'regex1': r'MODE_WORLD_WRITABLE|Context\.MODE_WORLD_WRITABLE',
        'regex2': r'openFileOutput\(\s*".+"\s*,\s*2\s*\)',
        'level': 'high',
        'match': 'regex_or',
        'input_case': 'exact',
        'cvss': 6.0,
        'cwe': 'CWE-276'
    },
    {
        'desc': 'The file is World Readable and Writable. Any App can read/write to the file',
        'type': 'regex',
        'regex1': r'openFileOutput\(\s*".+"\s*,\s*3\s*\)',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 6.0,
        'cwe': 'CWE-276'
    },
    {
        'desc': 'Weak Hash algorithm used',
        'type': 'regex',
        'regex1': r'getInstance(\"md4\")|getInstance(\"rc2\")|getInstance(\"rc4\")|getInstance(\"RC4\")|getInstance(\"RC2\")|getInstance(\"MD4\")',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 7.4,
        'cwe': 'CWE-327'
    },
    {
        'desc': '使用不安全的md5加密方式加密',
        'type': 'regex',
        'regex1': r'MessageDigest\.getInstance\(\"*MD5\"*\)|MessageDigest\.getInstance\(\"*md5\"*\)|DigestUtils\.md5\(',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 7.4,
        'cwe': 'CWE-327'
    },
    {
        'desc': '使用 SHA-1实现加密   SHA-1是弱哈希',
        'type': 'regex',
        'regex1': r'MessageDigest\.getInstance\(\"*SHA-1\"*\)|MessageDigest\.getInstance\(\"*sha-1\"*\)|DigestUtils\.sha\(',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': 'CWE-327'
    },
    {
        'desc': 'App can write to App Directory. Sensitive Information should be encrypted.',
        'type': 'regex',
        'regex1': r'MODE_PRIVATE|Context\.MODE_PRIVATE',
        'level': 'info',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 3.9,
        'cwe': 'CWE-276'
    },
    {
        'desc': '随机数不安全使用漏洞',
        'type': 'regex',
        'regex1': r'java\.util\.Random',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 7.5,
        'cwe': 'CWE-330'
    },
    {
        'desc': 'App logs 记录信息风险，建议不要再日志中记录敏感信息',
        'type': 'regex',
        'regex1': r'Log\.(v|d|i|w|e|f|s)|System\.out\.print|System\.err\.print',
        'level': 'info',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 7.5,
        'cwe': 'CWE-532'
    },
    {
        'desc': 'App  使用hash加密安全风险  建议使用安全得加密方式',
        'type': 'string',
        'string1': '.hashCode()',
        'level': 'high',
        'match': 'single_string',
        'input_case': 'exact',
        'cvss': 4.3,
        'cwe': 'CWE-327'
    },
    {
        'desc': 'These activities prevent screenshot when they go to background.',
        'type': 'string',
        'string1': 'LayoutParams.FLAG_SECURE',
        'level': 'good',
        'match': 'single_string',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'This App uses SQL Cipher. But the secret may be hardcoded.',
        'type': 'string',
        'string1': 'SQLiteOpenHelper.getWritableDatabase(',
        'level': 'warning',
        'match': 'single_string',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'This app has capabilities to prevent tapjacking attacks.',
        'type': 'string',
        'string1': 'setFilterTouchesWhenObscured(true)',
        'level': 'good',
        'match': 'single_string',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': '数据库文件任意读写漏洞',
        'perm': 'android.permission.WRITE_EXTERNAL_STORAGE',
        'type': 'string',
        'string1': '.getExternalStorage',
        'string2': '.getExternalFilesDir(',
        'level': 'high',
        'match': 'string_or_and_perm',
        'input_case': 'exact',
        'cvss': 5.5,
        'cwe': 'database-read'
    },
    {
        'desc': 'App创建临时文件风险，不应将敏感信息写入临时文件',
        'perm': 'android.permission.WRITE_EXTERNAL_STORAGE',
        'type': 'string',
        'string1': '.createTempFile(',
        'level': 'high',
        'match': 'string_and_perm',
        'input_case': 'exact',
        'cvss': 5.5,
        'cwe': 'CWE-276'
    },
    {
        'desc': 'Webview File同源策略绕过漏洞 在webview中设置setJavaScriptEnabled(true) 导致任意代码执行  建议 Google在4.2版本之后，规定允许被调用的函数必须以@JavascriptInterface进行注解， API等于高于17的Android系统。建议不要使用addJavascriptInterface接口  开发者自查@JavascriptInterface',
        'type': 'string',
        'string1': 'setJavaScriptEnabled(true)',
        'string2': '.addJavascriptInterface(',
        'level': 'warning',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 8.8,
        'cwe': 'Webview-Files'
    },
    {
        'desc': 'This App uses SQL Cipher. SQLCipher provides 256-bit AES encryption to sqlite database files.',
        'type': 'string',
        'string1': 'SQLiteDatabase.loadLibs(',
        'string2': 'net.sqlcipher.',
        'level': 'info',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'This App download files using Android Download Manager',
        'type': 'string',
        'string1': 'android.app.DownloadManager',
        'string2': 'getSystemService(DOWNLOAD_SERVICE)',
        'level': 'high',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'This App use Realm Database with encryption.',
        'type': 'string',
        'string1': 'io.realm.Realm',
        'string2': '.encryptionKey(',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'The App may use weak IVs like "0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00" or "0x01,0x02,0x03,0x04,0x05,0x06,0x07". Not using a random IV makes the resulting ciphertext much more predictable and susceptible to a dictionary attack.',
        'type': 'string',
        'string1': '0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00',
        'string2': '0x01,0x02,0x03,0x04,0x05,0x06,0x07',
        'level': 'high',
        'match': 'string_or',
        'input_case': 'exact',
        'cvss': 9.8,
        'cwe': 'CWE-329'
    },
    {
        'desc': 'Remote WebView debugging is enabled.',
        'type': 'string',
        'string1': '.setWebContentsDebuggingEnabled(true)',
        'string2': 'WebView',
        'level': 'high',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 5.4,
        'cwe': 'CWE-919'
    },
    {
        'desc': 'This app listens to Clipboard changes. Some malwares also listen to Clipboard changes.',
        'type': 'string',
        'string1': 'content.ClipboardManager',
        'string2': 'OnPrimaryClipChangedListener',
        'level': 'warning',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': '敏感信息泄露   app将数据复制到剪切板 可能导致其他应用获取剪切板的数据',
        'type': 'string',
        'string1': 'content.ClipboardManager',
        'string2': 'setPrimaryClip(',
        'level': 'info',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'Webview绕过证书校验漏洞 但如果重载WebView的onReceivedSslError()函数并在其中执行handler.proceed()，客户端可以绕过证书校验错误继续访问此非法URL。',
        'type': 'string',
        'string1': 'onReceivedSslError(WebView',
        'string2': '.proceed();',
        'level': 'high',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 7.4,
        'cwe': 'Webview-ssl'
    },
    {
        'desc': '使用sqlite数据库并执行原始sql查询，原始sql查询不受信任得用户输入可能导致sql注入，敏感信息也应该加密写入数据库',
        'type': 'string',
        'string1': 'android.database.sqlite',
        'string_or1': 'rawQuery(',
        'string_or2': 'execSQL(',
        'level': 'high',
        'match': 'string_and_or',
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': 'CWE-89'
    },
    {
        'desc': 'This App detects frida server.',
        'type': 'string',
        'string1': 'fridaserver',
        'string_or1': '27047',
        'string_or2': 'REJECT',
        'string_or3': 'LIBFRIDA',
        'level': 'good',
        'match': 'string_and_or',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'This App uses an SSL Pinning Library (org.thoughtcrime.ssl.pinning) to prevent MITM attacks in secure communication channel.',
        'type': 'string',
        'string1': 'org.thoughtcrime.ssl.pinning',
        'string_or1': 'PinningHelper.getPinnedHttpsURLConnection',
        'string_or2': 'PinningHelper.getPinnedHttpClient',
        'string_or3': 'PinningSSLSocketFactory(',
        'level': 'good',
        'match': 'string_and_or',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'This App has capabilities to prevent against Screenshots from Recent Task History/ Now On Tap etc.',
        'type': 'string',
        'string1': '.FLAG_SECURE',
        'string_or1': 'getWindow().setFlags(',
        'string_or2': 'getWindow().addFlags(',
        'level': 'high',
        'match': 'string_and_or',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'DexGuard Debug Detection code to detect wheather an App is debuggable or not is identified.',
        'type': 'string',
        'string1': 'import dexguard.util',
        'string2': 'DebugDetector.isDebuggable',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'DexGuard Debugger Detection code is identified.',
        'type': 'string',
        'string1': 'import dexguard.util',
        'string2': 'DebugDetector.isDebuggerConnected',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'DexGuard Emulator Detection code is identified.',
        'type': 'string',
        'string1': 'import dexguard.util',
        'string2': 'EmulatorDetector.isRunningInEmulator',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'DecGuard code to detect wheather the App is signed with a debug key or not is identified.',
        'type': 'string',
        'string1': 'import dexguard.util',
        'string2': 'DebugDetector.isSignedWithDebugKey',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'DexGuard Root Detection code is identified.',
        'type': 'string',
        'string1': 'import dexguard.util',
        'string2': 'RootDetector.isDeviceRooted',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'DexGuard App Tamper Detection code is identified.',
        'type': 'string',
        'string1': 'import dexguard.util',
        'string2': 'TamperDetector.checkApk',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'DexGuard Signer Certificate Tamper Detection code is identified.',
        'type': 'string',
        'string1': 'import dexguard.util',
        'string2': 'TCertificateChecker.checkCertificate',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'The App may use package signature for tamper detection.',
        'type': 'string',
        'string1': 'PackageManager.GET_SIGNATURES',
        'string2': 'getPackageName(',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'This App uses SafetyNet API.',
        'type': 'string',
        'string1': 'com.google.android.gms.safetynet.SafetyNetApi',
        'level': 'good',
        'match': 'single_string',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    },
    {
        'desc': 'This App may request root (Super User) privileges.',
        'type': 'string',
        'string1': 'com.noshufou.android.su',
        'string2': 'com.thirdparty.superuser',
        'string3': 'eu.chainfire.supersu',
        'string4': 'com.koushikdutta.superuser',
        'string5': 'eu.chainfire.',
        'level': 'high',
        'match': 'string_or',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': 'CWE-250'
    },
    {
        'desc': 'Root设备运行风险 ',
        'type': 'string',
        'string1': '.contains("test-keys")',
        'string2': '/system/app/Superuser.apk',
        'string3': 'isDeviceRooted()',
        'string4': '/system/bin/failsafe/su',
        'string5': '/system/sd/xbin/su',
        'string6': '"/system/xbin/which", "su"',
        "string7": 'RootTools.isAccessGiven()',
        'level': 'good',
        'match': 'string_or',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': ''
    }]
