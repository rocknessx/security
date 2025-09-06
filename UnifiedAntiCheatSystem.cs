using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UnityEngine;
using System.Runtime.InteropServices;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Threading;
using System.Collections;

#if UNITY_STANDALONE_WIN
using Microsoft.Win32;
using System.Diagnostics;
#endif

#if UNITY_ANDROID
using UnityEngine.Android;
#endif

namespace AntiCheatSystem
{
    /// <summary>
    /// Ana AntiCheat sistemi - Tüm platformları destekler
    /// Windows, Linux, macOS, Android için VM/Emülatör tespiti
    /// </summary>
    public class UnifiedAntiCheatSystem : MonoBehaviour
    {
        #region Singleton Pattern
        private static UnifiedAntiCheatSystem _instance;
        public static UnifiedAntiCheatSystem Instance
        {
            get
            {
                if (_instance == null)
                {
                    _instance = FindObjectOfType<UnifiedAntiCheatSystem>();
                    if (_instance == null)
                    {
                        GameObject go = new GameObject("AntiCheatSystem");
                        _instance = go.AddComponent<UnifiedAntiCheatSystem>();
                        DontDestroyOnLoad(go);
                    }
                }
                return _instance;
            }
        }
        #endregion

        #region Data Classes
        [System.Serializable]
        public class SystemFingerprint
        {
            public string timestamp;
            public string platform;
            public string unityVersion;
            public string gameVersion;

            // Donanım bilgileri
            public HardwareInfo hardware;

            // Aç bilgileri
            public NetworkInfo network;

            // Süreç bilgileri
            public ProcessInfo processes;

            // Sanallaştırma tespiti
            public VirtualizationInfo virtualization;

            // Risk analizi
            public RiskAnalysis risk;

            // Özet hash
            public string fingerprintHash;
        }

        [System.Serializable]
        public class HardwareInfo
        {
            public string deviceId;
            public string deviceModel;
            public string deviceName;
            public string deviceType;
            public string processorType;
            public int processorCount;
            public int processorFrequency;
            public string graphicsDeviceName;
            public string graphicsDeviceVendor;
            public int graphicsMemorySize;
            public int systemMemorySize;

            // Platform spesifik
            public string motherboardSerial;
            public string biosSerial;
            public string cpuId;
            public List<string> diskSerials = new List<string>();
            public List<string> macAddresses = new List<string>();
        }

        [System.Serializable]
        public class NetworkInfo
        {
            public List<NetworkAdapter> adapters = new List<NetworkAdapter>();
            public bool hasVirtualAdapter;
            public List<string> virtualAdapterNames = new List<string>();
            public string networkTopology;
        }

        [System.Serializable]
        public class NetworkAdapter
        {
            public string name;
            public string description;
            public string macAddress;
            public string type;
            public bool isVirtual;
            public long speed;
        }

        [System.Serializable]
        public class ProcessInfo
        {
            public List<string> runningProcesses = new List<string>();
            public List<string> suspiciousProcesses = new List<string>();
            public List<string> knownCheatTools = new List<string>();
            public List<string> knownEmulators = new List<string>();
            public bool hasRiskyProcesses;
        }

        [System.Serializable]
        public class VirtualizationInfo
        {
            public bool isVirtualized;
            public string detectionMethod;
            public List<string> evidence = new List<string>();
            public float confidenceScore;
        }

        [System.Serializable]
        public class RiskAnalysis
        {
            public float totalRiskScore;
            public string riskLevel; // LOW, MEDIUM, HIGH, CRITICAL
            public Dictionary<string, float> riskFactors = new Dictionary<string, float>();
            public List<string> detectedThreats = new List<string>();
            public bool shouldBlock;
        }
        #endregion

        #region Configuration
        [Header("AntiCheat Configuration")]
        [SerializeField] private bool enableDebugMode = true;
        [SerializeField] private float riskThreshold = 75f;
        [SerializeField] private float checkInterval = 30f;

        [Header("Detection Modules")]
        [SerializeField] private bool enableHardwareCheck = true;
        [SerializeField] private bool enableNetworkCheck = true;
        [SerializeField] private bool enableProcessCheck = true;
        [SerializeField] private bool enableVMDetection = true;

        [Header("Risk Weights")]
        [SerializeField] private float vmDetectionWeight = 40f;
        [SerializeField] private float emulatorWeight = 35f;
        [SerializeField] private float cheatToolWeight = 45f;
        [SerializeField] private float suspiciousProcessWeight = 25f;
        [SerializeField] private float virtualNetworkWeight = 20f;
        #endregion

        #region Private Fields
        private SystemFingerprint currentFingerprint;
        private CancellationTokenSource cancellationToken;
        private bool isInitialized = false;

        // Known signatures
        private readonly HashSet<string> knownVMProcesses = new HashSet<string>
        {
            "vmtoolsd", "vmwaretray", "vmwareuser", "vmacthlp",
            "vboxservice", "vboxtray", "vboxguest",
            "xenservice", "qemu-ga", "prl_cc", "prl_tools"
        };

        private readonly HashSet<string> knownEmulatorProcesses = new HashSet<string>
        {
            "bluestacks", "hd-player", "bstshutdown", "bstkern",
            "ldplayer", "ldvboxheadless", "ldconsole",
            "nox", "noxvmhandle", "bignox",
            "memu", "memuheadless", "memuconsole",
            "droid4x", "ami_droid", "andy",
            "genymotion", "player", "virtualapp"
        };

        private readonly HashSet<string> knownCheatProcesses = new HashSet<string>
        {
            "cheatengine", "artmoney", "gameguardian", "speedhack",
            "processhacker", "ollydbg", "x64dbg", "ida", "ida64",
            "wireshark", "fiddler", "charles", "httpanalyzer",
            "sandboxie", "vmprotect", "themida"
        };

        private readonly Dictionary<string, string> virtualMacPrefixes = new Dictionary<string, string>
        {
            { "00:05:69", "VMware" },
            { "00:0C:29", "VMware" },
            { "00:50:56", "VMware" },
            { "00:1C:14", "VMware" },
            { "08:00:27", "VirtualBox" },
            { "0A:00:27", "VirtualBox" },
            { "00:1C:42", "Parallels" },
            { "00:03:FF", "Microsoft Virtual PC" },
            { "00:16:3E", "Xen" },
            { "00:15:5D", "Hyper-V" },
            { "52:54:00", "QEMU/KVM" }
        };
        #endregion

        #region Unity Lifecycle
        void Awake()
        {
            if (_instance != null && _instance != this)
            {
                Destroy(gameObject);
                return;
            }

            _instance = this;
            DontDestroyOnLoad(gameObject);
        }

        void Start()
        {
            Initialize();
        }

        void OnDestroy()
        {
            cancellationToken?.Cancel();
            cancellationToken?.Dispose();
        }
        #endregion

        #region Public Methods
        public void Initialize()
        {
            if (isInitialized) return;

            isInitialized = true;
            cancellationToken = new CancellationTokenSource();

            StartCoroutine(InitialCheck());

            if (checkInterval > 0)
            {
                InvokeRepeating(nameof(PerformRuntimeCheck), checkInterval, checkInterval);
            }
        }

        public SystemFingerprint GetCurrentFingerprint()
        {
            return currentFingerprint;
        }

        public string GetFingerprintJSON()
        {
            if (currentFingerprint == null)
            {
                PerformFullSystemScan();
            }
            return JsonUtility.ToJson(currentFingerprint, true);
        }

        public float GetRiskScore()
        {
            return currentFingerprint?.risk?.totalRiskScore ?? 0f;
        }

        public bool IsSystemSafe()
        {
            return currentFingerprint?.risk?.shouldBlock == false;
        }
        #endregion

        #region Core Detection Logic
        private IEnumerator InitialCheck()
        {
            yield return new WaitForSeconds(1f); // Let Unity initialize

            PerformFullSystemScan();

            if (enableDebugMode)
            {
                UnityEngine.Debug.Log($"[AntiCheat] Initial scan complete. Risk Score: {currentFingerprint.risk.totalRiskScore}");
                UnityEngine.Debug.Log($"[AntiCheat] Full Fingerprint JSON:\n{GetFingerprintJSON()}");
            }
        }

        private void PerformRuntimeCheck()
        {
            if (!isInitialized) return;

            Task.Run(() =>
            {
                try
                {
                    PerformFullSystemScan();

                    if (currentFingerprint.risk.shouldBlock)
                    {
                        MainThreadDispatcher(() =>
                        {
                            HandleSecurityViolation();
                        });
                    }
                }
                catch (Exception e)
                {
                    UnityEngine.Debug.LogError($"[AntiCheat] Runtime check error: {e}");
                }
            }, cancellationToken.Token);
        }

        private void PerformFullSystemScan()
        {
            currentFingerprint = new SystemFingerprint
            {
                timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
                platform = Application.platform.ToString(),
                unityVersion = Application.unityVersion,
                gameVersion = Application.version,
                hardware = new HardwareInfo(),
                network = new NetworkInfo(),
                processes = new ProcessInfo(),
                virtualization = new VirtualizationInfo(),
                risk = new RiskAnalysis()
            };

            // Collect all data
            if (enableHardwareCheck)
                CollectHardwareInfo();

            if (enableNetworkCheck)
                CollectNetworkInfo();

            if (enableProcessCheck)
                CollectProcessInfo();

            if (enableVMDetection)
                DetectVirtualization();

            // Calculate risk
            CalculateRiskScore();

            // Generate fingerprint hash
            currentFingerprint.fingerprintHash = GenerateFingerprintHash();
        }
        #endregion

        #region Hardware Collection
        private void CollectHardwareInfo()
        {
            var hw = currentFingerprint.hardware;

            // Unity built-in info
            hw.deviceId = SystemInfo.deviceUniqueIdentifier;
            hw.deviceModel = SystemInfo.deviceModel;
            hw.deviceName = SystemInfo.deviceName;
            hw.deviceType = SystemInfo.deviceType.ToString();
            hw.processorType = SystemInfo.processorType;
            hw.processorCount = SystemInfo.processorCount;
            hw.processorFrequency = SystemInfo.processorFrequency;
            hw.graphicsDeviceName = SystemInfo.graphicsDeviceName;
            hw.graphicsDeviceVendor = SystemInfo.graphicsDeviceVendor;
            hw.graphicsMemorySize = SystemInfo.graphicsMemorySize;
            hw.systemMemorySize = SystemInfo.systemMemorySize;

#if UNITY_STANDALONE_WIN
            CollectWindowsHardwareInfo();
#elif UNITY_ANDROID
            CollectAndroidHardwareInfo();
#elif UNITY_STANDALONE_OSX || UNITY_IOS
            CollectAppleHardwareInfo();
#elif UNITY_STANDALONE_LINUX
            CollectLinuxHardwareInfo();
#endif
        }

#if UNITY_STANDALONE_WIN
        private void CollectWindowsHardwareInfo()
        {
            var hw = currentFingerprint.hardware;

            try
            {
                // Basit Windows bilgileri
                hw.motherboardSerial = "Windows-System";
                hw.biosSerial = "Windows-BIOS";
                hw.cpuId = SystemInfo.processorType;

                // MAC adreslerini NetworkInterface ile al
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var ni in interfaces)
                {
                    if (ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        hw.macAddresses.Add(ni.GetPhysicalAddress().ToString());
                    }
                }
            }
            catch (Exception e)
            {
                UnityEngine.Debug.LogWarning($"[AntiCheat] Windows hardware collection error: {e.Message}");
            }
        }
#endif

#if UNITY_ANDROID
        private void CollectAndroidHardwareInfo()
        {
            var hw = currentFingerprint.hardware;
            
            try
            {
                using (var unityPlayer = new AndroidJavaClass("com.unity3d.player.UnityPlayer"))
                {
                    var activity = unityPlayer.GetStatic<AndroidJavaObject>("currentActivity");
                    var context = activity.Call<AndroidJavaObject>("getApplicationContext");
                    
                    // Android ID
                    using (var settingsSecure = new AndroidJavaClass("android.provider.Settings$Secure"))
                    {
                        var resolver = context.Call<AndroidJavaObject>("getContentResolver");
                        var androidId = settingsSecure.CallStatic<string>("getString", resolver, "android_id");
                        hw.cpuId = androidId;
                    }
                    
                    // Build info
                    using (var build = new AndroidJavaClass("android.os.Build"))
                    {
                        hw.motherboardSerial = build.GetStatic<string>("SERIAL");
                        hw.biosSerial = build.GetStatic<string>("BOOTLOADER");
                    }
                }
            }
            catch (Exception e)
            {
                UnityEngine.Debug.LogWarning($"[AntiCheat] Android hardware collection error: {e.Message}");
            }
        }
#endif

#if UNITY_STANDALONE_OSX || UNITY_IOS
        private void CollectAppleHardwareInfo()
        {
            var hw = currentFingerprint.hardware;
            
            // macOS/iOS specific collection
            hw.motherboardSerial = SystemInfo.deviceUniqueIdentifier;
            hw.cpuId = SystemInfo.deviceModel;
        }
#endif

#if UNITY_STANDALONE_LINUX
        private void CollectLinuxHardwareInfo()
        {
            var hw = currentFingerprint.hardware;
            
            // Linux specific collection
            hw.motherboardSerial = SystemInfo.deviceUniqueIdentifier;
            hw.cpuId = SystemInfo.processorType;
        }
#endif
        #endregion

        #region Network Collection
        private void CollectNetworkInfo()
        {
            var net = currentFingerprint.network;

            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();

                foreach (var ni in interfaces)
                {
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;

                    var adapter = new NetworkAdapter
                    {
                        name = ni.Name,
                        description = ni.Description,
                        macAddress = ni.GetPhysicalAddress().ToString(),
                        type = ni.NetworkInterfaceType.ToString(),
                        speed = ni.Speed
                    };

                    // Check if virtual
                    adapter.isVirtual = IsVirtualNetworkAdapter(adapter);

                    if (adapter.isVirtual)
                    {
                        net.hasVirtualAdapter = true;
                        net.virtualAdapterNames.Add(adapter.name);
                    }

                    net.adapters.Add(adapter);
                }

                // Determine network topology
                DetermineNetworkTopology();
            }
            catch (Exception e)
            {
                UnityEngine.Debug.LogWarning($"[AntiCheat] Network collection error: {e.Message}");
            }
        }

        private bool IsVirtualNetworkAdapter(NetworkAdapter adapter)
        {
            // Check MAC prefix
            if (adapter.macAddress.Length >= 6)
            {
                var prefix = adapter.macAddress.Substring(0, 6);
                foreach (var vmPrefix in virtualMacPrefixes.Keys)
                {
                    if (prefix.StartsWith(vmPrefix.Replace(":", "")))
                        return true;
                }
            }

            // Check description
            var virtualKeywords = new[] { "virtual", "vmware", "vbox", "hyper-v", "parallels" };
            var desc = adapter.description.ToLower();

            return virtualKeywords.Any(keyword => desc.Contains(keyword));
        }

        private void DetermineNetworkTopology()
        {
            var net = currentFingerprint.network;

            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var gateways = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .SelectMany(n => n.GetIPProperties().GatewayAddresses)
                    .Select(g => g.Address.ToString())
                    .ToList();

                if (gateways.Any(g => g.StartsWith("192.168.")))
                    net.networkTopology = "NAT/Home Network";
                else if (gateways.Any(g => g.StartsWith("10.")))
                    net.networkTopology = "Corporate Network";
                else if (gateways.Any(g => g.StartsWith("172.")))
                    net.networkTopology = "Private Network";
                else
                    net.networkTopology = "Unknown";
            }
            catch
            {
                net.networkTopology = "Detection Failed";
            }
        }
        #endregion

        #region Process Collection
        private void CollectProcessInfo()
        {
            var proc = currentFingerprint.processes;

#if UNITY_STANDALONE_WIN || UNITY_STANDALONE_LINUX || UNITY_STANDALONE_OSX
            try
            {
                var processes = System.Diagnostics.Process.GetProcesses();

                foreach (var process in processes)
                {
                    var processName = process.ProcessName.ToLower();

                    // Add to running processes (limit to important ones)
                    if (proc.runningProcesses.Count < 100)
                    {
                        proc.runningProcesses.Add(process.ProcessName);
                    }

                    // Check for VM processes
                    if (knownVMProcesses.Any(vm => processName.Contains(vm)))
                    {
                        proc.suspiciousProcesses.Add(process.ProcessName);
                        proc.hasRiskyProcesses = true;
                    }

                    // Check for emulators
                    if (knownEmulatorProcesses.Any(emu => processName.Contains(emu)))
                    {
                        proc.knownEmulators.Add(process.ProcessName);
                        proc.hasRiskyProcesses = true;
                    }

                    // Check for cheat tools
                    if (knownCheatProcesses.Any(cheat => processName.Contains(cheat)))
                    {
                        proc.knownCheatTools.Add(process.ProcessName);
                        proc.hasRiskyProcesses = true;
                    }
                }
            }
            catch (Exception e)
            {
                UnityEngine.Debug.LogWarning($"[AntiCheat] Process collection error: {e.Message}");
            }
#elif UNITY_ANDROID
            CollectAndroidProcesses();
#endif
        }

#if UNITY_ANDROID
        private void CollectAndroidProcesses()
        {
            var proc = currentFingerprint.processes;
            
            try
            {
                using (var activityManager = new AndroidJavaClass("android.app.ActivityManager"))
                {
                    // Check for known emulator packages
                    var emulatorPackages = new[]
                    {
                        "com.bluestacks",
                        "com.bignox.app",
                        "com.topjohnwu.magisk",
                        "com.ldmnq.launcher3",
                        "com.microvirt.memuplay"
                    };
                    
                    foreach (var package in emulatorPackages)
                    {
                        if (IsPackageInstalled(package))
                        {
                            proc.knownEmulators.Add(package);
                            proc.hasRiskyProcesses = true;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                UnityEngine.Debug.LogWarning($"[AntiCheat] Android process collection error: {e.Message}");
            }
        }
        
        private bool IsPackageInstalled(string packageName)
        {
            try
            {
                using (var unityPlayer = new AndroidJavaClass("com.unity3d.player.UnityPlayer"))
                {
                    var activity = unityPlayer.GetStatic<AndroidJavaObject>("currentActivity");
                    var packageManager = activity.Call<AndroidJavaObject>("getPackageManager");
                    var packageInfo = packageManager.Call<AndroidJavaObject>("getPackageInfo", packageName, 0);
                    return packageInfo != null;
                }
            }
            catch
            {
                return false;
            }
        }
#endif
        #endregion

        #region Virtualization Detection
        private void DetectVirtualization()
        {
            var vm = currentFingerprint.virtualization;
            var evidence = new List<string>();
            float confidence = 0f;

#if UNITY_STANDALONE_WIN
            // Registry checks
            if (CheckVMwareRegistry())
            {
                evidence.Add("VMware Registry Keys");
                confidence += 30f;
            }

            if (CheckVirtualBoxRegistry())
            {
                evidence.Add("VirtualBox Registry Keys");
                confidence += 30f;
            }

            if (CheckHyperVRegistry())
            {
                evidence.Add("Hyper-V Registry Keys");
                confidence += 35f;
            }

            // Hardware checks
            if (CheckVirtualHardware())
            {
                evidence.Add("Virtual Hardware Detected");
                confidence += 25f;
            }

            // Timing checks
            if (PerformTimingCheck())
            {
                evidence.Add("Timing Anomalies");
                confidence += 20f;
            }
#elif UNITY_ANDROID
            // Android emulator checks
            if (CheckAndroidEmulator())
            {
                evidence.Add("Android Emulator Properties");
                confidence += 50f;
            }
            
            if (CheckEmulatorBuild())
            {
                evidence.Add("Emulator Build Properties");
                confidence += 40f;
            }
#endif

            // Process-based detection
            if (currentFingerprint.processes.suspiciousProcesses.Count > 0)
            {
                evidence.Add("VM Processes Running");
                confidence += 25f;
            }

            // Network-based detection
            if (currentFingerprint.network.hasVirtualAdapter)
            {
                evidence.Add("Virtual Network Adapters");
                confidence += 15f;
            }

            vm.evidence = evidence;
            vm.confidenceScore = Math.Min(100f, confidence);
            vm.isVirtualized = confidence >= 50f;
            vm.detectionMethod = "Multi-Layer Detection";
        }

#if UNITY_STANDALONE_WIN
        private bool CheckVMwareRegistry()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\VMware, Inc.\VMware Tools"))
                    return key != null;
            }
            catch { return false; }
        }

        private bool CheckVirtualBoxRegistry()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Oracle\VirtualBox Guest Additions"))
                    return key != null;
            }
            catch { return false; }
        }

        private bool CheckHyperVRegistry()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Virtual Machine\Guest"))
                    return key != null;
            }
            catch { return false; }
        }

        private bool CheckVirtualHardware()
        {
            var hw = currentFingerprint.hardware;

            // Check for virtual hardware indicators
            var virtualIndicators = new[] { "virtual", "vmware", "vbox", "qemu", "parallels" };

            return virtualIndicators.Any(indicator =>
                hw.graphicsDeviceName.ToLower().Contains(indicator) ||
                hw.processorType.ToLower().Contains(indicator));
        }

        private bool PerformTimingCheck()
        {
            const int iterations = 100;
            var timings = new List<long>();

            for (int i = 0; i < iterations; i++)
            {
                var start = DateTime.UtcNow.Ticks;

                // Operation that causes VM-exit
                var _ = SystemInfo.processorType;

                var end = DateTime.UtcNow.Ticks;
                timings.Add(end - start);
            }

            // Calculate variance
            var avg = timings.Average();
            var variance = timings.Sum(t => Math.Pow(t - avg, 2)) / timings.Count;

            // High variance indicates VM
            return variance > 5000;
        }
#endif

#if UNITY_ANDROID
        private bool CheckAndroidEmulator()
        {
            try
            {
                using (var build = new AndroidJavaClass("android.os.Build"))
                {
                    var fingerprint = build.GetStatic<string>("FINGERPRINT");
                    var model = build.GetStatic<string>("MODEL");
                    var manufacturer = build.GetStatic<string>("MANUFACTURER");
                    var hardware = build.GetStatic<string>("HARDWARE");
                    
                    var emulatorIndicators = new[]
                    {
                        "generic", "unknown", "emulator", "sdk", "google_sdk",
                        "goldfish", "vbox", "nox", "bluestacks", "genymotion"
                    };
                    
                    return emulatorIndicators.Any(indicator =>
                        fingerprint.ToLower().Contains(indicator) ||
                        model.ToLower().Contains(indicator) ||
                        manufacturer.ToLower().Contains(indicator) ||
                        hardware.ToLower().Contains(indicator));
                }
            }
            catch { return false; }
        }
        
        private bool CheckEmulatorBuild()
        {
            try
            {
                using (var systemProperties = new AndroidJavaClass("android.os.SystemProperties"))
                {
                    var qemuProps = new[]
                    {
                        "ro.kernel.qemu",
                        "ro.kernel.qemu.gles",
                        "init.svc.qemud",
                        "init.svc.qemu-props"
                    };
                    
                    foreach (var prop in qemuProps)
                    {
                        var value = systemProperties.CallStatic<string>("get", prop);
                        if (!string.IsNullOrEmpty(value))
                            return true;
                    }
                }
            }
            catch { }
            
            return false;
        }
#endif
        #endregion

        #region Risk Calculation
        private void CalculateRiskScore()
        {
            var risk = currentFingerprint.risk;
            risk.riskFactors.Clear();
            risk.detectedThreats.Clear();

            float totalScore = 0f;

            // VM/Emulator detection
            if (currentFingerprint.virtualization.isVirtualized)
            {
                var vmScore = (currentFingerprint.virtualization.confidenceScore / 100f) * vmDetectionWeight;
                risk.riskFactors["Virtualization"] = vmScore;
                risk.detectedThreats.Add("Virtual Machine/Emulator Detected");
                totalScore += vmScore;
            }

            // Emulator processes
            if (currentFingerprint.processes.knownEmulators.Count > 0)
            {
                risk.riskFactors["Emulator Processes"] = emulatorWeight;
                risk.detectedThreats.Add($"Emulator Processes: {string.Join(", ", currentFingerprint.processes.knownEmulators)}");
                totalScore += emulatorWeight;
            }

            // Cheat tools
            if (currentFingerprint.processes.knownCheatTools.Count > 0)
            {
                risk.riskFactors["Cheat Tools"] = cheatToolWeight;
                risk.detectedThreats.Add($"Cheat Tools: {string.Join(", ", currentFingerprint.processes.knownCheatTools)}");
                totalScore += cheatToolWeight;
            }

            // Suspicious processes
            if (currentFingerprint.processes.suspiciousProcesses.Count > 0)
            {
                risk.riskFactors["Suspicious Processes"] = suspiciousProcessWeight;
                risk.detectedThreats.Add($"Suspicious Processes: {string.Join(", ", currentFingerprint.processes.suspiciousProcesses)}");
                totalScore += suspiciousProcessWeight;
            }

            // Virtual network adapters
            if (currentFingerprint.network.hasVirtualAdapter)
            {
                risk.riskFactors["Virtual Network"] = virtualNetworkWeight;
                risk.detectedThreats.Add($"Virtual Network Adapters: {string.Join(", ", currentFingerprint.network.virtualAdapterNames)}");
                totalScore += virtualNetworkWeight;
            }

            // Additional risk factors based on platform
#if UNITY_ANDROID
           // Check for rooted device
           if (IsDeviceRooted())
           {
               risk.riskFactors["Rooted Device"] = 30f;
               risk.detectedThreats.Add("Device is Rooted");
               totalScore += 30f;
           }
           
           // Check for suspicious packages
           if (HasSuspiciousPackages())
           {
               risk.riskFactors["Suspicious Packages"] = 20f;
               risk.detectedThreats.Add("Suspicious Packages Installed");
               totalScore += 20f;
           }
#endif

#if UNITY_STANDALONE_WIN
            // Check for debugger
            if (IsDebuggerPresent())
            {
                risk.riskFactors["Debugger"] = 40f;
                risk.detectedThreats.Add("Debugger Detected");
                totalScore += 40f;
            }

            // Check for code injection
            if (DetectCodeInjection())
            {
                risk.riskFactors["Code Injection"] = 50f;
                risk.detectedThreats.Add("Code Injection Detected");
                totalScore += 50f;
            }
#endif

            // Calculate final risk score (0-100)
            risk.totalRiskScore = Math.Min(100f, totalScore);

            // Determine risk level
            if (risk.totalRiskScore >= 80f)
            {
                risk.riskLevel = "CRITICAL";
                risk.shouldBlock = true;
            }
            else if (risk.totalRiskScore >= 60f)
            {
                risk.riskLevel = "HIGH";
                risk.shouldBlock = risk.totalRiskScore >= riskThreshold;
            }
            else if (risk.totalRiskScore >= 40f)
            {
                risk.riskLevel = "MEDIUM";
                risk.shouldBlock = false;
            }
            else if (risk.totalRiskScore >= 20f)
            {
                risk.riskLevel = "LOW";
                risk.shouldBlock = false;
            }
            else
            {
                risk.riskLevel = "SAFE";
                risk.shouldBlock = false;
            }
        }

#if UNITY_ANDROID
       private bool IsDeviceRooted()
       {
           try
           {
               // Check for root indicators
               var rootIndicators = new[]
               {
                   "/system/app/Superuser.apk",
                   "/sbin/su",
                   "/system/bin/su",
                   "/system/xbin/su",
                   "/data/local/xbin/su",
                   "/data/local/bin/su",
                   "/system/sd/xbin/su",
                   "/system/bin/failsafe/su",
                   "/data/local/su"
               };
               
               using (var file = new AndroidJavaClass("java.io.File"))
               {
                   foreach (var path in rootIndicators)
                   {
                       var f = new AndroidJavaObject("java.io.File", path);
                       if (f.Call<bool>("exists"))
                           return true;
                   }
               }
               
               // Check for root packages
               var rootPackages = new[]
               {
                   "com.topjohnwu.magisk",
                   "com.koushikdutta.superuser",
                   "com.noshufou.android.su",
                   "com.thirdparty.superuser",
                   "eu.chainfire.supersu"
               };
               
               foreach (var package in rootPackages)
               {
                   if (IsPackageInstalled(package))
                       return true;
               }
           }
           catch { }
           
           return false;
       }
       
       private bool HasSuspiciousPackages()
       {
           var suspiciousPackages = new[]
           {
               "com.chelpus.lackypatch",
               "com.dimonvideo.luckypatcher",
               "com.forpda.lp",
               "com.android.vending.billing.InAppBillingService.COIN",
               "com.android.protips"
           };
           
           foreach (var package in suspiciousPackages)
           {
               if (IsPackageInstalled(package))
                   return true;
           }
           
           return false;
       }
#endif

#if UNITY_STANDALONE_WIN
        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        private bool DetectCodeInjection()
        {
            try
            {
                // Check for injected DLLs
                var process = Process.GetCurrentProcess();
                var modules = process.Modules;

                var suspiciousDlls = new[]
                {
                   "speedhack", "cheatengine", "inject", "hook",
                   "hack", "cheat", "trainer", "mod"
               };

                foreach (ProcessModule module in modules)
                {
                    var moduleName = module.ModuleName.ToLower();
                    if (suspiciousDlls.Any(dll => moduleName.Contains(dll)))
                        return true;
                }
            }
            catch { }

            return false;
        }
#endif
        #endregion

        #region Utility Methods
        private string GenerateFingerprintHash()
        {
            var data = new List<string>();

            // Hardware
            var hw = currentFingerprint.hardware;
            data.Add(hw.deviceId);
            data.Add(hw.motherboardSerial);
            data.Add(hw.biosSerial);
            data.Add(hw.cpuId);
            data.AddRange(hw.diskSerials);
            data.AddRange(hw.macAddresses);

            // Create combined hash
            var combined = string.Join("|", data.Where(s => !string.IsNullOrEmpty(s)));

            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(combined));
                return Convert.ToBase64String(hashBytes);
            }
        }

        private void MainThreadDispatcher(Action action)
        {
            UnityMainThreadDispatcher.Instance.Enqueue(action);
        }

        private void HandleSecurityViolation()
        {
            if (enableDebugMode)
            {
                UnityEngine.Debug.LogError($"[AntiCheat] SECURITY VIOLATION DETECTED!");
                UnityEngine.Debug.LogError($"[AntiCheat] Risk Score: {currentFingerprint.risk.totalRiskScore}");
                UnityEngine.Debug.LogError($"[AntiCheat] Risk Level: {currentFingerprint.risk.riskLevel}");
                UnityEngine.Debug.LogError($"[AntiCheat] Threats: {string.Join(", ", currentFingerprint.risk.detectedThreats)}");

                // Log full JSON for debugging
                UnityEngine.Debug.LogError($"[AntiCheat] Full Report:\n{GetFingerprintJSON()}");
            }

            // Send to server or take action
            OnSecurityViolationDetected?.Invoke(currentFingerprint);
        }
        #endregion

        #region Events
        public static event Action<SystemFingerprint> OnSecurityViolationDetected;
        #endregion
    }

    /// <summary>
    /// Helper class for main thread execution
    /// </summary>
    public class UnityMainThreadDispatcher : MonoBehaviour
    {
        private static UnityMainThreadDispatcher _instance;
        private static readonly Queue<Action> _executionQueue = new Queue<Action>();

        public static UnityMainThreadDispatcher Instance
        {
            get
            {
                if (_instance == null)
                {
                    var go = new GameObject("MainThreadDispatcher");
                    _instance = go.AddComponent<UnityMainThreadDispatcher>();
                    DontDestroyOnLoad(go);
                }
                return _instance;
            }
        }

        void Update()
        {
            lock (_executionQueue)
            {
                while (_executionQueue.Count > 0)
                {
                    _executionQueue.Dequeue()?.Invoke();
                }
            }
        }

        public void Enqueue(Action action)
        {
            lock (_executionQueue)
            {
                _executionQueue.Enqueue(action);
            }
        }
    }

    /// <summary>
    /// Test component for debugging
    /// </summary>
    public class AntiCheatTester : MonoBehaviour
    {
        [Header("Test Controls")]
        [SerializeField] private bool autoTest = true;
        [SerializeField] private float testDelay = 3f;

        [Header("Test Results")]
        [SerializeField] private bool testCompleted = false;
        [SerializeField] private float lastRiskScore = 0f;
        [SerializeField] private string lastRiskLevel = "";
        [SerializeField] private bool systemBlocked = false;

        [Header("JSON Output")]
        [TextArea(20, 50)]
        [SerializeField] private string fingerprintJSON = "";

        void Start()
        {
            if (autoTest)
            {
                Invoke(nameof(RunTest), testDelay);
            }

            // Subscribe to events
            UnifiedAntiCheatSystem.OnSecurityViolationDetected += OnViolationDetected;
        }

        void OnDestroy()
        {
            UnifiedAntiCheatSystem.OnSecurityViolationDetected -= OnViolationDetected;
        }

        [ContextMenu("Run AntiCheat Test")]
        public void RunTest()
        {
            UnityEngine.Debug.Log("[AntiCheat Test] Starting comprehensive system scan...");

            var antiCheat = UnifiedAntiCheatSystem.Instance;
            antiCheat.Initialize();

            // Wait a frame for initialization
            StartCoroutine(GetTestResults());
        }

        private IEnumerator GetTestResults()
        {
            yield return new WaitForSeconds(1f);

            var antiCheat = UnifiedAntiCheatSystem.Instance;

            // Get results
            fingerprintJSON = antiCheat.GetFingerprintJSON();
            lastRiskScore = antiCheat.GetRiskScore();
            systemBlocked = !antiCheat.IsSystemSafe();

            var fingerprint = antiCheat.GetCurrentFingerprint();
            if (fingerprint != null && fingerprint.risk != null)
            {
                lastRiskLevel = fingerprint.risk.riskLevel;
            }

            testCompleted = true;

            // Log results
            UnityEngine.Debug.Log($"[AntiCheat Test] Test completed!");
            UnityEngine.Debug.Log($"[AntiCheat Test] Risk Score: {lastRiskScore}");
            UnityEngine.Debug.Log($"[AntiCheat Test] Risk Level: {lastRiskLevel}");
            UnityEngine.Debug.Log($"[AntiCheat Test] System Blocked: {systemBlocked}");
            UnityEngine.Debug.Log($"[AntiCheat Test] JSON Output:\n{fingerprintJSON}");

            // Detailed breakdown
            if (fingerprint != null)
            {
                UnityEngine.Debug.Log($"[AntiCheat Test] === DETAILED REPORT ===");
                UnityEngine.Debug.Log($"Platform: {fingerprint.platform}");
                UnityEngine.Debug.Log($"Device ID: {fingerprint.hardware.deviceId}");
                UnityEngine.Debug.Log($"Is Virtualized: {fingerprint.virtualization.isVirtualized}");
                UnityEngine.Debug.Log($"VM Confidence: {fingerprint.virtualization.confidenceScore}%");

                if (fingerprint.virtualization.evidence.Count > 0)
                {
                    UnityEngine.Debug.Log($"VM Evidence: {string.Join(", ", fingerprint.virtualization.evidence)}");
                }

                if (fingerprint.processes.knownEmulators.Count > 0)
                {
                    UnityEngine.Debug.LogWarning($"Emulators Found: {string.Join(", ", fingerprint.processes.knownEmulators)}");
                }

                if (fingerprint.processes.knownCheatTools.Count > 0)
                {
                    UnityEngine.Debug.LogError($"Cheat Tools Found: {string.Join(", ", fingerprint.processes.knownCheatTools)}");
                }

                if (fingerprint.risk.detectedThreats.Count > 0)
                {
                    UnityEngine.Debug.LogError($"Threats Detected: {string.Join(", ", fingerprint.risk.detectedThreats)}");
                }
            }
        }

        private void OnViolationDetected(UnifiedAntiCheatSystem.SystemFingerprint fingerprint)
        {
            UnityEngine.Debug.LogError($"[AntiCheat Test] VIOLATION DETECTED! Risk Score: {fingerprint.risk.totalRiskScore}");
        }

        [ContextMenu("Export JSON to File")]
        public void ExportJSON()
        {
            if (string.IsNullOrEmpty(fingerprintJSON))
            {
                UnityEngine.Debug.LogError("No fingerprint data to export. Run test first!");
                return;
            }

            var path = Application.persistentDataPath + "/anticheat_fingerprint.json";
            System.IO.File.WriteAllText(path, fingerprintJSON);
            UnityEngine.Debug.Log($"Fingerprint exported to: {path}");
        }
    }
}