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
using System.Net;
using System.IO;
using System.Text;
using Newtonsoft.Json;

using Debug = UnityEngine.Debug;
#if UNITY_STANDALONE_WIN
using Microsoft.Win32;
using System.Diagnostics;
using System.Management;
#endif
#if UNITY_ANDROID
using UnityEngine.Android;
#endif
namespace AntiCheatSystem
{
    /// <summary>
    /// Geliştirilmiş AntiCheat Sistemi - Tüm platformları destekler
    /// Detaylı donanım, ağ, sistem bilgisi toplama ve VM/Emülatör tespiti
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
            public string uniqueId; // SHA-256 Hash
            public float dataCollectionTime; // Veri toplama süresi (ms)

            // Detaylı bilgiler
            public HardwareInfo hardware;
            public NetworkInfo network;
            public SystemInfo systemInfo;
            public VirtualizationInfo virtualization;
            public EmulatorInfo emulator;
            public SecurityInfo security;
            public PerformanceInfo performance;
            public ProcessInfo processes;
            public RiskAnalysis risk;

            // Özet hash
            public string fingerprintHash;
        }

        [System.Serializable]
        public class HardwareInfo
        {
            // CPU Bilgileri
            public string cpuId;
            public string cpuName;
            public int cpuCoreCount;
            public int cpuThreadCount;
            public int cpuFrequency;
            public string cpuArchitecture;

            // Anakart ve BIOS
            public string motherboardId;
            public string motherboardManufacturer;
            public string motherboardProduct;
            public string biosVersion;
            public string biosManufacturer;
            public string biosSerialNumber;

            // RAM
            public int totalRamMB;
            public int availableRamMB;
            public string ramType;
            public int ramSpeed;

            // Disk Bilgileri
            public List<DiskInfo> disks = new List<DiskInfo>();

            // GPU Bilgileri  
            public List<GPUInfo> gpus = new List<GPUInfo>();

            // USB Cihazları
            public List<USBDevice> usbDevices = new List<USBDevice>();

            // Diğer
            public string deviceId;
            public string deviceModel;
            public string deviceName;
            public string deviceType;
        }

        [System.Serializable]
        public class DiskInfo
        {
            public string serialNumber;
            public string model;
            public string interfaceType;
            public long totalSizeGB;
            public long freeSizeGB;
            public string fileSystem;
            public string installDate;
        }

        [System.Serializable]
        public class GPUInfo
        {
            public string name;
            public string deviceId;
            public int videoMemoryMB;
            public string driverVersion;
            public string vendor;
        }

        [System.Serializable]
        public class USBDevice
        {
            public string deviceId;
            public string name;
            public string manufacturer;
            public string deviceClass;
        }

        [System.Serializable]
        public class NetworkInfo
        {
            public List<NetworkAdapter> adapters = new List<NetworkAdapter>();
            public string publicIp;
            public string gatewayIp;
            public List<string> dnsServers = new List<string>();
            public List<ARPEntry> arpTable = new List<ARPEntry>();
            public List<string> networkShares = new List<string>();
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
            public string type; // Ethernet/Wireless
            public bool isWireless;
            public string manufacturer;
            public List<string> ipAddresses = new List<string>();
            public bool isVirtual;
            public long speed;
            public string status;
        }

        [System.Serializable]
        public class ARPEntry
        {
            public string ipAddress;
            public string macAddress;
            public string type;
        }

        [System.Serializable]
        public class SystemInfo
        {
            public string osName;
            public string osVersion;
            public string osBuild;
            public string osArchitecture;
            public string computerName;
            public string userName;
            public string domainName;
            public string systemBootTime;
            public string osInstallDate;
            public List<string> installedSoftware = new List<string>();
            public List<string> runningProcesses = new List<string>();
            public List<string> systemServices = new List<string>();
            public List<string> startupPrograms = new List<string>();
            public string systemLanguage;
            public string timeZone;
        }

        [System.Serializable]
        public class VirtualizationInfo
        {
            public bool isVirtualized;
            public string hypervisorType; // VMware/VirtualBox/Hyper-V/QEMU/None
            public List<string> vmIndicators = new List<string>();
            public bool vmwareToolsPresent;
            public bool vboxAdditionsPresent;
            public bool hyperVIntegrationPresent;
            public List<string> suspiciousProcesses = new List<string>();
            public List<string> suspiciousRegistryKeys = new List<string>();
            public List<string> vmHardwareSignatures = new List<string>();
            public List<string> vmBiosSignatures = new List<string>();
            public bool vmMacAddressDetected;
            public float confidenceScore;
            public string detectionMethod;
            public bool vmToolsInstalled;
        }

        [System.Serializable]
        public class EmulatorInfo
        {
            public bool isEmulator;
            public string emulatorType; // BlueStacks/Nox/LDPlayer/MEmu/None
            public List<string> emulatorIndicators = new List<string>();
            public bool androidEmulatorDetected;
            public bool iosSimulatorDetected;
            public List<string> emulatorFilePaths = new List<string>();
            public List<string> emulatorProcesses = new List<string>();
            public List<string> emulatorRegistryKeys = new List<string>();
            public bool deviceModelMismatch;
            public bool screenResolutionMismatch;
            public float confidenceScore;
            public string detectionMethod;
        }

        [System.Serializable]
        public class SecurityInfo
        {
            public bool debuggerPresent;
            public bool antivirusActive;
            public List<string> securitySoftwareList = new List<string>();
            public bool firewallEnabled;
            public List<int> openPorts = new List<int>();
            public bool hasAdminPrivileges;
            public List<string> analysisToolsDetected = new List<string>();
            public bool sandboxEnvironmentDetected;
            public bool mouseMovementAnomalyDetected;
            public float systemUptime;
            public bool rootedDevice;
            public bool jailbrokenDevice;
        }

        [System.Serializable]
        public class PerformanceInfo
        {
            public float cpuUsagePercent;
            public float memoryUsagePercent;
            public float gpuUsagePercent;
            public float diskUsagePercent;
            public List<float> cpuTimingTests = new List<float>();
            public List<float> memoryTimingTests = new List<float>();
            public float averageTestTime;
            public float timingVariance;
            public bool suspiciousTimingDetected;
            public float renderPerformanceScore;
            public bool memoryIntegrityValid;
        }

        [System.Serializable]
        public class ProcessInfo
        {
            public List<string> runningProcesses = new List<string>();
            public List<string> suspiciousProcesses = new List<string>();
            public List<string> knownCheatTools = new List<string>();
            public List<string> knownEmulators = new List<string>();
            public List<string> knownVMProcesses = new List<string>();
            public bool hasRiskyProcesses;
        }

        [System.Serializable]
        public class RiskAnalysis
        {
            public float totalRiskScore;
            public string riskLevel;
            public Dictionary<string, float> riskFactors = new Dictionary<string, float>();
            public List<string> detectedThreats = new List<string>();
            public bool shouldBlock;
        }
        #endregion

        #region Configuration
        [Header("AntiCheat Configuration")]
        [SerializeField] private bool enableDebugMode = true;
        [SerializeField] private float checkInterval = 30f;

        [Header("Detection Modules")]
        [SerializeField] private bool enableHardwareCheck = true;
        [SerializeField] private bool enableNetworkCheck = true;
        [SerializeField] private bool enableProcessCheck = true;
        [SerializeField] private bool enableVMDetection = true;
        [SerializeField] private bool enableEmulatorDetection = true;
        [SerializeField] private bool enableSecurityCheck = true;
        [SerializeField] private bool enablePerformanceCheck = true;
        #endregion

        #region Private Fields
        private SystemFingerprint currentFingerprint;
        private float scanStartTime;
        private DebugLogger debugLogger;

        // Known signatures - Genişletilmiş listeler
        private readonly HashSet<string> knownVMProcesses = new HashSet<string>
    {
        "vmtoolsd", "vmwaretray", "vmwareuser", "vmacthlp", "vmware",
        "vboxservice", "vboxtray", "vboxguest", "virtualbox",
        "xenservice", "qemu-ga", "qemu", "prl_cc", "prl_tools",
        "vmmemctl", "vmhgfs", "vmxnet", "vmci", "vsepflt"
    };

        private readonly HashSet<string> knownEmulatorProcesses = new HashSet<string>
    {
        // BlueStacks
        "bluestacks", "hd-player", "bstshutdown", "bstkern", "bstservice",
        "hd-logrotatorservice", "hd-blockdevice", "hd-network",
        
        // LDPlayer
        "ldplayer", "ldvboxheadless", "ldconsole", "dnplayer", "ldmnq",
        
        // Nox
        "nox", "noxvmhandle", "bignox", "noxd", "nox_adb",
        
        // MEmu
        "memu", "memuheadless", "memuconsole", "memuservice",
        
        // Diğer
        "droid4x", "ami_droid", "andy", "andyroid",
        "genymotion", "player", "virtualapp", "koplayer",
        "windroye", "microvirt", "tiantian", "qqplayer"
    };

        private readonly HashSet<string> knownCheatProcesses = new HashSet<string>
    {
        "cheatengine", "artmoney", "gameguardian", "speedhack",
        "processhacker", "ollydbg", "x64dbg", "ida", "ida64",
        "wireshark", "fiddler", "charles", "httpanalyzer",
        "sandboxie", "vmprotect", "themida", "enigma",
        "trainer", "injector", "bypass", "crack"
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
        { "52:54:00", "QEMU/KVM" },
        { "00:21:F6", "VirtualBox" },
        { "00:14:4F", "VirtualBox" },
        { "00:0F:4B", "VirtualBox" }
    };

        private readonly HashSet<string> vmHardwareVendors = new HashSet<string>
    {
        "vmware", "virtualbox", "vbox", "qemu", "virtual",
        "parallels", "xen", "kvm", "microsoft corporation",
        "oracle", "innotek", "red hat", "bochs"
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
            
            // DebugLogger'ı başlat
            InitializeDebugLogger();
        }

        void Start()
        {
            Initialize();
        }
        #endregion

        #region Debug Logger
        private void InitializeDebugLogger()
        {
            debugLogger = FindObjectOfType<DebugLogger>();
            if (debugLogger == null)
            {
                GameObject loggerObj = new GameObject("DebugLogger");
                debugLogger = loggerObj.AddComponent<DebugLogger>();
                DontDestroyOnLoad(loggerObj);
            }
        }
        
        private void LogDebug(string message)
        {
            if (debugLogger != null)
            {
                debugLogger.Log(message);
            }
            else if (enableDebugMode)
            {
                Debug.Log(message);
            }
            
            // Test mesajı - her zaman console'a yazdır
            Debug.Log($"[DebugLogger Test] {message}");
        }
        
        private void LogWarning(string message)
        {
            if (debugLogger != null)
            {
                debugLogger.LogWarning(message);
            }
            else if (enableDebugMode)
            {
                Debug.LogWarning(message);
            }
        }
        
        private void LogError(string message)
        {
            if (debugLogger != null)
            {
                debugLogger.LogError(message);
            }
            else if (enableDebugMode)
            {
                Debug.LogError(message);
            }
        }
        #endregion

        #region Public Methods
        public void Initialize()
        {
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
                UnityEngine.Debug.LogWarning("[AntiCheat] No fingerprint data! Running scan...");
                PerformFullSystemScan();
            }

            try
            {
                // Tüm veriyi içeren obje
                var dataForServer = new Dictionary<string, object>
                {
                    ["timestamp"] = currentFingerprint.timestamp,
                    ["platform"] = currentFingerprint.platform,
                    ["unityVersion"] = currentFingerprint.unityVersion,
                    ["gameVersion"] = currentFingerprint.gameVersion,
                    ["uniqueId"] = currentFingerprint.uniqueId,
                    ["dataCollectionTime"] = currentFingerprint.dataCollectionTime,
                    ["fingerprintHash"] = currentFingerprint.fingerprintHash,

                    // Detaylı veriler
                    ["hardware"] = currentFingerprint.hardware,
                    ["network"] = currentFingerprint.network,
                    ["system"] = currentFingerprint.systemInfo,
                    ["virtualization"] = currentFingerprint.virtualization,
                    ["emulator"] = currentFingerprint.emulator,
                    ["security"] = currentFingerprint.security,
                    ["performance"] = currentFingerprint.performance,
                    ["processes"] = new
                    {
                        runningProcesses = currentFingerprint.processes.runningProcesses,
                        suspiciousProcesses = currentFingerprint.processes.suspiciousProcesses,
                        knownCheatTools = currentFingerprint.processes.knownCheatTools,
                        knownEmulators = currentFingerprint.processes.knownEmulators,
                        knownVMProcesses = currentFingerprint.processes.knownVMProcesses,
                        hasRiskyProcesses = currentFingerprint.processes.hasRiskyProcesses
                    },
                    ["risk"] = new
                    {
                        totalRiskScore = currentFingerprint.risk.totalRiskScore,
                        riskLevel = currentFingerprint.risk.riskLevel,
                        detectedThreats = currentFingerprint.risk.detectedThreats,
                        shouldBlock = currentFingerprint.risk.shouldBlock
                    }
                };

                // JSON serialize - JsonUtility Dictionary ile çalışmaz, manuel oluştur
                string json = CreateManualJSON();

                LogDebug("[AntiCheat] Full Fingerprint JSON:");
                LogDebug(json);

                return json;
            }
            catch (Exception e)
            {
                UnityEngine.Debug.LogError($"[AntiCheat] JSON generation failed: {e.Message}");
                return "{}";
            }
        }

        public string GetSystemTypeDescription()
        {
            if (currentFingerprint == null) return "Unknown System";

            // Unity Editor kontrolü
            if (Application.isEditor)
            {
                return "Bu sistem Unity Editördür";
            }

            // Platform kontrolü
            string platform = currentFingerprint.platform?.ToLower() ?? "";

            // Emülatör kontrolü
            if (currentFingerprint.emulator != null && currentFingerprint.emulator.isEmulator)
            {
                string emulatorType = currentFingerprint.emulator.emulatorType?.ToLower() ?? "";
                if (emulatorType.Contains("bluestacks"))
                    return "Bu sistem BlueStacks emülatörüdür";
                else if (emulatorType.Contains("ldplayer"))
                    return "Bu sistem LDPlayer emülatörüdür";
                else if (emulatorType.Contains("nox"))
                    return "Bu sistem Nox emülatörüdür";
                else if (emulatorType.Contains("mumu"))
                    return "Bu sistem MuMu emülatörüdür";
                else if (emulatorType.Contains("genymotion"))
                    return "Bu sistem Genymotion emülatörüdür";
                else
                    return "Bu sistem bir emülatördür";
            }

            // Virtual Machine kontrolü
            if (currentFingerprint.virtualization != null && currentFingerprint.virtualization.isVirtualized)
            {
                string vmType = currentFingerprint.virtualization.hypervisorType?.ToLower() ?? "";
                if (vmType.Contains("vmware"))
                    return "Bu sistem VMware virtual machine'dir";
                else if (vmType.Contains("virtualbox"))
                    return "Bu sistem VirtualBox virtual machine'dir";
                else if (vmType.Contains("hyper-v"))
                    return "Bu sistem Hyper-V virtual machine'dir";
                else if (vmType.Contains("qemu"))
                    return "Bu sistem QEMU virtual machine'dir";
                else if (vmType.Contains("parallels"))
                    return "Bu sistem Parallels virtual machine'dir";
                else
                    return "Bu sistem bir virtual machine'dir";
            }

            // Platform bazlı sistem tipi
            if (platform.Contains("windows"))
                return "Bu sistem Windows işletim sistemidir";
            else if (platform.Contains("android"))
                return "Bu sistem Android telefondur";
            else if (platform.Contains("ios") || platform.Contains("iphone"))
                return "Bu sistem iPhone telefondur";
            else if (platform.Contains("macos") || platform.Contains("osx"))
                return "Bu sistem macOS işletim sistemidir";
            else if (platform.Contains("linux"))
                return "Bu sistem Linux işletim sistemidir";
            else if (platform.Contains("webgl"))
                return "Bu sistem WebGL tarayıcısıdır";

            return "Bu sistem bilinmeyen bir platformdur";
        }

        private string GetNetworkBandwidth()
        {
            if (currentFingerprint?.network?.adapters == null) return "Unknown";

            long totalSpeed = 0;
            foreach (var adapter in currentFingerprint.network.adapters)
            {
                if (!adapter.isVirtual) // Sadece fiziksel adaptörler
                {
                    totalSpeed += adapter.speed;
                }
            }

            if (totalSpeed >= 1000000000) // 1 Gbps
                return $"{totalSpeed / 1000000000} Gbps";
            else if (totalSpeed >= 1000000) // 1 Mbps
                return $"{totalSpeed / 1000000} Mbps";
            else if (totalSpeed >= 1000) // 1 Kbps
                return $"{totalSpeed / 1000} Kbps";
            else
                return $"{totalSpeed} bps";
        }

        private string GetEmulatorVersion()
        {
            if (currentFingerprint?.emulator?.emulatorType == null) return "Unknown";
            
            string emulatorType = currentFingerprint.emulator.emulatorType.ToLower();
            
            // Emülatör süreçlerinden versiyon bilgisi çıkarmaya çalış
            foreach (var process in currentFingerprint.processes?.runningProcesses ?? new List<string>())
            {
                if (emulatorType.Contains("bluestacks") && process.ToLower().Contains("bluestacks"))
                {
                    // BlueStacks versiyon bilgisi çıkarma
                    return "BlueStacks (Version detected from process)";
                }
                else if (emulatorType.Contains("ldplayer") && process.ToLower().Contains("ldplayer"))
                {
                    return "LDPlayer (Version detected from process)";
                }
                else if (emulatorType.Contains("nox") && process.ToLower().Contains("nox"))
                {
                    return "Nox Player (Version detected from process)";
                }
            }
            
            return $"{currentFingerprint.emulator.emulatorType} (Version unknown)";
        }

        private string GetAndroidVersion()
        {
            if (currentFingerprint?.systemInfo?.osVersion != null)
            {
                return currentFingerprint.systemInfo.osVersion;
            }
            
            // Android versiyonunu sistem bilgilerinden çıkarmaya çalış
            if (currentFingerprint?.platform?.ToLower().Contains("android") == true)
            {
                return "Android (Version from system info)";
            }
            
            return "Unknown";
        }

        private string CreateManualJSON()
        {
            if (currentFingerprint == null) return "{}";

            var json = new System.Text.StringBuilder();
            json.AppendLine("{");

            // Temel bilgiler
            json.AppendLine($"  \"timestamp\": \"{currentFingerprint.timestamp}\",");
            json.AppendLine($"  \"platform\": \"{currentFingerprint.platform}\",");
            json.AppendLine($"  \"unityVersion\": \"{currentFingerprint.unityVersion}\",");
            json.AppendLine($"  \"gameVersion\": \"{currentFingerprint.gameVersion}\",");
            json.AppendLine($"  \"uniqueId\": \"{currentFingerprint.uniqueId}\",");
            json.AppendLine($"  \"dataCollectionTime\": {currentFingerprint.dataCollectionTime},");
            json.AppendLine($"  \"systemType\": \"{GetSystemTypeDescription()}\",");

            // Hardware bilgileri
            if (currentFingerprint.hardware != null)
            {
                json.AppendLine("  \"hardware\": {");
                json.AppendLine($"    \"deviceId\": \"{currentFingerprint.hardware.deviceId}\",");
                json.AppendLine($"    \"deviceModel\": \"{currentFingerprint.hardware.deviceModel}\",");
                json.AppendLine($"    \"deviceName\": \"{currentFingerprint.hardware.deviceName}\",");
                json.AppendLine($"    \"deviceType\": \"{currentFingerprint.hardware.deviceType}\",");
                json.AppendLine($"    \"processorType\": \"{currentFingerprint.hardware.cpuName}\",");
                json.AppendLine($"    \"processorCount\": {currentFingerprint.hardware.cpuThreadCount},");
                json.AppendLine($"    \"processorFrequency\": {currentFingerprint.hardware.cpuCoreCount},");
                
                if (currentFingerprint.hardware.gpus.Count > 0)
                {
                    var gpu = currentFingerprint.hardware.gpus[0];
                    json.AppendLine($"    \"graphicsDeviceName\": \"{gpu.name}\",");
                    json.AppendLine($"    \"graphicsDeviceVendor\": \"{gpu.vendor}\",");
                    json.AppendLine($"    \"graphicsMemorySize\": {gpu.videoMemoryMB},");
                }
                else
                {
                    json.AppendLine($"    \"graphicsDeviceName\": \"Unknown\",");
                    json.AppendLine($"    \"graphicsDeviceVendor\": \"Unknown\",");
                    json.AppendLine($"    \"graphicsMemorySize\": 0,");
                }
                
                json.AppendLine($"    \"systemMemorySize\": {currentFingerprint.hardware.totalRamMB},");
                json.AppendLine($"    \"availableMemorySize\": {currentFingerprint.hardware.availableRamMB},");
                json.AppendLine($"    \"motherboardSerial\": \"{currentFingerprint.hardware.motherboardId}\",");
                json.AppendLine($"    \"motherboardManufacturer\": \"{currentFingerprint.hardware.motherboardManufacturer}\",");
                json.AppendLine($"    \"motherboardProduct\": \"{currentFingerprint.hardware.motherboardProduct}\",");
                json.AppendLine($"    \"biosSerial\": \"{currentFingerprint.hardware.biosSerialNumber}\",");
                json.AppendLine($"    \"biosVersion\": \"{currentFingerprint.hardware.biosVersion}\",");
                json.AppendLine($"    \"biosManufacturer\": \"{currentFingerprint.hardware.biosManufacturer}\",");
                json.AppendLine($"    \"cpuId\": \"{currentFingerprint.hardware.cpuId}\",");
                json.AppendLine($"    \"cpuCoreCount\": {currentFingerprint.hardware.cpuCoreCount},");
                json.AppendLine($"    \"cpuThreadCount\": {currentFingerprint.hardware.cpuThreadCount},");
                json.AppendLine($"    \"ramType\": \"{currentFingerprint.hardware.ramType}\",");
                json.AppendLine($"    \"ramSpeed\": {currentFingerprint.hardware.ramSpeed},");
                
                // Disk bilgileri
                json.AppendLine("    \"disks\": [");
                for (int i = 0; i < currentFingerprint.hardware.disks.Count; i++)
                {
                    var disk = currentFingerprint.hardware.disks[i];
                    json.AppendLine("      {");
                    json.AppendLine($"        \"serialNumber\": \"{disk.serialNumber}\",");
                    json.AppendLine($"        \"model\": \"{disk.model}\",");
                    json.AppendLine($"        \"interfaceType\": \"{disk.interfaceType}\",");
                    json.AppendLine($"        \"totalSizeGB\": {disk.totalSizeGB},");
                    json.AppendLine($"        \"freeSizeGB\": {disk.freeSizeGB},");
                    json.AppendLine($"        \"fileSystem\": \"{disk.fileSystem}\",");
                    json.AppendLine($"        \"installDate\": \"{disk.installDate}\"");
                    json.AppendLine("      }" + (i < currentFingerprint.hardware.disks.Count - 1 ? "," : ""));
                }
                json.AppendLine("    ],");
                
                // USB cihazları
                json.AppendLine("    \"usbDevices\": [");
                for (int i = 0; i < currentFingerprint.hardware.usbDevices.Count; i++)
                {
                    var usb = currentFingerprint.hardware.usbDevices[i];
                    json.AppendLine("      {");
                    json.AppendLine($"        \"deviceId\": \"{usb.deviceId}\",");
                    json.AppendLine($"        \"name\": \"{usb.name}\",");
                    json.AppendLine($"        \"manufacturer\": \"{usb.manufacturer}\",");
                    json.AppendLine($"        \"deviceClass\": \"{usb.deviceClass}\"");
                    json.AppendLine("      }" + (i < currentFingerprint.hardware.usbDevices.Count - 1 ? "," : ""));
                }
                json.AppendLine("    ],");
                
                // MAC adresleri
                json.Append("    \"macAddresses\": [");
                for (int i = 0; i < currentFingerprint.network.adapters.Count; i++)
                {
                    if (i > 0) json.Append(", ");
                    json.Append($"\"{currentFingerprint.network.adapters[i].macAddress}\"");
                }
                json.AppendLine("]");
                json.AppendLine("  },");
            }

            // Network bilgileri
            if (currentFingerprint.network != null)
            {
                json.AppendLine("  \"network\": {");
                json.AppendLine("    \"adapters\": [");
                for (int i = 0; i < currentFingerprint.network.adapters.Count; i++)
                {
                    var adapter = currentFingerprint.network.adapters[i];
                    json.AppendLine("      {");
                    json.AppendLine($"        \"name\": \"{adapter.name}\",");
                    json.AppendLine($"        \"description\": \"{adapter.description}\",");
                    json.AppendLine($"        \"macAddress\": \"{adapter.macAddress}\",");
                    json.AppendLine($"        \"type\": \"{adapter.type}\",");
                    json.AppendLine($"        \"isVirtual\": {adapter.isVirtual.ToString().ToLower()},");
                    json.AppendLine($"        \"speed\": {adapter.speed}");
                    json.AppendLine("      }" + (i < currentFingerprint.network.adapters.Count - 1 ? "," : ""));
                }
                json.AppendLine("    ],");
                json.AppendLine($"    \"publicIp\": \"{currentFingerprint.network.publicIp}\",");
                json.AppendLine($"    \"gatewayIp\": \"{currentFingerprint.network.gatewayIp}\",");
                json.AppendLine($"    \"hasVirtualAdapter\": {currentFingerprint.network.hasVirtualAdapter.ToString().ToLower()},");
                
                json.Append("    \"virtualAdapterNames\": [");
                for (int i = 0; i < currentFingerprint.network.virtualAdapterNames.Count; i++)
                {
                    if (i > 0) json.Append(", ");
                    json.Append($"\"{currentFingerprint.network.virtualAdapterNames[i]}\"");
                }
                json.AppendLine("],");
                json.AppendLine($"    \"networkTopology\": \"{currentFingerprint.network.networkTopology}\"");
                json.AppendLine("  },");
            }

            // Processes bilgileri
            if (currentFingerprint.processes != null)
            {
                json.AppendLine("  \"processes\": {");
                json.Append("    \"runningProcesses\": [");
                for (int i = 0; i < currentFingerprint.processes.runningProcesses.Count; i++)
                {
                    if (i > 0) json.Append(", ");
                    json.Append($"\"{currentFingerprint.processes.runningProcesses[i]}\"");
                }
                json.AppendLine("],");
                
                json.Append("    \"suspiciousProcesses\": [");
                for (int i = 0; i < currentFingerprint.processes.suspiciousProcesses.Count; i++)
                {
                    if (i > 0) json.Append(", ");
                    json.Append($"\"{currentFingerprint.processes.suspiciousProcesses[i]}\"");
                }
                json.AppendLine("],");
                
                json.Append("    \"knownCheatTools\": [");
                for (int i = 0; i < currentFingerprint.processes.knownCheatTools.Count; i++)
                {
                    if (i > 0) json.Append(", ");
                    json.Append($"\"{currentFingerprint.processes.knownCheatTools[i]}\"");
                }
                json.AppendLine("],");
                
                json.Append("    \"knownEmulators\": [");
                for (int i = 0; i < currentFingerprint.processes.knownEmulators.Count; i++)
                {
                    if (i > 0) json.Append(", ");
                    json.Append($"\"{currentFingerprint.processes.knownEmulators[i]}\"");
                }
                json.AppendLine("],");
                
                json.AppendLine($"    \"hasRiskyProcesses\": {currentFingerprint.processes.hasRiskyProcesses.ToString().ToLower()}");
                json.AppendLine("  },");
            }

            // Virtualization bilgileri
            if (currentFingerprint.virtualization != null)
            {
                json.AppendLine("  \"virtualization\": {");
                json.AppendLine($"    \"isVirtualized\": {currentFingerprint.virtualization.isVirtualized.ToString().ToLower()},");
                json.AppendLine($"    \"hypervisorType\": \"{currentFingerprint.virtualization.hypervisorType}\",");
                json.AppendLine($"    \"detectionMethod\": \"{currentFingerprint.virtualization.detectionMethod}\",");
                json.AppendLine($"    \"confidenceScore\": {currentFingerprint.virtualization.confidenceScore},");
                
                // VM kaynak bilgileri (eğer VM ise)
                if (currentFingerprint.virtualization.isVirtualized)
                {
                    json.AppendLine("    \"vmResources\": {");
                    json.AppendLine($"      \"allocatedRAM\": {currentFingerprint.hardware?.totalRamMB ?? 0},");
                    json.AppendLine($"      \"allocatedCPU\": {currentFingerprint.hardware?.cpuCoreCount ?? 0},");
                    json.AppendLine($"      \"allocatedStorage\": {currentFingerprint.hardware?.disks?.Sum(d => d.totalSizeGB) ?? 0},");
                    json.AppendLine($"      \"networkBandwidth\": \"{GetNetworkBandwidth()}\",");
                    json.AppendLine($"      \"vmToolsInstalled\": {currentFingerprint.virtualization.vmToolsInstalled.ToString().ToLower()}");
                    json.AppendLine("    },");
                }
                
                json.Append("    \"evidence\": [");
                for (int i = 0; i < currentFingerprint.virtualization.vmIndicators.Count; i++)
                {
                    if (i > 0) json.Append(", ");
                    json.Append($"\"{currentFingerprint.virtualization.vmIndicators[i]}\"");
                }
                json.AppendLine("],");
                
                json.Append("    \"suspiciousProcesses\": [");
                for (int i = 0; i < currentFingerprint.virtualization.suspiciousProcesses.Count; i++)
                {
                    if (i > 0) json.Append(", ");
                    json.Append($"\"{currentFingerprint.virtualization.suspiciousProcesses[i]}\"");
                }
                json.AppendLine("]");
                json.AppendLine("  },");
            }

            // System Info
            if (currentFingerprint.systemInfo != null)
            {
                json.AppendLine("  \"systemInfo\": {");
                json.AppendLine($"    \"osName\": \"{currentFingerprint.systemInfo.osName}\",");
                json.AppendLine($"    \"osVersion\": \"{currentFingerprint.systemInfo.osVersion}\",");
                json.AppendLine($"    \"osBuild\": \"{currentFingerprint.systemInfo.osBuild}\",");
                json.AppendLine($"    \"osArchitecture\": \"{currentFingerprint.systemInfo.osArchitecture}\",");
                json.AppendLine($"    \"computerName\": \"{currentFingerprint.systemInfo.computerName}\",");
                json.AppendLine($"    \"userName\": \"{currentFingerprint.systemInfo.userName}\",");
                json.AppendLine($"    \"domainName\": \"{currentFingerprint.systemInfo.domainName}\",");
                json.AppendLine($"    \"systemBootTime\": \"{currentFingerprint.systemInfo.systemBootTime}\",");
                json.AppendLine($"    \"osInstallDate\": \"{currentFingerprint.systemInfo.osInstallDate}\",");
                json.AppendLine($"    \"systemLanguage\": \"{currentFingerprint.systemInfo.systemLanguage}\",");
                json.AppendLine($"    \"timeZone\": \"{currentFingerprint.systemInfo.timeZone}\"");
                json.AppendLine("  },");
            }

            // Security Info
            if (currentFingerprint.security != null)
            {
                json.AppendLine("  \"security\": {");
                json.AppendLine($"    \"debuggerPresent\": {currentFingerprint.security.debuggerPresent.ToString().ToLower()},");
                json.AppendLine($"    \"antivirusActive\": {currentFingerprint.security.antivirusActive.ToString().ToLower()},");
                json.AppendLine($"    \"firewallEnabled\": {currentFingerprint.security.firewallEnabled.ToString().ToLower()},");
                json.AppendLine($"    \"hasAdminPrivileges\": {currentFingerprint.security.hasAdminPrivileges.ToString().ToLower()},");
                json.AppendLine($"    \"sandboxEnvironmentDetected\": {currentFingerprint.security.sandboxEnvironmentDetected.ToString().ToLower()},");
                json.AppendLine($"    \"mouseMovementAnomalyDetected\": {currentFingerprint.security.mouseMovementAnomalyDetected.ToString().ToLower()},");
                json.AppendLine($"    \"systemUptime\": {currentFingerprint.security.systemUptime},");
                json.AppendLine($"    \"rootedDevice\": {currentFingerprint.security.rootedDevice.ToString().ToLower()},");
                json.AppendLine($"    \"jailbrokenDevice\": {currentFingerprint.security.jailbrokenDevice.ToString().ToLower()},");
                
                json.Append("    \"analysisToolsDetected\": [");
                for (int i = 0; i < currentFingerprint.security.analysisToolsDetected.Count; i++)
                {
                    if (i > 0) json.Append(", ");
                    json.Append($"\"{currentFingerprint.security.analysisToolsDetected[i]}\"");
                }
                json.AppendLine("]");
                json.AppendLine("  },");
            }

            // Performance Info
            if (currentFingerprint.performance != null)
            {
                json.AppendLine("  \"performance\": {");
                json.AppendLine($"    \"cpuUsagePercent\": {currentFingerprint.performance.cpuUsagePercent},");
                json.AppendLine($"    \"memoryUsagePercent\": {currentFingerprint.performance.memoryUsagePercent},");
                json.AppendLine($"    \"gpuUsagePercent\": {currentFingerprint.performance.gpuUsagePercent},");
                json.AppendLine($"    \"diskUsagePercent\": {currentFingerprint.performance.diskUsagePercent},");
                json.AppendLine($"    \"averageTestTime\": {currentFingerprint.performance.averageTestTime},");
                json.AppendLine($"    \"timingVariance\": {currentFingerprint.performance.timingVariance},");
                json.AppendLine($"    \"suspiciousTimingDetected\": {currentFingerprint.performance.suspiciousTimingDetected.ToString().ToLower()},");
                json.AppendLine($"    \"renderPerformanceScore\": {currentFingerprint.performance.renderPerformanceScore},");
                json.AppendLine($"    \"memoryIntegrityValid\": {currentFingerprint.performance.memoryIntegrityValid.ToString().ToLower()}");
                json.AppendLine("  },");
            }

            // Emulator Info
            if (currentFingerprint.emulator != null)
            {
                json.AppendLine("  \"emulator\": {");
                json.AppendLine($"    \"isEmulator\": {currentFingerprint.emulator.isEmulator.ToString().ToLower()},");
                json.AppendLine($"    \"emulatorType\": \"{currentFingerprint.emulator.emulatorType}\",");
                json.AppendLine($"    \"confidenceScore\": {currentFingerprint.emulator.confidenceScore},");
                json.AppendLine($"    \"detectionMethod\": \"{currentFingerprint.emulator.detectionMethod}\",");
                json.AppendLine($"    \"deviceModelMismatch\": {currentFingerprint.emulator.deviceModelMismatch.ToString().ToLower()},");
                json.AppendLine($"    \"screenResolutionMismatch\": {currentFingerprint.emulator.screenResolutionMismatch.ToString().ToLower()},");
                
                // Emülatör kaynak bilgileri (eğer emülatör ise)
                if (currentFingerprint.emulator.isEmulator)
                {
                    json.AppendLine("    \"emulatorResources\": {");
                    json.AppendLine($"      \"allocatedRAM\": {currentFingerprint.hardware?.totalRamMB ?? 0},");
                    json.AppendLine($"      \"allocatedCPU\": {currentFingerprint.hardware?.cpuCoreCount ?? 0},");
                    json.AppendLine($"      \"allocatedStorage\": {currentFingerprint.hardware?.disks?.Sum(d => d.totalSizeGB) ?? 0},");
                    json.AppendLine($"      \"networkBandwidth\": \"{GetNetworkBandwidth()}\",");
                    json.AppendLine($"      \"emulatorVersion\": \"{GetEmulatorVersion()}\",");
                    json.AppendLine($"      \"androidVersion\": \"{GetAndroidVersion()}\"");
                    json.AppendLine("    },");
                }
                
                json.Append("    \"emulatorIndicators\": [");
                for (int i = 0; i < currentFingerprint.emulator.emulatorIndicators.Count; i++)
                {
                    if (i > 0) json.Append(", ");
                    json.Append($"\"{currentFingerprint.emulator.emulatorIndicators[i]}\"");
                }
                json.AppendLine("],");
                
                json.Append("    \"emulatorProcesses\": [");
                for (int i = 0; i < currentFingerprint.emulator.emulatorProcesses.Count; i++)
                {
                    if (i > 0) json.Append(", ");
                    json.Append($"\"{currentFingerprint.emulator.emulatorProcesses[i]}\"");
                }
                json.AppendLine("]");
                json.AppendLine("  },");
            }

            // Risk bilgileri
            if (currentFingerprint.risk != null)
            {
                json.AppendLine("  \"risk\": {");
                json.AppendLine($"    \"totalRiskScore\": {currentFingerprint.risk.totalRiskScore},");
                json.AppendLine($"    \"riskLevel\": \"{currentFingerprint.risk.riskLevel}\",");
                
                json.Append("    \"detectedThreats\": [");
                for (int i = 0; i < currentFingerprint.risk.detectedThreats.Count; i++)
                {
                    if (i > 0) json.Append(", ");
                    json.Append($"\"{currentFingerprint.risk.detectedThreats[i]}\"");
                }
                json.AppendLine("],");
                json.AppendLine($"    \"shouldBlock\": {currentFingerprint.risk.shouldBlock.ToString().ToLower()}");
                json.AppendLine("  },");
            }

            json.AppendLine($"  \"fingerprintHash\": \"{currentFingerprint.fingerprintHash}\"");
            json.AppendLine("}");

            return json.ToString();
        }

        public float GetRiskScore()
        {
            return currentFingerprint?.risk?.totalRiskScore ?? 0f;
        }

        public void SaveJSONToFile(string json)
        {
            try
            {
                string fileName = $"anticheat_data_{DateTime.Now:yyyyMMdd_HHmmss}.json";
                string path = Path.Combine(Application.persistentDataPath, fileName);
                File.WriteAllText(path, json);

                // Path'i clipboard'a kopyala (kolay erişim için)
                GUIUtility.systemCopyBuffer = path;
            }
            catch (Exception e)
            {
                UnityEngine.Debug.LogError($"[AntiCheat] Failed to save JSON: {e.Message}");
            }
        }

        public bool IsSystemSafe()
        {
            return currentFingerprint?.risk?.shouldBlock == false;
        }
        #endregion

        #region Core Detection Logic
        private IEnumerator InitialCheck()
        {
            yield return new WaitForSeconds(1f);

            PerformFullSystemScan();

            if (enableDebugMode)
            {
                // Risk bilgilerini göster
                string systemType = GetSystemTypeDescription();
                LogDebug($"Risk Score: {currentFingerprint.risk.totalRiskScore}% - {currentFingerprint.risk.riskLevel} | {systemType}");
                
                if (currentFingerprint.risk.detectedThreats.Count > 0)
                {
                    LogDebug($"Risk Sebepleri: {string.Join(", ", currentFingerprint.risk.detectedThreats)}");
                }
                else
                {
                    LogDebug("Risk Sebepleri: Temiz sistem - risk tespit edilmedi");
                }
            }

            // JSON'u her zaman göster
            string json = GetFingerprintJSON();
        }

        private void PerformRuntimeCheck()
        {
            PerformFullSystemScan();

            if (currentFingerprint.risk.shouldBlock)
            {
                HandleSecurityViolation();
            }
        }

        private void PerformFullSystemScan()
        {
            scanStartTime = Time.realtimeSinceStartup;

            currentFingerprint = new SystemFingerprint
            {
                timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
                platform = Application.platform.ToString(),
                unityVersion = Application.unityVersion,
                gameVersion = Application.version,
                hardware = new HardwareInfo(),
                network = new NetworkInfo(),
                systemInfo = new SystemInfo(),
                virtualization = new VirtualizationInfo(),
                emulator = new EmulatorInfo(),
                security = new SecurityInfo(),
                performance = new PerformanceInfo(),
                processes = new ProcessInfo(),
                risk = new RiskAnalysis()
            };

            // Collect all data
            if (enableHardwareCheck)
                CollectHardwareInfo();

            if (enableNetworkCheck)
                CollectNetworkInfo();

            CollectSystemInfo();

            if (enableProcessCheck)
                CollectProcessInfo();

            if (enableVMDetection)
                DetectVirtualization();

            if (enableEmulatorDetection)
                DetectEmulator();

            if (enableSecurityCheck)
                CollectSecurityInfo();

            if (enablePerformanceCheck)
                CollectPerformanceInfo();

            // Calculate risk
            CalculateRiskScore();

            // Generate IDs
            currentFingerprint.uniqueId = GenerateUniqueId();
            currentFingerprint.fingerprintHash = GenerateFingerprintHash();
            currentFingerprint.dataCollectionTime = (Time.realtimeSinceStartup - scanStartTime) * 1000f; // ms
        }
        #endregion

        #region Hardware Collection
        private void CollectHardwareInfo()
        {
            var hw = currentFingerprint.hardware;

            // Unity built-in info
            hw.deviceId = UnityEngine.SystemInfo.deviceUniqueIdentifier;
            hw.deviceModel = UnityEngine.SystemInfo.deviceModel;
            hw.deviceName = UnityEngine.SystemInfo.deviceName;
            hw.deviceType = UnityEngine.SystemInfo.deviceType.ToString();

            // CPU
            hw.cpuName = UnityEngine.SystemInfo.processorType;
            hw.cpuCoreCount = UnityEngine.SystemInfo.processorCount;
            hw.cpuFrequency = UnityEngine.SystemInfo.processorFrequency;
            hw.cpuArchitecture = System.Environment.Is64BitOperatingSystem ? "x64" : "x86";

            // RAM
            hw.totalRamMB = UnityEngine.SystemInfo.systemMemorySize;

            // GPU
            var gpu = new GPUInfo
            {
                name = UnityEngine.SystemInfo.graphicsDeviceName,
                vendor = UnityEngine.SystemInfo.graphicsDeviceVendor,
                videoMemoryMB = UnityEngine.SystemInfo.graphicsMemorySize,
                deviceId = UnityEngine.SystemInfo.graphicsDeviceID.ToString(),
                driverVersion = UnityEngine.SystemInfo.graphicsDeviceVersion
            };
            hw.gpus.Add(gpu);
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
                // WMI üzerinden detaylı bilgi toplama
                CollectWindowsCPUInfo();
                CollectWindowsMotherboardInfo();
                CollectWindowsBIOSInfo();
                CollectWindowsRAMInfo();
                CollectWindowsDiskInfo();
                CollectWindowsUSBInfo();

                // Thread sayısını hesapla
                hw.cpuThreadCount = Environment.ProcessorCount;
            }
            catch (Exception e)
            {
                UnityEngine.Debug.LogWarning($"[AntiCheat] Windows hardware collection error: {e.Message}");
            }
        }

        private void CollectWindowsCPUInfo()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        currentFingerprint.hardware.cpuId = obj["ProcessorId"]?.ToString() ?? "Unknown";
                        currentFingerprint.hardware.cpuName = obj["Name"]?.ToString() ?? currentFingerprint.hardware.cpuName;
                        currentFingerprint.hardware.cpuCoreCount = Convert.ToInt32(obj["NumberOfCores"] ?? currentFingerprint.hardware.cpuCoreCount);
                        currentFingerprint.hardware.cpuThreadCount = Convert.ToInt32(obj["NumberOfLogicalProcessors"] ?? Environment.ProcessorCount);
                        break;
                    }
                }
            }
            catch { }
        }

        private void CollectWindowsMotherboardInfo()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        currentFingerprint.hardware.motherboardId = obj["SerialNumber"]?.ToString() ?? "Unknown";
                        currentFingerprint.hardware.motherboardManufacturer = obj["Manufacturer"]?.ToString() ?? "Unknown";
                        currentFingerprint.hardware.motherboardProduct = obj["Product"]?.ToString() ?? "Unknown";
                        break;
                    }
                }
            }
            catch { }
        }

        private void CollectWindowsBIOSInfo()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_BIOS"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        currentFingerprint.hardware.biosVersion = obj["Version"]?.ToString() ?? "Unknown";
                        currentFingerprint.hardware.biosManufacturer = obj["Manufacturer"]?.ToString() ?? "Unknown";
                        currentFingerprint.hardware.biosSerialNumber = obj["SerialNumber"]?.ToString() ?? "Unknown";
                        break;
                    }
                }
            }
            catch { }
        }

        private void CollectWindowsRAMInfo()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_PhysicalMemory"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        currentFingerprint.hardware.ramType = obj["MemoryType"]?.ToString() ?? "Unknown";
                        currentFingerprint.hardware.ramSpeed = Convert.ToInt32(obj["Speed"] ?? 0);
                        break;
                    }
                }

                // Available RAM
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        currentFingerprint.hardware.availableRamMB = Convert.ToInt32(Convert.ToInt64(obj["FreePhysicalMemory"] ?? 0) / 1024);
                        break;
                    }
                }
            }
            catch { }
        }

        private void CollectWindowsDiskInfo()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        var disk = new DiskInfo
                        {
                            serialNumber = obj["SerialNumber"]?.ToString() ?? "Unknown",
                            model = obj["Model"]?.ToString() ?? "Unknown",
                            interfaceType = obj["InterfaceType"]?.ToString() ?? "Unknown",
                            totalSizeGB = Convert.ToInt64(obj["Size"] ?? 0) / (1024 * 1024 * 1024)
                        };

                        currentFingerprint.hardware.disks.Add(disk);
                    }
                }

                // File system bilgileri
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType=3"))
                {
                    int index = 0;
                    foreach (var obj in searcher.Get())
                    {
                        if (index < currentFingerprint.hardware.disks.Count)
                        {
                            currentFingerprint.hardware.disks[index].fileSystem = obj["FileSystem"]?.ToString() ?? "Unknown";
                            currentFingerprint.hardware.disks[index].freeSizeGB = Convert.ToInt64(obj["FreeSpace"] ?? 0) / (1024 * 1024 * 1024);
                        }
                        index++;
                    }
                }
            }
            catch { }
        }

        private void CollectWindowsUSBInfo()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_USBHub"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        var usb = new USBDevice
                        {
                            deviceId = obj["DeviceID"]?.ToString() ?? "Unknown",
                            name = obj["Name"]?.ToString() ?? "Unknown",
                            manufacturer = obj["Manufacturer"]?.ToString() ?? "Unknown",
                            deviceClass = obj["ClassGuid"]?.ToString() ?? "Unknown"
                        };

                        currentFingerprint.hardware.usbDevices.Add(usb);
                    }
                }
            }
            catch { }
        }
#endif
#if UNITY_ANDROID
private void CollectAndroidHardwareInfo()
{
var hw = currentFingerprint.hardware;
        try
        {
            using (var build = new AndroidJavaClass("android.os.Build"))
            {
                hw.motherboardId = build.GetStatic<string>("SERIAL");
                hw.motherboardManufacturer = build.GetStatic<string>("MANUFACTURER");
                hw.motherboardProduct = build.GetStatic<string>("PRODUCT");
                hw.biosVersion = build.GetStatic<string>("BOOTLOADER");
                hw.biosManufacturer = build.GetStatic<string>("BRAND");
                
                // CPU bilgileri
                hw.cpuId = build.GetStatic<string>("HARDWARE");
                
                // Thread sayısı
                using (var runtime = new AndroidJavaClass("java.lang.Runtime"))
                {
                    var rt = runtime.CallStatic<AndroidJavaObject>("getRuntime");
                    hw.cpuThreadCount = rt.Call<int>("availableProcessors");
                }
            }
            
            // Android ID
            using (var unityPlayer = new AndroidJavaClass("com.unity3d.player.UnityPlayer"))
            {
                var activity = unityPlayer.GetStatic<AndroidJavaObject>("currentActivity");
                var context = activity.Call<AndroidJavaObject>("getApplicationContext");
                
                using (var settingsSecure = new AndroidJavaClass("android.provider.Settings$Secure"))
                {
                    var resolver = context.Call<AndroidJavaObject>("getContentResolver");
                    var androidId = settingsSecure.CallStatic<string>("getString", resolver, "android_id");
                    hw.cpuId = androidId ?? hw.cpuId;
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
        hw.motherboardId = UnityEngine.SystemInfo.deviceUniqueIdentifier;
        hw.cpuId = UnityEngine.SystemInfo.deviceModel;
        hw.cpuThreadCount = Environment.ProcessorCount;
        hw.biosVersion = "Apple EFI";
    }
#endif
#if UNITY_STANDALONE_LINUX
private void CollectLinuxHardwareInfo()
{
var hw = currentFingerprint.hardware;
        hw.motherboardId = UnityEngine.SystemInfo.deviceUniqueIdentifier;
        hw.cpuId = UnityEngine.SystemInfo.processorType;
        hw.cpuThreadCount = Environment.ProcessorCount;
        
        // Linux'ta /proc/cpuinfo'dan bilgi alınabilir
        try
        {
            if (File.Exists("/proc/cpuinfo"))
            {
                var lines = File.ReadAllLines("/proc/cpuinfo");
                foreach (var line in lines)
                {
                    if (line.StartsWith("model name"))
                    {
                        hw.cpuName = line.Split(':')[1].Trim();
                        break;
                    }
                }
            }
        }
        catch { }
    }
#endif
        #endregion
        #region Network Collection
        private void CollectNetworkInfo()
        {
            var net = currentFingerprint.network;

            try
            {
                // Network adapters
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
                        isWireless = ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211, // Düzeltildi
                        speed = ni.Speed,
                        status = ni.OperationalStatus.ToString()
                    };

                    // IP addresses
                    var props = ni.GetIPProperties();
                    foreach (var addr in props.UnicastAddresses)
                    {
                        if (addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ||
                            addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                        {
                            adapter.ipAddresses.Add(addr.Address.ToString());
                        }
                    }

                    // Check if virtual
                    adapter.isVirtual = IsVirtualNetworkAdapter(adapter);
                    if (adapter.isVirtual)
                    {
                        net.hasVirtualAdapter = true;
                        net.virtualAdapterNames.Add(adapter.name);
                    }

                    // Manufacturer
                    adapter.manufacturer = GetNetworkAdapterManufacturer(adapter.macAddress);

                    net.adapters.Add(adapter);
                }

                // Gateway and DNS
                CollectGatewayAndDNS(net);

                // Public IP
                CollectPublicIP(net);

                // ARP Table
                CollectARPTable(net);

                // Network shares
                CollectNetworkShares(net);

                // Network topology
                DetermineNetworkTopology(net);
            }
            catch (Exception e)
            {
                UnityEngine.Debug.LogWarning($"[AntiCheat] Network collection error: {e.Message}");
            }
        }

        private string GetNetworkAdapterManufacturer(string macAddress)
        {
            if (string.IsNullOrEmpty(macAddress) || macAddress.Length < 6)
                return "Unknown";

            var prefix = macAddress.Substring(0, 6).ToUpper();

            // OUI database'den birkaç örnek
            var manufacturers = new Dictionary<string, string>
        {
            { "00155D", "Microsoft" },
            { "000569", "VMware" },
            { "000C29", "VMware" },
            { "005056", "VMware" },
            { "080027", "VirtualBox" },
            { "0A0027", "VirtualBox" },
            { "001C42", "Parallels" },
            { "525400", "QEMU" },
            { "00163E", "Xen" }
        };

            return manufacturers.ContainsKey(prefix) ? manufacturers[prefix] : "Unknown";
        }

        private void CollectGatewayAndDNS(NetworkInfo net)
        {
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var ni in interfaces)
                {
                    if (ni.OperationalStatus != OperationalStatus.Up)
                        continue;

                    var props = ni.GetIPProperties();

                    // Gateway
                    foreach (var gateway in props.GatewayAddresses)
                    {
                        if (!string.IsNullOrEmpty(gateway.Address.ToString()) &&
                            !net.gatewayIp.Contains(gateway.Address.ToString()))
                        {
                            if (string.IsNullOrEmpty(net.gatewayIp))
                                net.gatewayIp = gateway.Address.ToString();
                            else
                                net.gatewayIp += ", " + gateway.Address.ToString();
                        }
                    }

                    // DNS
                    foreach (var dns in props.DnsAddresses)
                    {
                        var dnsStr = dns.ToString();
                        if (!net.dnsServers.Contains(dnsStr))
                            net.dnsServers.Add(dnsStr);
                    }
                }
            }
            catch { }
        }

        private void CollectPublicIP(NetworkInfo net)
        {
            try
            {
                using (var client = new WebClient())
                {
                    client.Timeout = 3000;
                    net.publicIp = client.DownloadString("https://api.ipify.org").Trim();
                }
            }
            catch
            {
                net.publicIp = "Unable to detect";
            }
        }

        private void CollectARPTable(NetworkInfo net)
        {
#if UNITY_STANDALONE_WIN
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "arp",
                    Arguments = "-a",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };
                using (var process = Process.Start(startInfo))
                {
                    var output = process.StandardOutput.ReadToEnd();
                    var lines = output.Split('\n');

                    foreach (var line in lines)
                    {
                        if (line.Contains(".") && line.Contains("-"))
                        {
                            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 3)
                            {
                                net.arpTable.Add(new ARPEntry
                                {
                                    ipAddress = parts[0],
                                    macAddress = parts[1],
                                    type = parts[2]
                                });
                            }
                        }
                    }
                }
            }
            catch { }
#endif
        }
        private void CollectNetworkShares(NetworkInfo net)
        {
#if UNITY_STANDALONE_WIN
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "net",
                    Arguments = "share",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };
                using (var process = Process.Start(startInfo))
                {
                    var output = process.StandardOutput.ReadToEnd();
                    var lines = output.Split('\n');

                    foreach (var line in lines)
                    {
                        if (line.Contains("$") || line.Contains(":"))
                        {
                            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length > 0)
                            {
                                net.networkShares.Add(parts[0]);
                            }
                        }
                    }
                }
            }
            catch { }
#endif
        }
        private void DetermineNetworkTopology(NetworkInfo net)
        {
            if (string.IsNullOrEmpty(net.gatewayIp))
            {
                net.networkTopology = "No Gateway";
                return;
            }

            if (net.gatewayIp.StartsWith("192.168."))
                net.networkTopology = "NAT/Home Network";
            else if (net.gatewayIp.StartsWith("10."))
                net.networkTopology = "Corporate Network";
            else if (net.gatewayIp.StartsWith("172."))
                net.networkTopology = "Private Network";
            else
                net.networkTopology = "Public Network";
        }

        private bool IsVirtualNetworkAdapter(NetworkAdapter adapter)
        {
            if (string.IsNullOrEmpty(adapter.macAddress) || adapter.macAddress.Length < 6)
                return false;

            var macPrefix = adapter.macAddress.Substring(0, 6).ToUpper();

            // Check MAC prefix
            foreach (var vmPrefix in virtualMacPrefixes.Keys)
            {
                if (macPrefix.StartsWith(vmPrefix.Replace(":", "")))
                    return true;
            }

            // Check description
            var desc = adapter.description.ToLower();
            var virtualKeywords = new[] { "virtual", "vmware", "vbox", "hyper-v", "parallels", "qemu", "kvm" };

            return virtualKeywords.Any(keyword => desc.Contains(keyword));
        }
        #endregion

        #region System Info Collection
        private void CollectSystemInfo()
        {
            var sys = currentFingerprint.systemInfo;

            // Basic info
            sys.osName = System.Environment.OSVersion.Platform.ToString();
            sys.osVersion = System.Environment.OSVersion.Version.ToString();
            sys.osBuild = System.Environment.OSVersion.ServicePack;
            sys.osArchitecture = System.Environment.Is64BitOperatingSystem ? "x64" : "x86";
            sys.computerName = System.Environment.MachineName;
            sys.userName = System.Environment.UserName;
            sys.domainName = System.Environment.UserDomainName;
            sys.systemLanguage = System.Globalization.CultureInfo.CurrentCulture.Name;
            sys.timeZone = TimeZoneInfo.Local.DisplayName;
#if UNITY_STANDALONE_WIN
            CollectWindowsSystemInfo();
#elif UNITY_ANDROID
CollectAndroidSystemInfo();
#endif
        }
#if UNITY_STANDALONE_WIN
        private void CollectWindowsSystemInfo()
        {
            var sys = currentFingerprint.systemInfo;
            try
            {
                // OS detailed info
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        sys.osName = obj["Caption"]?.ToString() ?? sys.osName;
                        sys.osVersion = obj["Version"]?.ToString() ?? sys.osVersion;
                        sys.osBuild = obj["BuildNumber"]?.ToString() ?? sys.osBuild;

                        var installDate = obj["InstallDate"]?.ToString();
                        if (!string.IsNullOrEmpty(installDate) && installDate.Length >= 8)
                        {
                            sys.osInstallDate = $"{installDate.Substring(0, 4)}-{installDate.Substring(4, 2)}-{installDate.Substring(6, 2)}";
                        }

                        var bootTime = obj["LastBootUpTime"]?.ToString();
                        if (!string.IsNullOrEmpty(bootTime) && bootTime.Length >= 14)
                        {
                            sys.systemBootTime = $"{bootTime.Substring(0, 4)}-{bootTime.Substring(4, 2)}-{bootTime.Substring(6, 2)} {bootTime.Substring(8, 2)}:{bootTime.Substring(10, 2)}:{bootTime.Substring(12, 2)}";
                        }
                        break;
                    }
                }

                // Installed software (limit to important ones)
                CollectInstalledSoftware(sys);

                // System services
                CollectSystemServices(sys);

                // Startup programs
                CollectStartupPrograms(sys);
            }
            catch (Exception e)
            {
                UnityEngine.Debug.LogWarning($"[AntiCheat] Windows system info error: {e.Message}");
            }
        }

        private void CollectInstalledSoftware(SystemInfo sys)
        {
            try
            {
                var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                if (key != null)
                {
                    foreach (var subKeyName in key.GetSubKeyNames())
                    {
                        var subKey = key.OpenSubKey(subKeyName);
                        var displayName = subKey?.GetValue("DisplayName")?.ToString();

                        if (!string.IsNullOrEmpty(displayName))
                        {
                            // Sadece önemli yazılımları ekle
                            var important = new[] { "Steam", "Epic", "Origin", "Discord", "TeamViewer",
                                               "VirtualBox", "VMware", "BlueStacks", "Nox", "LDPlayer" };

                            if (important.Any(sw => displayName.Contains(sw, StringComparison.OrdinalIgnoreCase)))
                            {
                                sys.installedSoftware.Add(displayName);
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private void CollectSystemServices(SystemInfo sys)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service WHERE State='Running'"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        var serviceName = obj["Name"]?.ToString();

                        // Sadece şüpheli servisleri ekle
                        var suspicious = new[] { "VMware", "VBox", "Parallels", "BlueStacks", "Nox", "LDPlayer" };

                        if (suspicious.Any(s => serviceName.Contains(s, StringComparison.OrdinalIgnoreCase)))
                        {
                            sys.systemServices.Add(serviceName);
                        }
                    }
                }
            }
            catch { }
        }

        private void CollectStartupPrograms(SystemInfo sys)
        {
            try
            {
                var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = key.GetValue(valueName)?.ToString();
                        if (!string.IsNullOrEmpty(value))
                        {
                            sys.startupPrograms.Add($"{valueName}: {value}");
                        }
                    }
                }
            }
            catch { }
        }
#endif
#if UNITY_ANDROID
private void CollectAndroidSystemInfo()
{
var sys = currentFingerprint.systemInfo;
        try
        {
            using (var build = new AndroidJavaClass("android.os.Build$VERSION"))
            {
                sys.osName = "Android";
                sys.osVersion = build.GetStatic<string>("RELEASE");
                sys.osBuild = build.GetStatic<int>("SDK_INT").ToString();
            }

            using (var build = new AndroidJavaClass("android.os.Build"))
            {
                sys.computerName = build.GetStatic<string>("MODEL");
            }
        }
        catch { }
    }
#endif
        #endregion
        #region Process Collection
        private void CollectProcessInfo()
        {
            var proc = currentFingerprint.processes;
#if UNITY_STANDALONE_WIN || UNITY_STANDALONE_LINUX || UNITY_STANDALONE_OSX
            try
            {
                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    try
                    {
                        var processName = process.ProcessName.ToLower();

                        // Add to running processes (limit)
                        if (proc.runningProcesses.Count < 100)
                        {
                            proc.runningProcesses.Add(process.ProcessName);
                        }

                        // Check for VM processes
                        if (knownVMProcesses.Any(vm => processName.Contains(vm)))
                        {
                            proc.knownVMProcesses.Add(process.ProcessName);
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
                    catch { }
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
            // Check for known emulator packages
            var emulatorPackages = new[]
            {
                "com.bluestacks",
                "com.bignox.app",
                "com.topjohnwu.magisk",
                "com.ldmnq.launcher3",
                "com.microvirt.memuplay",
                "com.koplayer",
                "com.vphone.launcher",
                "com.nox.mopen.app"
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
            float confidence = 0f;
#if UNITY_STANDALONE_WIN
            // Registry checks
            if (CheckVMwareRegistry())
            {
                vm.vmIndicators.Add("VMware Registry Keys");
                vm.suspiciousRegistryKeys.Add(@"SOFTWARE\VMware, Inc.");
                vm.vmwareToolsPresent = true;
                confidence += 40f;
            }
            if (CheckVirtualBoxRegistry())
            {
                vm.vmIndicators.Add("VirtualBox Registry Keys");
                vm.suspiciousRegistryKeys.Add("SOFTWARE\\Oracle\\VirtualBox");
                vm.vboxAdditionsPresent = true;
                confidence += 40f;
            }

            if (CheckHyperVRegistry())
            {
                vm.vmIndicators.Add("Hyper-V Registry Keys");
                vm.suspiciousRegistryKeys.Add("SOFTWARE\\Microsoft\\Virtual Machine");
                vm.hyperVIntegrationPresent = true;
                confidence += 40f;
            }

            // Hardware checks
            if (CheckVirtualHardware())
            {
                vm.vmIndicators.Add("Virtual Hardware Detected");
                confidence += 30f;
            }

            // BIOS checks
            if (CheckVirtualBIOS())
            {
                vm.vmIndicators.Add("Virtual BIOS Detected");
                confidence += 25f;
            }

            // WMI checks
            if (CheckWMIForVM())
            {
                vm.vmIndicators.Add("WMI VM Detection");
                confidence += 35f;
            }

            // Timing checks
            if (PerformTimingCheck())
            {
                vm.vmIndicators.Add("Timing Anomalies");
                confidence += 20f;
            }
#elif UNITY_ANDROID
// Android VM/Emulator checks
if (CheckAndroidEmulator())
{
vm.vmIndicators.Add("Android Emulator Properties");
confidence += 50f;
}
        if (CheckEmulatorBuild())
        {
            vm.vmIndicators.Add("Emulator Build Properties");
            confidence += 40f;
        }
#endif
            // Process-based detection
            if (currentFingerprint.processes.knownVMProcesses.Count > 0)
            {
                vm.suspiciousProcesses.AddRange(currentFingerprint.processes.knownVMProcesses);
                vm.vmIndicators.Add("VM Processes Running");
                confidence += 35f;
            }

            // Network-based detection
            if (currentFingerprint.network.hasVirtualAdapter)
            {
                vm.vmIndicators.Add("Virtual Network Adapters");
                vm.vmMacAddressDetected = true;
                confidence += 25f;
            }

            // MAC address check
            foreach (var adapter in currentFingerprint.network.adapters)
            {
                if (!string.IsNullOrEmpty(adapter.macAddress) && adapter.macAddress.Length >= 6)
                {
                    var macPrefix = adapter.macAddress.Substring(0, 6).ToUpper();
                    foreach (var kvp in virtualMacPrefixes)
                    {
                        if (macPrefix.StartsWith(kvp.Key.Replace(":", "")))
                        {
                            vm.vmHardwareSignatures.Add($"MAC: {kvp.Value}");
                            vm.vmMacAddressDetected = true;
                            confidence += 20f;
                            break;
                        }
                    }
                }
            }

            // Hardware signature checks
            var hw = currentFingerprint.hardware;
            if (vmHardwareVendors.Any(vendor => hw.motherboardManufacturer?.ToLower().Contains(vendor) == true))
            {
                vm.vmHardwareSignatures.Add($"Motherboard: {hw.motherboardManufacturer}");
                confidence += 30f;
            }

            if (vmHardwareVendors.Any(vendor => hw.biosManufacturer?.ToLower().Contains(vendor) == true))
            {
                vm.vmBiosSignatures.Add($"BIOS: {hw.biosManufacturer}");
                confidence += 30f;
            }

            // Determine hypervisor type
            if (confidence > 0)
            {
                if (vm.vmwareToolsPresent || vm.vmIndicators.Any(i => i.Contains("VMware")))
                    vm.hypervisorType = "VMware";
                else if (vm.vboxAdditionsPresent || vm.vmIndicators.Any(i => i.Contains("VirtualBox")))
                    vm.hypervisorType = "VirtualBox";
                else if (vm.hyperVIntegrationPresent || vm.vmIndicators.Any(i => i.Contains("Hyper-V")))
                    vm.hypervisorType = "Hyper-V";
                else if (vm.vmIndicators.Any(i => i.Contains("QEMU")))
                    vm.hypervisorType = "QEMU/KVM";
                else if (vm.vmIndicators.Any(i => i.Contains("Parallels")))
                    vm.hypervisorType = "Parallels";
                else
                    vm.hypervisorType = "Unknown VM";
            }
            else
            {
                vm.hypervisorType = "None";
            }

            vm.confidenceScore = Math.Min(100f, confidence);
            vm.isVirtualized = confidence >= 30f; // Lower threshold for better detection
            vm.detectionMethod = "Multi-Layer Detection";
        }
#if UNITY_STANDALONE_WIN
        private bool CheckVMwareRegistry()
        {
            var keys = new[]
            {
@"SOFTWARE\VMware, Inc.\VMware Tools",
@"SYSTEM\CurrentControlSet\Services\VMTools",
@"SYSTEM\CurrentControlSet\Services\vmware",
@"SYSTEM\CurrentControlSet\Services\vmhgfs"
};
            foreach (var keyPath in keys)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null) return true;
                    }
                }
                catch { }
            }
            return false;
        }

        private bool CheckVirtualBoxRegistry()
        {
            var keys = new[]
            {
            @"SOFTWARE\Oracle\VirtualBox Guest Additions",
            @"SYSTEM\CurrentControlSet\Services\VBoxGuest",
            @"SYSTEM\CurrentControlSet\Services\VBoxMouse",
            @"SYSTEM\CurrentControlSet\Services\VBoxService"
        };

            foreach (var keyPath in keys)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null) return true;
                    }
                }
                catch { }
            }
            return false;
        }

        private bool CheckHyperVRegistry()
        {
            var keys = new[]
            {
            @"SOFTWARE\Microsoft\Virtual Machine\Guest",
            @"SYSTEM\CurrentControlSet\Services\vmicheartbeat",
            @"SYSTEM\CurrentControlSet\Services\vmicvss",
            @"SYSTEM\CurrentControlSet\Services\vmicshutdown"
        };

            foreach (var keyPath in keys)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null) return true;
                    }
                }
                catch { }
            }
            return false;
        }

        private bool CheckVirtualHardware()
        {
            var hw = currentFingerprint.hardware;
            var virtualIndicators = new[] { "virtual", "vmware", "vbox", "qemu", "parallels", "microsoft corporation" };

            foreach (var gpu in hw.gpus)
            {
                if (virtualIndicators.Any(indicator => gpu.name.ToLower().Contains(indicator)))
                    return true;
            }

            if (virtualIndicators.Any(indicator => hw.cpuName?.ToLower().Contains(indicator) == true))
                return true;

            return false;
        }

        private bool CheckVirtualBIOS()
        {
            var hw = currentFingerprint.hardware;
            var virtualBiosIndicators = new[] { "vmware", "virtualbox", "qemu", "parallels", "american megatrends", "phoenix" };

            return virtualBiosIndicators.Any(indicator =>
                hw.biosManufacturer?.ToLower().Contains(indicator) == true ||
                hw.biosVersion?.ToLower().Contains(indicator) == true);
        }

        private bool CheckWMIForVM()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        var manufacturer = obj["Manufacturer"]?.ToString().ToLower();
                        var model = obj["Model"]?.ToString().ToLower();

                        if (vmHardwareVendors.Any(vendor => manufacturer?.Contains(vendor) == true))
                            return true;

                        if (vmHardwareVendors.Any(vendor => model?.Contains(vendor) == true))
                            return true;
                    }
                }
            }
            catch { }
            return false;
        }

        private bool PerformTimingCheck()
        {
            const int iterations = 100;
            var timings = new List<long>();

            for (int i = 0; i < iterations; i++)
            {
                var start = DateTime.UtcNow.Ticks;

                // Operation that causes VM-exit
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System"))
                    {
                        var _ = key?.GetValue("SystemBiosVersion");
                    }
                }
                catch { }

                var end = DateTime.UtcNow.Ticks;
                timings.Add(end - start);
            }

            // Calculate variance
            var avg = timings.Average();
            var variance = timings.Sum(t => Math.Pow(t - avg, 2)) / timings.Count;

            // High variance indicates VM
            currentFingerprint.performance.timingVariance = (float)variance;
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
var product = build.GetStatic<string>("PRODUCT");
                var emulatorIndicators = new[]
                {
                    "generic", "unknown", "emulator", "sdk", "google_sdk",
                    "goldfish", "vbox", "nox", "bluestacks", "genymotion",
                    "andy", "ttvm", "droid4x", "memorial", "ldplayer"
                };
                
                return emulatorIndicators.Any(indicator =>
                    fingerprint.ToLower().Contains(indicator) ||
                    model.ToLower().Contains(indicator) ||
                    manufacturer.ToLower().Contains(indicator) ||
                    hardware.ToLower().Contains(indicator) ||
                    product.ToLower().Contains(indicator));
            }
        }
        catch { return false; }
    }
    
    private bool CheckEmulatorBuild()
    {
        try
        {
            // Check for QEMU
            var qemuProps = new[]
            {
                "ro.kernel.qemu",
                "ro.kernel.qemu.gles",
                "init.svc.qemud",
                "init.svc.qemu-props",
                "ro.bootloader",
                "ro.hardware"
            };
            
            using (var systemProperties = new AndroidJavaClass("android.os.SystemProperties"))
            {
                foreach (var prop in qemuProps)
                {
                    var value = systemProperties.CallStatic<string>("get", prop);
                    if (!string.IsNullOrEmpty(value) && 
                        (value.Contains("unknown") || value.Contains("emulator") || value.Contains("goldfish")))
                    {
                        return true;
                    }
                }
            }
            
            // Check files
            var emulatorFiles = new[]
            {
                "/system/lib/libc_malloc_debug_qemu.so",
                "/system/bin/qemu-props",
                "/dev/socket/qemud",
                "/dev/qemu_pipe"
            };
            
            using (var file = new AndroidJavaClass("java.io.File"))
            {
                foreach (var path in emulatorFiles)
                {
                    var f = new AndroidJavaObject("java.io.File", path);
                    if (f.Call<bool>("exists"))
                        return true;
                }
            }
        }
        catch { }
        
        return false;
    }
#endif
        #endregion
        #region Emulator Detection
        private void DetectEmulator()
        {
            var emu = currentFingerprint.emulator;
            float confidence = 0f;
#if UNITY_STANDALONE_WIN
            // Windows emulator detection
            DetectWindowsEmulators(emu, ref confidence);
#elif UNITY_ANDROID
// Android emulator detection
DetectAndroidEmulators(emu, ref confidence);
#endif
            // Process-based detection
            if (currentFingerprint.processes.knownEmulators.Count > 0)
            {
                emu.emulatorProcesses.AddRange(currentFingerprint.processes.knownEmulators);
                emu.emulatorIndicators.Add("Emulator Processes Running");
                confidence += 50f;
            }

            // Determine emulator type
            DetermineEmulatorType(emu);

            emu.confidenceScore = Math.Min(100f, confidence);
            emu.isEmulator = confidence >= 30f;
        }


#if UNITY_STANDALONE_WIN
        private void DetectWindowsEmulators(EmulatorInfo emu, ref float confidence)
        {
            // BlueStacks detection
            if (CheckBlueStacksRegistry())
            {
                emu.emulatorIndicators.Add("BlueStacks Registry Keys");
                emu.emulatorRegistryKeys.Add(@"SOFTWARE\BlueStacks");
                confidence += 50f;
            }
            // Nox detection
            if (CheckNoxRegistry())
            {
                emu.emulatorIndicators.Add("Nox Registry Keys");
                emu.emulatorRegistryKeys.Add(@"SOFTWARE\BigNox");
                confidence += 50f;
            }

            // LDPlayer detection
            if (CheckLDPlayerRegistry())
            {
                emu.emulatorIndicators.Add("LDPlayer Registry Keys");
                emu.emulatorRegistryKeys.Add(@"SOFTWARE\ldplayer");
                confidence += 50f;
            }

            // MEmu detection
            if (CheckMEmuRegistry())
            {
                emu.emulatorIndicators.Add("MEmu Registry Keys");
                emu.emulatorRegistryKeys.Add(@"SOFTWARE\MEmu");
                confidence += 50f;
            }

            // Check file paths
            CheckEmulatorFilePaths(emu, ref confidence);
        }

        private bool CheckBlueStacksRegistry()
        {
            var keys = new[]
            {
            @"SOFTWARE\BlueStacks",
            @"SOFTWARE\BlueStacks_nxt",
            @"SOFTWARE\BlueStacksGP"
        };

            foreach (var keyPath in keys)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null) return true;
                    }
                    using (var key = Registry.CurrentUser.OpenSubKey(keyPath))
                    {
                        if (key != null) return true;
                    }
                }
                catch { }
            }
            return false;
        }

        private bool CheckNoxRegistry()
        {
            var keys = new[]
            {
            @"SOFTWARE\BigNox",
            @"SOFTWARE\Nox",
            @"SOFTWARE\Duodian\Nox"
        };

            foreach (var keyPath in keys)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null) return true;
                    }
                }
                catch { }
            }
            return false;
        }

        private bool CheckLDPlayerRegistry()
        {
            var keys = new[]
            {
            @"SOFTWARE\ldplayer",
            @"SOFTWARE\ldplayer9",
            @"SOFTWARE\dnplayer"
        };

            foreach (var keyPath in keys)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null) return true;
                    }
                    using (var key = Registry.CurrentUser.OpenSubKey(keyPath))
                    {
                        if (key != null) return true;
                    }
                }
                catch { }
            }
            return false;
        }

        private bool CheckMEmuRegistry()
        {
            var keys = new[]
            {
            @"SOFTWARE\MEmu",
            @"SOFTWARE\Microvirt\MEmu"
        };

            foreach (var keyPath in keys)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null) return true;
                    }
                }
                catch { }
            }
            return false;
        }

        private void CheckEmulatorFilePaths(EmulatorInfo emu, ref float confidence)
        {
            var emulatorPaths = new Dictionary<string, string>
        {
            { @"C:\Program Files\BlueStacks", "BlueStacks" },
            { @"C:\Program Files\BlueStacks_nxt", "BlueStacks" },
            { @"C:\Program Files (x86)\BlueStacks", "BlueStacks" },
            { @"C:\Program Files\Nox", "Nox" },
            { @"C:\Program Files (x86)\Nox", "Nox" },
            { @"C:\Program Files\Bignox", "Nox" },
            { @"C:\Program Files\LDPlayer", "LDPlayer" },
            { @"C:\Program Files\ldplayer9", "LDPlayer" },
            { @"C:\Program Files\dnplayer", "LDPlayer" },
            { @"C:\Program Files\Microvirt", "MEmu" },
            { @"C:\Program Files (x86)\Microvirt", "MEmu" }
        };

            foreach (var path in emulatorPaths)
            {
                if (Directory.Exists(path.Key))
                {
                    emu.emulatorFilePaths.Add(path.Key);
                    emu.emulatorIndicators.Add($"{path.Value} Installation Found");
                    confidence += 40f;
                }
            }
        }
#endif
#if UNITY_ANDROID
private void DetectAndroidEmulators(EmulatorInfo emu, ref float confidence)
{
emu.androidEmulatorDetected = true;
        // Build properties check
        try
        {
            using (var build = new AndroidJavaClass("android.os.Build"))
            {
                var manufacturer = build.GetStatic<string>("MANUFACTURER").ToLower();
                var brand = build.GetStatic<string>("BRAND").ToLower();
                var device = build.GetStatic<string>("DEVICE").ToLower();
                var model = build.GetStatic<string>("MODEL").ToLower();
                var product = build.GetStatic<string>("PRODUCT").ToLower();
                var hardware = build.GetStatic<string>("HARDWARE").ToLower();

                // BlueStacks indicators
                if (manufacturer.Contains("bluestacks") || brand.Contains("bluestacks"))
                {
                    emu.emulatorIndicators.Add("BlueStacks Build Properties");
                    confidence += 60f;
                }

                // Nox indicators
                if (device.Contains("nox") || model.Contains("nox"))
                {
                    emu.emulatorIndicators.Add("Nox Build Properties");
                    confidence += 60f;
                }

                // LDPlayer indicators
                if (model.Contains("ldplayer") || device.Contains("ldplayer"))
                {
                    emu.emulatorIndicators.Add("LDPlayer Build Properties");
                    confidence += 60f;
                }

                // Generic emulator indicators
                if (hardware.Contains("goldfish") || hardware.Contains("ranchu"))
                {
                    emu.emulatorIndicators.Add("Android SDK Emulator");
                    confidence += 50f;
                }

                // Device model mismatches
                if ((manufacturer == "unknown" || brand == "generic") && model != "sdk")
                {
                    emu.deviceModelMismatch = true;
                    confidence += 30f;
                }
            }

            // File-based detection
            CheckAndroidEmulatorFiles(emu, ref confidence);

            // Property-based detection
            CheckAndroidEmulatorProperties(emu, ref confidence);
        }
        catch { }
    }

    private void CheckAndroidEmulatorFiles(EmulatorInfo emu, ref float confidence)
    {
        var emulatorFiles = new Dictionary<string, string>
        {
            { "/system/lib/libc_malloc_debug_qemu.so", "QEMU" },
            { "/sys/qemu_trace", "QEMU" },
            { "/system/bin/qemu-props", "QEMU" },
            { "/dev/socket/qemud", "QEMU" },
            { "/dev/qemu_pipe", "QEMU" },
            { "/system/lib/libnoxd.so", "Nox" },
            { "/system/lib/libnoxspeedup.so", "Nox" },
            { "/system/bin/nox", "Nox" },
            { "/system/bin/nox-prop", "Nox" },
            { "/data/app/com.bluestacks.home", "BlueStacks" },
            { "/data/app/com.bluestacks.searchapp", "BlueStacks" },
            { "/mnt/windows/BstSharedFolder", "BlueStacks" }
        };

        using (var file = new AndroidJavaClass("java.io.File"))
        {
            foreach (var emulatorFile in emulatorFiles)
            {
                var f = new AndroidJavaObject("java.io.File", emulatorFile.Key);
                if (f.Call<bool>("exists"))
                {
                    emu.emulatorFilePaths.Add(emulatorFile.Key);
                    emu.emulatorIndicators.Add($"{emulatorFile.Value} File Detected");
                    confidence += 40f;
                }
            }
        }
    }

    private void CheckAndroidEmulatorProperties(EmulatorInfo emu, ref float confidence)
    {
        try
        {
            using (var systemProperties = new AndroidJavaClass("android.os.SystemProperties"))
            {
                // BlueStacks properties
                var bstProp = systemProperties.CallStatic<string>("get", "ro.bstacks.version");
                if (!string.IsNullOrEmpty(bstProp))
                {
                    emu.emulatorIndicators.Add("BlueStacks System Property");
                    confidence += 50f;
                }

                // Nox properties
                var noxProp = systemProperties.CallStatic<string>("get", "ro.nox.version");
                if (!string.IsNullOrEmpty(noxProp))
                {
                    emu.emulatorIndicators.Add("Nox System Property");
                    confidence += 50f;
                }

                // Generic emulator properties
                var qemuProp = systemProperties.CallStatic<string>("get", "ro.kernel.qemu");
                if (qemuProp == "1")
                {
                    emu.emulatorIndicators.Add("QEMU Kernel Property");
                    confidence += 40f;
                }
            }
        }
        catch { }
    }
#endif
        private void DetermineEmulatorType(EmulatorInfo emu)
        {
            if (emu.emulatorIndicators.Count == 0)
            {
                emu.emulatorType = "None";
                return;
            }

            // Count indicators for each type
            var bluestacksCount = emu.emulatorIndicators.Count(i => i.Contains("BlueStacks"));
            var noxCount = emu.emulatorIndicators.Count(i => i.Contains("Nox"));
            var ldplayerCount = emu.emulatorIndicators.Count(i => i.Contains("LDPlayer"));
            var memuCount = emu.emulatorIndicators.Count(i => i.Contains("MEmu"));

            // Determine most likely type
            var maxCount = Math.Max(Math.Max(bluestacksCount, noxCount), Math.Max(ldplayerCount, memuCount));

            if (maxCount == 0)
            {
                emu.emulatorType = "Unknown Emulator";
            }
            else if (bluestacksCount == maxCount)
            {
                emu.emulatorType = "BlueStacks";
            }
            else if (noxCount == maxCount)
            {
                emu.emulatorType = "Nox";
            }
            else if (ldplayerCount == maxCount)
            {
                emu.emulatorType = "LDPlayer";
            }
            else if (memuCount == maxCount)
            {
                emu.emulatorType = "MEmu";
            }
            else
            {
                emu.emulatorType = "Unknown Emulator";
            }
        }
        #endregion

        #region Security Collection
        private void CollectSecurityInfo()
        {
            var sec = currentFingerprint.security;
#if UNITY_STANDALONE_WIN
            // Debugger check
            sec.debuggerPresent = IsDebuggerPresent();
            // Admin privileges
            sec.hasAdminPrivileges = IsRunningAsAdmin();

            // Security software
            DetectSecuritySoftware(sec);

            // Analysis tools
            DetectAnalysisTools(sec);

            // Firewall status
            CheckFirewallStatus(sec);

            // Open ports
            CheckOpenPorts(sec);

            // Sandbox detection
            sec.sandboxEnvironmentDetected = DetectSandbox();

            // System uptime
            sec.systemUptime = GetSystemUptime();
#elif UNITY_ANDROID
// Root detection
sec.rootedDevice = IsDeviceRooted();
        // Debugger check
        sec.debuggerPresent = Debug.isDebugBuild;
#endif
        }
#if UNITY_STANDALONE_WIN
        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();
        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
            ref int processInformation, int processInformationLength, ref int returnLength);

        private bool IsRunningAsAdmin()
        {
            try
            {
                using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
                {
                    var principal = new System.Security.Principal.WindowsPrincipal(identity);
                    return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }

        private void DetectSecuritySoftware(SecurityInfo sec)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2",
                    "SELECT * FROM AntiVirusProduct"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        var name = obj["displayName"]?.ToString();
                        if (!string.IsNullOrEmpty(name))
                        {
                            sec.securitySoftwareList.Add(name);
                            sec.antivirusActive = true;
                        }
                    }
                }
            }
            catch { }
        }

        private void DetectAnalysisTools(SecurityInfo sec)
        {
            var analysisTools = new[]
            {
            "wireshark", "fiddler", "charles", "burp",
            "processhacker", "procmon", "procexp",
            "ollydbg", "x64dbg", "ida", "ghidra",
            "cheatengine", "artmoney", "gameguardian"
        };

            foreach (var process in currentFingerprint.processes.runningProcesses)
            {
                var processLower = process.ToLower();
                foreach (var tool in analysisTools)
                {
                    if (processLower.Contains(tool))
                    {
                        sec.analysisToolsDetected.Add(process);
                    }
                }
            }
        }

        private void CheckFirewallStatus(SecurityInfo sec)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2",
                    "SELECT * FROM FirewallProduct"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        sec.firewallEnabled = true;
                        break;
                    }
                }
            }
            catch { }
        }

        private void CheckOpenPorts(SecurityInfo sec)
        {
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var listeners = properties.GetActiveTcpListeners();

                foreach (var listener in listeners)
                {
                    sec.openPorts.Add(listener.Port);
                }
            }
            catch { }
        }

        private bool DetectSandbox()
        {
            // Check for sandbox indicators
            var sandboxIndicators = new[]
            {
            @"C:\analysis",
            @"C:\inetpub",
            @"C:\sandbox",
            @"C:\virus"
        };

            foreach (var path in sandboxIndicators)
            {
                if (Directory.Exists(path))
                    return true;
            }

            // Check for sandbox processes
            var sandboxProcesses = new[] { "sandboxie", "cuckoomon", "vboxservice" };
            foreach (var process in currentFingerprint.processes.runningProcesses)
            {
                if (sandboxProcesses.Any(sp => process.ToLower().Contains(sp)))
                    return true;
            }

            return false;
        }

        private float GetSystemUptime()
        {
            try
            {
                return Environment.TickCount / 1000f / 60f; // Convert to minutes
            }
            catch
            {
                return 0f;
            }
        }
#endif
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
"/data/local/su",
"/su/bin/su"
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
                "eu.chainfire.supersu",
                "com.kingroot.kinguser",
                "com.kingo.root",
                "com.smedialink.oneclickroot",
                "com.zhiqupk.root.global"
            };
            
            foreach (var package in rootPackages)
            {
                if (IsPackageInstalled(package))
                    return true;
            }
            
            // Check build properties
            using (var build = new AndroidJavaClass("android.os.Build"))
            {
                var tags = build.GetStatic<string>("TAGS");
                if (tags != null && tags.Contains("test-keys"))
                    return true;
            }
        }
        catch { }
        
        return false;
    }
#endif
        #endregion
        #region Performance Collection
        private void CollectPerformanceInfo()
        {
            var perf = currentFingerprint.performance;

            // CPU usage
            perf.cpuUsagePercent = GetCPUUsage();

            // Memory usage
            perf.memoryUsagePercent = GetMemoryUsage();

            // Disk usage
            perf.diskUsagePercent = GetDiskUsage();

            // Timing tests
            PerformTimingTests(perf);

            // Render performance
            perf.renderPerformanceScore = CalculateRenderScore();

            // Memory integrity
            perf.memoryIntegrityValid = CheckMemoryIntegrity();
        }

        private float GetCPUUsage()
        {
#if UNITY_STANDALONE_WIN
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name='_Total'"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        return Convert.ToSingle(obj["PercentProcessorTime"] ?? 0);
                    }
                }
            }
            catch { }
#endif
            return 0f;
        }
        private float GetMemoryUsage()
        {
            var hw = currentFingerprint.hardware;
            if (hw.totalRamMB > 0 && hw.availableRamMB > 0)
            {
                return ((hw.totalRamMB - hw.availableRamMB) / (float)hw.totalRamMB) * 100f;
            }
            return 0f;
        }

        private float GetDiskUsage()
        {
            var hw = currentFingerprint.hardware;
            if (hw.disks.Count > 0)
            {
                var totalSize = hw.disks.Sum(d => d.totalSizeGB);
                var freeSize = hw.disks.Sum(d => d.freeSizeGB);
                if (totalSize > 0)
                {
                    return ((totalSize - freeSize) / (float)totalSize) * 100f;
                }
            }
            return 0f;
        }

        private void PerformTimingTests(PerformanceInfo perf)
        {
            const int iterations = 50;

            // CPU timing tests
            for (int i = 0; i < iterations; i++)
            {
                var start = DateTime.UtcNow.Ticks;

                // Simple CPU operation
                double result = 0;
                for (int j = 0; j < 10000; j++)
                {
                    result += Math.Sqrt(j);
                }

                var end = DateTime.UtcNow.Ticks;
                perf.cpuTimingTests.Add((end - start) / 10000f); // Convert to microseconds
            }

            // Memory timing tests
            for (int i = 0; i < iterations; i++)
            {
                var start = DateTime.UtcNow.Ticks;

                // Memory allocation
                var buffer = new byte[1024 * 1024]; // 1MB
                for (int j = 0; j < buffer.Length; j++)
                {
                    buffer[j] = (byte)(j % 256);
                }

                var end = DateTime.UtcNow.Ticks;
                perf.memoryTimingTests.Add((end - start) / 10000f);
            }

            // Calculate statistics
            if (perf.cpuTimingTests.Count > 0)
            {
                perf.averageTestTime = perf.cpuTimingTests.Average();

                var variance = perf.cpuTimingTests.Sum(t => Math.Pow(t - perf.averageTestTime, 2)) / perf.cpuTimingTests.Count;
                perf.timingVariance = (float)variance;

                // High variance may indicate VM/emulator
                perf.suspiciousTimingDetected = variance > 1000;
            }
        }

        private float CalculateRenderScore()
        {
            // Simple render performance based on Unity stats
            return Application.targetFrameRate > 0 ? Application.targetFrameRate : 60f;
        }

        private bool CheckMemoryIntegrity()
        {
            // Simple memory integrity check
            try
            {
                var testData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
                var encoded = Convert.ToBase64String(testData);
                var decoded = Convert.FromBase64String(encoded);

                for (int i = 0; i < testData.Length; i++)
                {
                    if (testData[i] != decoded[i])
                        return false;
                }
                return true;
            }
            catch
            {
                return false;
            }
        }
        #endregion

        #region Risk Calculation
        private void CalculateRiskScore()
        {
            var risk = currentFingerprint.risk;
            risk.riskFactors.Clear();
            risk.detectedThreats.Clear();

            float totalScore = 0f;

            // CRITICAL: Emulator detection - instant 100%
            if (currentFingerprint.emulator.isEmulator)
            {
                risk.riskFactors["Emulator"] = 100f;
                risk.detectedThreats.Add($"EMULATOR DETECTED: {currentFingerprint.emulator.emulatorType}");
                totalScore = 100f; // Instant max risk
            }

            // CRITICAL: VM detection - instant 100%
            if (currentFingerprint.virtualization.isVirtualized)
            {
                risk.riskFactors["Virtual Machine"] = 100f;
                risk.detectedThreats.Add($"VM DETECTED: {currentFingerprint.virtualization.hypervisorType}");
                totalScore = 100f; // Instant max risk
            }

            // Additional threats (only if not already at 100%)
            if (totalScore < 100f)
            {
                // Cheat tools
                if (currentFingerprint.processes.knownCheatTools.Count > 0)
                {
                    risk.riskFactors["Cheat Tools"] = 80f;
                    risk.detectedThreats.Add($"Cheat Tools: {string.Join(", ", currentFingerprint.processes.knownCheatTools)}");
                    totalScore += 80f;
                }

                // Debugger
                if (currentFingerprint.security.debuggerPresent)
                {
                    risk.riskFactors["Debugger"] = 70f;
                    risk.detectedThreats.Add("Debugger Attached");
                    totalScore += 70f;
                }

                // Analysis tools
                if (currentFingerprint.security.analysisToolsDetected.Count > 0)
                {
                    risk.riskFactors["Analysis Tools"] = 60f;
                    risk.detectedThreats.Add($"Analysis Tools: {string.Join(", ", currentFingerprint.security.analysisToolsDetected)}");
                    totalScore += 60f;
                }

                // Rooted/Jailbroken
                if (currentFingerprint.security.rootedDevice || currentFingerprint.security.jailbrokenDevice)
                {
                    risk.riskFactors["Modified Device"] = 50f;
                    risk.detectedThreats.Add("Device is Rooted/Jailbroken");
                    totalScore += 50f;
                }

                // Sandbox environment
                if (currentFingerprint.security.sandboxEnvironmentDetected)
                {
                    risk.riskFactors["Sandbox"] = 40f;
                    risk.detectedThreats.Add("Sandbox Environment");
                    totalScore += 40f;
                }

                // Suspicious timing
                if (currentFingerprint.performance.suspiciousTimingDetected)
                {
                    risk.riskFactors["Timing Anomaly"] = 30f;
                    risk.detectedThreats.Add("Suspicious Timing Patterns");
                    totalScore += 30f;
                }
            }

            // Final risk score
            risk.totalRiskScore = Math.Min(100f, totalScore);

            // Determine risk level
            if (risk.totalRiskScore >= 100f)
            {
                risk.riskLevel = "BLOCKED";
                risk.shouldBlock = true;
            }
            else if (risk.totalRiskScore >= 80f)
            {
                risk.riskLevel = "CRITICAL";
                risk.shouldBlock = true;
            }
            else if (risk.totalRiskScore >= 60f)
            {
                risk.riskLevel = "HIGH";
                risk.shouldBlock = true;
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
        #endregion

        #region Utility Methods
        private string GenerateUniqueId()
        {
            var components = new List<string>();

            // Hardware components
            var hw = currentFingerprint.hardware;
            components.Add(hw.cpuId ?? "");
            components.Add(hw.motherboardId ?? "");
            components.Add(hw.biosSerialNumber ?? "");

            // Network MACs
            foreach (var adapter in currentFingerprint.network.adapters)
            {
                if (!string.IsNullOrEmpty(adapter.macAddress))
                    components.Add(adapter.macAddress);
            }

            // Disk serials
            foreach (var disk in hw.disks)
            {
                if (!string.IsNullOrEmpty(disk.serialNumber))
                    components.Add(disk.serialNumber);
            }

            // Create SHA-256 hash
            var combined = string.Join("|", components.Where(c => !string.IsNullOrEmpty(c)));

            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(combined));
                return Convert.ToBase64String(hashBytes);
            }
        }

        private string GenerateFingerprintHash()
        {
            // Create a comprehensive fingerprint hash
            var fingerprint = JsonUtility.ToJson(currentFingerprint);

            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(fingerprint));
                return Convert.ToBase64String(hashBytes);
            }
        }

        private void HandleSecurityViolation()
        {
            if (enableDebugMode)
            {
                UnityEngine.Debug.LogError($"⚠️ SECURITY VIOLATION: {currentFingerprint.risk.totalRiskScore}% - {currentFingerprint.risk.riskLevel}");
                if (currentFingerprint.risk.detectedThreats.Count > 0)
                {
                    UnityEngine.Debug.LogError($"Risk Sebepleri: {string.Join(", ", currentFingerprint.risk.detectedThreats)}");
                }
            }

            OnSecurityViolationDetected?.Invoke(currentFingerprint);

            // Optionally quit application
            if (currentFingerprint.risk.totalRiskScore >= 100f)
            {
                if (enableDebugMode)
                {
                    // Critical threat detected - application will be terminated
                }

                // Give time for logging
                Invoke(nameof(QuitApplication), 2f);
            }
        }
        private void QuitApplication()
        {
#if UNITY_EDITOR
            UnityEditor.EditorApplication.isPlaying = false;
#else
            Application.Quit();
#endif
        }
        #endregion

        #region Events
        public static event Action<SystemFingerprint> OnSecurityViolationDetected;
        #endregion

        #region WebClient Extension
        // WebClient with timeout support
        private class WebClient : System.Net.WebClient
        {
            public int Timeout { get; set; } = 5000;

            protected override WebRequest GetWebRequest(Uri uri)
            {
                WebRequest w = base.GetWebRequest(uri);
                w.Timeout = Timeout;
                return w;
            }
        }
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

        [Header("Detection Results")]
        [SerializeField] private bool vmDetected = false;
        [SerializeField] private string vmType = "";
        [SerializeField] private bool emulatorDetected = false;
        [SerializeField] private string emulatorType = "";

        [Header("Debug Settings")]
        [SerializeField] private bool saveJSONToFile = true;
        [SerializeField] private bool logJSONToConsole = true;
        [SerializeField] private bool compactJSON = false; // false = pretty print

        [Header("JSON Output")]
        [TextArea(20, 50)]
        [SerializeField] private string fingerprintJSON = "";
        
        private DebugLogger debugLogger;

        void Start()
        {
            // DebugLogger'ı başlat
            debugLogger = FindObjectOfType<DebugLogger>();
            if (debugLogger == null)
            {
                GameObject loggerObj = new GameObject("DebugLogger");
                debugLogger = loggerObj.AddComponent<DebugLogger>();
                DontDestroyOnLoad(loggerObj);
            }
            
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
        
        private void LogDebug(string message)
        {
            if (debugLogger != null)
            {
                debugLogger.Log(message);
            }
            else
            {
                Debug.Log(message);
            }
        }

        [ContextMenu("Run AntiCheat Test")]
        public void RunTest()
        {
            var antiCheat = UnifiedAntiCheatSystem.Instance;
            antiCheat.Initialize();

            // Wait a frame for initialization
            StartCoroutine(GetTestResults());
        }

        [ContextMenu("Generate and Show JSON")]
        public void GenerateAndShowJSON()
        {
            // UnifiedAntiCheatSystem instance'ını al
            var antiCheat = UnifiedAntiCheatSystem.Instance;
            if (antiCheat == null)
            {
                UnityEngine.Debug.LogError("[AntiCheat] UnifiedAntiCheatSystem instance not found!");
                return;
            }

            // Scan yap
            antiCheat.Initialize();

            // Fingerprint'i al
            var fingerprint = antiCheat.GetCurrentFingerprint();
            if (fingerprint == null)
            {
                UnityEngine.Debug.LogError("[AntiCheat] No fingerprint data available!");
                return;
            }

            // Risk bilgilerini göster
            LogDebug("⚠️ RISK ASSESSMENT:");
            string systemType = antiCheat.GetSystemTypeDescription();
            LogDebug($"Risk Score: {fingerprint.risk.totalRiskScore}% - {fingerprint.risk.riskLevel} | {systemType}");
            
            if (fingerprint.risk.detectedThreats.Count > 0)
            {
                LogDebug($"Risk Sebepleri: {string.Join(", ", fingerprint.risk.detectedThreats)}");
            }
            else
            {
                LogDebug("Risk Sebepleri: Temiz sistem - risk tespit edilmedi");
            }

            // JSON'u al ve göster
            string json = antiCheat.GetFingerprintJSON();
            fingerprintJSON = json;

            // JSON'u her zaman göster
            LogDebug("[AntiCheat] Full Fingerprint JSON:");
            LogDebug(json);

            if (saveJSONToFile)
            {
                antiCheat.SaveJSONToFile(json);
            }
        }

        [ContextMenu("Open JSON Save Location")]
        public void OpenJSONLocation()
        {
            Application.OpenURL(Application.persistentDataPath);
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
            if (fingerprint != null)
            {
                if (fingerprint.risk != null)
                {
                    lastRiskLevel = fingerprint.risk.riskLevel;
                }

                if (fingerprint.virtualization != null)
                {
                    vmDetected = fingerprint.virtualization.isVirtualized;
                    vmType = fingerprint.virtualization.hypervisorType;
                }

                if (fingerprint.emulator != null)
                {
                    emulatorDetected = fingerprint.emulator.isEmulator;
                    emulatorType = fingerprint.emulator.emulatorType;
                }
            }

            testCompleted = true;

            // Log results
            LogTestResults(fingerprint);
        }

        private void LogTestResults(UnifiedAntiCheatSystem.SystemFingerprint fingerprint)
        {
            // Risk Assessment
            LogDebug("⚠️ RISK ASSESSMENT:");
            var antiCheat = UnifiedAntiCheatSystem.Instance;
            string systemType = antiCheat?.GetSystemTypeDescription() ?? "Unknown System";
            LogDebug($"Risk Score: {lastRiskScore}% - {lastRiskLevel} | {systemType}");
            
            if (fingerprint != null && fingerprint.risk.detectedThreats.Count > 0)
            {
                LogDebug($"Risk Sebepleri: {string.Join(", ", fingerprint.risk.detectedThreats)}");
            }
            else
            {
                LogDebug("Risk Sebepleri: Temiz sistem - risk tespit edilmedi");
            }

        }

        private void OnViolationDetected(UnifiedAntiCheatSystem.SystemFingerprint fingerprint)
        {
            UnityEngine.Debug.LogError($"⚠️ SECURITY VIOLATION: {fingerprint.risk.totalRiskScore}% - {fingerprint.risk.riskLevel}");
        }

        [ContextMenu("Export JSON to File")]
        public void ExportJSON()
        {
            if (string.IsNullOrEmpty(fingerprintJSON))
            {
                UnityEngine.Debug.LogError("No fingerprint data to export. Run test first!");
                return;
            }

            var path = Path.Combine(Application.persistentDataPath, $"anticheat_fingerprint_{DateTime.Now:yyyyMMdd_HHmmss}.json");
            File.WriteAllText(path, fingerprintJSON);
            
            // Also log the path to clipboard if possible
            GUIUtility.systemCopyBuffer = path;
        }

        [ContextMenu("Clear Test Results")]
        public void ClearResults()
        {
            testCompleted = false;
            lastRiskScore = 0f;
            lastRiskLevel = "";
            systemBlocked = false;
            vmDetected = false;
            vmType = "";
            emulatorDetected = false;
            emulatorType = "";
            fingerprintJSON = "";

            UnityEngine.Debug.Log("[AntiCheat Test] Test results cleared");
        }
    }
}
