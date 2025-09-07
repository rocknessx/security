using UnityEngine;

namespace AntiCheatSystem
{
    public class AntiCheatDebugBridge : MonoBehaviour
    {
        [Header("References")]
        public DebugLogger debugLogger;
        public UnifiedAntiCheatSystem antiCheatSystem;
        
        [Header("Settings")]
        public bool showJSONFingerprint = true;
        public bool showDetailedInfo = true;
        
        void Start()
        {
            // Referansları bul
            if (debugLogger == null)
                debugLogger = FindObjectOfType<DebugLogger>();
                
            if (antiCheatSystem == null)
                antiCheatSystem = UnifiedAntiCheatSystem.Instance;
            
            // AntiCheat sistemini başlat
            if (antiCheatSystem != null)
            {
                antiCheatSystem.Initialize();
                LogMessage("AntiCheat System Initialized");
            }
            
            // Test için birkaç saniye sonra bilgi al
            Invoke(nameof(LogSystemInfo), 3f);
        }
        
        void LogSystemInfo()
        {
            if (antiCheatSystem == null || debugLogger == null) return;
            
            var fingerprint = antiCheatSystem.GetCurrentFingerprint();
            if (fingerprint != null)
            {
                LogMessage("=== ANTICHEAT SYSTEM INFO ===");
                
                if (showDetailedInfo)
                {
                    LogMessage($"Platform: {fingerprint.platform}");
                    LogMessage($"Unity Version: {fingerprint.unityVersion}");
                    LogMessage($"Game Version: {fingerprint.gameVersion}");
                    LogMessage($"Timestamp: {fingerprint.timestamp}");
                    LogMessage($"Device ID: {fingerprint.hardware.deviceId}");
                    LogMessage($"Device Model: {fingerprint.hardware.deviceModel}");
                    LogMessage($"Device Name: {fingerprint.hardware.deviceName}");
                    LogMessage($"Processor Type: {fingerprint.hardware.processorType}");
                    LogMessage($"Processor Count: {fingerprint.hardware.processorCount}");
                    LogMessage($"Graphics Device: {fingerprint.hardware.graphicsDeviceName}");
                    LogMessage($"System Memory: {fingerprint.hardware.systemMemorySize} MB");
                    LogMessage($"Risk Score: {antiCheatSystem.GetRiskScore():F1}%");
                    LogMessage($"Risk Level: {fingerprint.risk.riskLevel}");
                    LogMessage($"Is Safe: {antiCheatSystem.IsSystemSafe()}");
                    LogMessage($"Is Virtualized: {fingerprint.virtualization.isVirtualized}");
                    LogMessage($"VM Confidence: {fingerprint.virtualization.confidenceScore:F1}%");
                    
                    if (fingerprint.virtualization.evidence.Count > 0)
                    {
                        LogMessage($"VM Evidence: {string.Join(", ", fingerprint.virtualization.evidence)}");
                    }
                    
                    if (fingerprint.processes.knownEmulators.Count > 0)
                    {
                        LogMessage($"Emulators Found: {string.Join(", ", fingerprint.processes.knownEmulators)}");
                    }
                    
                    if (fingerprint.processes.knownCheatTools.Count > 0)
                    {
                        LogMessage($"Cheat Tools Found: {string.Join(", ", fingerprint.processes.knownCheatTools)}");
                    }
                    
                    if (fingerprint.processes.suspiciousProcesses.Count > 0)
                    {
                        LogMessage($"Suspicious Processes: {string.Join(", ", fingerprint.processes.suspiciousProcesses)}");
                    }
                    
                    if (fingerprint.network.hasVirtualAdapter)
                    {
                        LogMessage($"Virtual Network Adapters: {string.Join(", ", fingerprint.network.virtualAdapterNames)}");
                    }
                    
                    if (fingerprint.risk.detectedThreats.Count > 0)
                    {
                        LogMessage($"Detected Threats: {string.Join(", ", fingerprint.risk.detectedThreats)}");
                    }
                    
                    LogMessage($"Fingerprint Hash: {fingerprint.fingerprintHash}");
                }
                
                if (showJSONFingerprint)
                {
                    LogMessage("=== FULL JSON FINGERPRINT ===");
                    string jsonData = antiCheatSystem.GetFingerprintJSON();
                    LogMessage(jsonData);
                }
                
                LogMessage("=== END OF ANTICHEAT INFO ===");
            }
        }
        
        void LogMessage(string message)
        {
            if (debugLogger != null)
            {
                debugLogger.AddLog(message);
            }
            else
            {
                Debug.Log($"[AntiCheat] {message}");
            }
        }
        
        // Manuel olarak bilgileri yenilemek için
        [ContextMenu("Refresh AntiCheat Info")]
        public void RefreshInfo()
        {
            LogSystemInfo();
        }
        
        // Sadece JSON'u göstermek için
        [ContextMenu("Show JSON Only")]
        public void ShowJSONOnly()
        {
            if (antiCheatSystem == null || debugLogger == null) return;
            
            LogMessage("=== JSON FINGERPRINT ===");
            string jsonData = antiCheatSystem.GetFingerprintJSON();
            LogMessage(jsonData);
        }
    }
}
