using UnityEngine;
using UnityEngine.UI;
using System.Collections.Generic;
using System.Text;

namespace AntiCheatSystem
{
    public class DebugLogger : MonoBehaviour
    {
        [Header("UI References")]
        public Text logText;
        public ScrollRect scrollRect;
        public Scrollbar verticalScrollbar;
        
        [Header("Settings")]
        public int maxLines = 999999;
        public bool autoScroll = false;
        public bool wordWrap = true;
        public float lineHeight = 16f;
        public bool captureUnityLogs = true;
        public bool showAllLogs = true;
        
        private List<string> logLines = new List<string>();
        private StringBuilder stringBuilder = new StringBuilder();
        
        void Start()
        {
            // AntiCheat sistemine event bağla
            UnifiedAntiCheatSystem.OnSecurityViolationDetected += OnSecurityViolation;
            
            // Unity log'larını yakala
            if (captureUnityLogs)
            {
                Application.logMessageReceived += OnUnityLogReceived;
            }
            
            // İlk mesaj
            AddLog("Debug Logger Started - Ready to display AntiCheat information");
            AddLog("Unity Console logs will be captured and displayed here");
            AddLog($"Max Lines: {maxLines} (Unlimited)");
            
            // Scroll ayarlarını düzelt
            SetupScrollRect();
        }
        
        void OnUnityLogReceived(string logString, string stackTrace, LogType type)
        {
            if (showAllLogs || logString.Contains("[AntiCheat]") || logString.Contains("AntiCheat"))
            {
                string logType = type.ToString();
                string colorTag = GetLogColor(type);
                
                string cleanLog = logString;
                if (cleanLog.Contains("UnityEngine.Debug:Log"))
                {
                    cleanLog = cleanLog.Split(new string[] { "UnityEngine.Debug:Log" }, System.StringSplitOptions.None)[0].Trim();
                }
                
                if (cleanLog.Length > 200)
                {
                    cleanLog = cleanLog.Substring(0, 200) + "...";
                }
                
                AddLog($"{colorTag}[UNITY-{logType}] {cleanLog}</color>");
            }
        }
        
        string GetLogColor(LogType type)
        {
            switch (type)
            {
                case LogType.Error:
                    return "<color=#FF0000>";
                case LogType.Warning:
                    return "<color=#FFFF00>";
                case LogType.Assert:
                    return "<color=#FF8000>";
                default:
                    return "<color=#00FFFF>";
            }
        }
        
        void SetupScrollRect()
        {
            if (scrollRect != null)
            {
                // ScrollRect ayarları
                scrollRect.horizontal = false;
                scrollRect.vertical = true;
                scrollRect.verticalScrollbarVisibility = ScrollRect.ScrollbarVisibility.Permanent;
                scrollRect.scrollSensitivity = 20f;
                scrollRect.movementType = ScrollRect.MovementType.Elastic;
                scrollRect.elasticity = 0.1f;
                
                // Scrollbar'ı bağla
                if (verticalScrollbar != null)
                {
                    scrollRect.verticalScrollbar = verticalScrollbar;
                }
                
                // Content RectTransform ayarları - DÜZELTME
                if (scrollRect.content != null)
                {
                    RectTransform contentRect = scrollRect.content;
                    contentRect.anchorMin = new Vector2(0, 0);
                    contentRect.anchorMax = new Vector2(1, 1);
                    contentRect.pivot = new Vector2(0.5f, 0.5f);
                    contentRect.anchoredPosition = Vector2.zero;
                    contentRect.offsetMin = Vector2.zero;
                    contentRect.offsetMax = Vector2.zero;
                }
            }
            
            // Scrollbar ayarları
            if (verticalScrollbar != null)
            {
                verticalScrollbar.direction = Scrollbar.Direction.BottomToTop;
                verticalScrollbar.size = 0.1f;
                
                CanvasGroup scrollbarCanvasGroup = verticalScrollbar.GetComponent<CanvasGroup>();
                if (scrollbarCanvasGroup == null)
                {
                    scrollbarCanvasGroup = verticalScrollbar.gameObject.AddComponent<CanvasGroup>();
                }
                scrollbarCanvasGroup.alpha = 1f;
                scrollbarCanvasGroup.interactable = true;
                scrollbarCanvasGroup.blocksRaycasts = true;
            }
        }
        
        public void AddLog(string message)
        {
            string timestamp = System.DateTime.Now.ToString("HH:mm:ss");
            string colorTag = GetMessageColor(message);
            string logEntry = $"[{timestamp}] {colorTag}{message}</color>";
            
            if (message.Length > 100 && wordWrap)
            {
                string[] lines = message.Split('\n');
                foreach (string line in lines)
                {
                    if (!string.IsNullOrEmpty(line.Trim()))
                    {
                        logLines.Add($"[{timestamp}] {colorTag}{line}</color>");
                    }
                }
            }
            else
            {
                logLines.Add(logEntry);
            }
            
            if (logLines.Count > maxLines)
            {
                int removeCount = maxLines / 10;
                logLines.RemoveRange(0, removeCount);
            }
            
            UpdateLogText();
            UpdateContentSize();
            
            if (autoScroll && scrollRect != null)
            {
                StartCoroutine(ScrollToBottom());
            }
        }
        
        string GetMessageColor(string message)
        {
            if (message.Contains("SECURITY VIOLATION") || message.Contains("CRITICAL"))
                return "<color=#FF0000>";
            
            if (message.Contains("Risk Score: 100") || message.Contains("Risk Score: 8") || message.Contains("Risk Score: 9"))
                return "<color=#FF0000>";
            
            if (message.Contains("Risk Score: 6") || message.Contains("Risk Score: 7"))
                return "<color=#FF8000>";
            
            if (message.Contains("Risk Score: 4") || message.Contains("Risk Score: 5"))
                return "<color=#FFFF00>";
            
            if (message.Contains("Risk Score: 0") || message.Contains("Risk Score: 1") || message.Contains("Risk Score: 2") || message.Contains("Risk Score: 3"))
                return "<color=#00FF00>";
            
            if (message.Contains("Emulator") || message.Contains("Cheat Tools") || message.Contains("Virtual Machine"))
                return "<color=#FF0000>";
            
            if (message.Contains("VM Evidence") || message.Contains("Virtual Network"))
                return "<color=#FF8000>";
            
            if (message.Contains("Platform:") || message.Contains("Device ID:") || message.Contains("Processor"))
                return "<color=#00FFFF>";
            
            if (message.Contains("JSON") || message.Contains("Fingerprint"))
                return "<color=#FF00FF>";
            
            if (message.Contains("ERROR") || message.Contains("Error"))
                return "<color=#FF0000>";
            
            if (message.Contains("WARNING") || message.Contains("Warning"))
                return "<color=#FFFF00>";
            
            return "<color=#FFFFFF>";
        }
        
        void UpdateLogText()
        {
            if (logText == null) return;
            
            stringBuilder.Clear();
            foreach (string line in logLines)
            {
                stringBuilder.AppendLine(line);
            }
            
            logText.text = stringBuilder.ToString();
        }
        
        void UpdateContentSize()
        {
            if (scrollRect == null || scrollRect.content == null || logText == null) return;
            
            // Content boyutunu log satır sayısına göre hesapla
            float contentHeight = logLines.Count * lineHeight;
            
            // Minimum height viewport boyutu kadar olsun
            float viewportHeight = scrollRect.viewport.rect.height;
            contentHeight = Mathf.Max(contentHeight, viewportHeight);
            
            // Content boyutunu güncelle
            RectTransform contentRect = scrollRect.content;
            contentRect.sizeDelta = new Vector2(0, contentHeight);
            
            // Content positioning'i düzelt - Top'u 0'da tut
            contentRect.anchoredPosition = new Vector2(0, 0);
            
            // Text'in de boyutunu güncelle - Top'u 0'da tut
            RectTransform textRect = logText.rectTransform;
            textRect.sizeDelta = new Vector2(0, contentHeight);
            textRect.anchoredPosition = new Vector2(0, 0);
            
            // Text'in anchor'larını düzelt
            textRect.anchorMin = new Vector2(0, 0);
            textRect.anchorMax = new Vector2(1, 1);
            textRect.offsetMin = new Vector2(5, 5);
            textRect.offsetMax = new Vector2(-5, -5);
            
            // Scrollbar'ı güncelle
            if (verticalScrollbar != null)
            {
                verticalScrollbar.size = Mathf.Clamp01(viewportHeight / contentHeight);
            }
        }
        
        System.Collections.IEnumerator ScrollToBottom()
        {
            yield return new WaitForEndOfFrame();
            if (scrollRect != null)
            {
                Canvas.ForceUpdateCanvases();
                scrollRect.verticalNormalizedPosition = 0f;
            }
        }
        
        void OnSecurityViolation(UnifiedAntiCheatSystem.SystemFingerprint fingerprint)
        {
            AddLog($"SECURITY VIOLATION DETECTED!");
            AddLog($"Risk Score: {fingerprint.risk.totalRiskScore}%");
            AddLog($"Risk Level: {fingerprint.risk.riskLevel}");
            AddLog($"Threats: {string.Join(", ", fingerprint.risk.detectedThreats)}");
        }
        
        [ContextMenu("Clear All Logs")]
        public void ClearAllLogs()
        {
            logLines.Clear();
            UpdateLogText();
            UpdateContentSize();
            AddLog("All logs cleared");
        }
        
        [ContextMenu("Show Log Count")]
        public void ShowLogCount()
        {
            AddLog($"Total log lines: {logLines.Count}");
        }
        
        void OnDestroy()
        {
            UnifiedAntiCheatSystem.OnSecurityViolationDetected -= OnSecurityViolation;
            
            if (captureUnityLogs)
            {
                Application.logMessageReceived -= OnUnityLogReceived;
            }
        }
    }
}
