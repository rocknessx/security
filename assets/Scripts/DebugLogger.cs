using System.Collections.Generic;
using UnityEngine;
using System.Text;

namespace AntiCheatSystem
{
    public class DebugLogger : MonoBehaviour
    {
        [Header("Debug Logger Settings")]
        public int maxLogEntries = 1000;
        public bool enableTimestamp = true;
        public bool enableLogType = true;
        
        private List<LogEntry> logEntries = new List<LogEntry>();
        private System.Action<string> onLogUpdated;
        
        public static DebugLogger Instance { get; private set; }
        
        [System.Serializable]
        public class LogEntry
        {
            public string message;
            public LogType logType;
            public string timestamp;
            public string fullText;
            
            public LogEntry(string msg, LogType type)
            {
                message = msg;
                logType = type;
                timestamp = System.DateTime.Now.ToString("HH:mm:ss");
                fullText = $"[{timestamp}] {type}: {msg}";
            }
        }
        
        public enum LogType
        {
            Log,
            Warning,
            Error
        }
        
        void Awake()
        {
            if (Instance == null)
            {
                Instance = this;
                DontDestroyOnLoad(gameObject);
            }
            else
            {
                Destroy(gameObject);
            }
        }
        
        public void Log(string message)
        {
            AddLogEntry(message, LogType.Log);
        }
        
        public void LogWarning(string message)
        {
            AddLogEntry(message, LogType.Warning);
        }
        
        public void LogError(string message)
        {
            AddLogEntry(message, LogType.Error);
        }
        
        private void AddLogEntry(string message, LogType logType)
        {
            var entry = new LogEntry(message, logType);
            logEntries.Add(entry);
            
            // Maksimum log sayısını aş
            if (logEntries.Count > maxLogEntries)
            {
                logEntries.RemoveAt(0);
            }
            
            // UI'yi güncelle
            onLogUpdated?.Invoke(GetAllLogsAsString());
            
            // Console'a da yazdır (Unity'nin kendi debug sistemi için)
            switch (logType)
            {
                case LogType.Log:
                    Debug.Log(message);
                    break;
                case LogType.Warning:
                    Debug.LogWarning(message);
                    break;
                case LogType.Error:
                    Debug.LogError(message);
                    break;
            }
        }
        
        public string GetAllLogsAsString()
        {
            var sb = new StringBuilder();
            foreach (var entry in logEntries)
            {
                sb.AppendLine(entry.fullText);
            }
            return sb.ToString();
        }
        
        public List<LogEntry> GetAllLogs()
        {
            return new List<LogEntry>(logEntries);
        }
        
        public void ClearLogs()
        {
            logEntries.Clear();
            onLogUpdated?.Invoke("");
        }
        
        public void SubscribeToLogUpdates(System.Action<string> callback)
        {
            onLogUpdated += callback;
        }
        
        public void UnsubscribeFromLogUpdates(System.Action<string> callback)
        {
            onLogUpdated -= callback;
        }
        
        public void CopyAllLogsToClipboard()
        {
            string allLogs = GetAllLogsAsString();
            GUIUtility.systemCopyBuffer = allLogs;
            Debug.Log("Debug logs copied to clipboard!");
        }
    }
}

