using UnityEngine;
using UnityEngine.UI;
using UnityEngine.InputSystem;
using System.Collections;

namespace AntiCheatSystem
{
    public class DebugCanvasUI : MonoBehaviour
    {
        [Header("UI References")]
        public Canvas debugCanvas;
        public ScrollRect scrollRect;
        public Text logText;
        public Button showAllButton;
        public Button copyButton;
        public Button clearButton;
        public Button scrollToTopButton;
        public Button scrollToBottomButton;

        [Header("Settings")]
        public bool startVisible = true;
        public bool autoScrollToBottom = true;
        public bool showFullLogs = false;
        public int maxDisplayLines = 100;

        [Header("Auto Scroll")]
        public float scrollSpeed = 5f;
        public bool smoothScroll = true;

        [Header("Scroll Settings")]
        public float mouseWheelSensitivity = 3f;
        public float scrollMomentum = 0.95f;
        public bool enableScrollMomentum = true;

        [Header("Touch Controls (Android)")]
        public bool enableTouchControls = true;
        public bool enableSwipeGestures = true;
        public float swipeThreshold = 50f;

        // Private variables
        private bool isVisible = false;
        private DebugLogger debugLogger;
        private bool isAutoScrolling = false;
        private string lastLogContent = "";
        private Keyboard keyboard;
        private float scrollVelocity = 0f;

        void Awake()
        {
            // Input System'i başlat
            keyboard = Keyboard.current;
        }

        void Start()
        {
            // DebugLogger'ı bul veya oluştur
            debugLogger = FindObjectOfType<DebugLogger>();
            if (debugLogger == null)
            {
                GameObject loggerObj = new GameObject("DebugLogger");
                debugLogger = loggerObj.AddComponent<DebugLogger>();
                DontDestroyOnLoad(loggerObj);
            }

            // UI'yi başlat
            InitializeUI();

            // Başlangıç durumunu ayarla
            SetCanvasVisibility(startVisible);
        }

        void Update()
        {
            // Null check for keyboard
            if (keyboard == null)
            {
                keyboard = Keyboard.current;
                return;
            }

            // F1 ile toggle
            if (keyboard.f1Key.wasPressedThisFrame)
            {
                ToggleCanvasVisibility();
            }

            if (isVisible)
            {
                // Mouse wheel ile kaydırma
                float scrollInput = Mouse.current != null ? Mouse.current.scroll.ReadValue().y : 0f;
                if (Mathf.Abs(scrollInput) > 0.1f)
                {
                    scrollVelocity = scrollInput * mouseWheelSensitivity * Time.deltaTime;
                    ApplyScrollVelocity();
                }

                // Scroll momentum uygula
                if (enableScrollMomentum && Mathf.Abs(scrollVelocity) > 0.01f)
                {
                    ApplyScrollVelocity();
                    scrollVelocity *= scrollMomentum;
                }

                // Home tuşu ile en üste git
                if (keyboard.homeKey.wasPressedThisFrame)
                {
                    ScrollToTop();
                }
                // End tuşu ile en alta git
                else if (keyboard.endKey.wasPressedThisFrame)
                {
                    ScrollToBottom();
                }
                // Ctrl+C ile kopyala
                else if (keyboard.cKey.wasPressedThisFrame &&
                        (keyboard.leftCtrlKey.isPressed || keyboard.rightCtrlKey.isPressed))
                {
                    CopyLogsToClipboard();
                }
                // Delete ile temizle
                else if (keyboard.deleteKey.wasPressedThisFrame)
                {
                    ClearLogs();
                }
                // Page Up ile yukarı scroll
                else if (keyboard.pageUpKey.wasPressedThisFrame)
                {
                    StartCoroutine(ScrollUpPage());
                }
                // Page Down ile aşağı scroll
                else if (keyboard.pageDownKey.wasPressedThisFrame)
                {
                    StartCoroutine(ScrollDownPage());
                }
            }
        }

        void OnDestroy()
        {
            if (debugLogger != null)
            {
                debugLogger.UnsubscribeFromLogUpdates(OnLogUpdated);
            }
        }

        private void InitializeUI()
        {
            // Buton eventlerini ayarla
            if (showAllButton != null)
            {
                showAllButton.onClick.AddListener(ToggleShowAllLogs);
                UpdateShowAllButtonText();
            }

            if (copyButton != null)
            {
                copyButton.onClick.AddListener(CopyLogsToClipboard);
            }

            if (clearButton != null)
            {
                clearButton.onClick.AddListener(ClearLogs);
            }

            if (scrollToTopButton != null)
            {
                scrollToTopButton.onClick.AddListener(ScrollToTop);
            }

            if (scrollToBottomButton != null)
            {
                scrollToBottomButton.onClick.AddListener(ScrollToBottom);
            }


            // DebugLogger'a abone ol
            if (debugLogger != null)
            {
                debugLogger.SubscribeToLogUpdates(OnLogUpdated);
                // Başlangıçta text'i güncelle
                UpdateTextDisplay();
            }
        }

        public void SetCanvasVisibility(bool visible)
        {
            isVisible = visible;
            if (debugCanvas != null)
            {
                debugCanvas.gameObject.SetActive(visible);
            }
        }

        public void ToggleCanvasVisibility()
        {
            SetCanvasVisibility(!isVisible);
        }

        private void OnLogUpdated(string logs)
        {
            if (logText != null)
            {
                UpdateLogDisplay(logs);

                // Otomatik scroll (yeni log geldiğinde)
                if (autoScrollToBottom && !isAutoScrolling)
                {
                    StartCoroutine(AutoScrollToBottom());
                }
            }
        }

        private void UpdateLogDisplay(string logs)
        {
            if (string.IsNullOrEmpty(logs))
            {
                logText.text = "Debug console ready...\nWaiting for logs...";
                return;
            }

            string displayText;

            if (showFullLogs)
            {
                // Tüm logları göster
                displayText = logs;
            }
            else
            {
                // Sadece son N satırı göster
                string[] lines = logs.Split('\n');
                if (lines.Length > maxDisplayLines)
                {
                    string[] lastLines = new string[maxDisplayLines];
                    System.Array.Copy(lines, lines.Length - maxDisplayLines, lastLines, 0, maxDisplayLines);
                    displayText = string.Join("\n", lastLines);
                    displayText = $"... (showing last {maxDisplayLines} lines) ...\n" + displayText;
                }
                else
                {
                    displayText = logs;
                }
            }

            logText.text = displayText;
            lastLogContent = displayText;
        }

        private void UpdateTextDisplay()
        {
            if (logText != null && debugLogger != null)
            {
                string allLogs = debugLogger.GetAllLogsAsString();
                UpdateLogDisplay(allLogs);
            }
        }

        public void ToggleShowAllLogs()
        {
            showFullLogs = !showFullLogs;
            UpdateShowAllButtonText();
            UpdateTextDisplay();

            // Eğer tüm logları göstermeye geçtiyse en üste scroll yap
            if (showFullLogs)
            {
                StartCoroutine(ScrollToTopCoroutine());
            }
        }

        private void UpdateShowAllButtonText()
        {
            if (showAllButton != null)
            {
                Text buttonText = showAllButton.GetComponentInChildren<Text>();
                if (buttonText != null)
                {
                    buttonText.text = showFullLogs ? "Show Recent" : "Show All";
                }
            }
        }

        public void ScrollToTop()
        {
            if (smoothScroll)
            {
                StartCoroutine(ScrollToTopCoroutine());
            }
            else
            {
                if (scrollRect != null)
                {
                    scrollRect.verticalNormalizedPosition = 1f;
                }
            }
        }

        public void ScrollToBottom()
        {
            if (smoothScroll)
            {
                StartCoroutine(ScrollToBottomCoroutine());
            }
            else
            {
                if (scrollRect != null)
                {
                    scrollRect.verticalNormalizedPosition = 0f;
                }
            }
        }

        private IEnumerator ScrollToTopCoroutine()
        {
            if (scrollRect == null) yield break;

            isAutoScrolling = true;
            float startPos = scrollRect.verticalNormalizedPosition;
            float targetPos = 1f;
            float journey = 0f;

            while (journey <= 1f)
            {
                journey += Time.deltaTime * scrollSpeed;
                scrollRect.verticalNormalizedPosition = Mathf.Lerp(startPos, targetPos, journey);
                yield return null;
            }

            scrollRect.verticalNormalizedPosition = targetPos;
            isAutoScrolling = false;
        }

        private IEnumerator ScrollToBottomCoroutine()
        {
            if (scrollRect == null) yield break;

            isAutoScrolling = true;
            float startPos = scrollRect.verticalNormalizedPosition;
            float targetPos = 0f;
            float journey = 0f;

            while (journey <= 1f)
            {
                journey += Time.deltaTime * scrollSpeed;
                scrollRect.verticalNormalizedPosition = Mathf.Lerp(startPos, targetPos, journey);
                yield return null;
            }

            scrollRect.verticalNormalizedPosition = targetPos;
            isAutoScrolling = false;
        }

        private IEnumerator AutoScrollToBottom()
        {
            // Bir frame bekle ki layout güncellensin
            yield return new WaitForEndOfFrame();

            if (autoScrollToBottom && scrollRect != null)
            {
                if (smoothScroll)
                {
                    yield return StartCoroutine(ScrollToBottomCoroutine());
                }
                else
                {
                    scrollRect.verticalNormalizedPosition = 0f;
                }
            }
        }

        private IEnumerator ScrollUpPage()
        {
            if (scrollRect == null) yield break;

            isAutoScrolling = true;
            float currentPos = scrollRect.verticalNormalizedPosition;
            float targetPos = Mathf.Clamp01(currentPos + 0.3f); // %30 yukarı
            float journey = 0f;

            while (journey <= 1f)
            {
                journey += Time.deltaTime * scrollSpeed;
                scrollRect.verticalNormalizedPosition = Mathf.Lerp(currentPos, targetPos, journey);
                yield return null;
            }

            scrollRect.verticalNormalizedPosition = targetPos;
            isAutoScrolling = false;
        }

        private IEnumerator ScrollDownPage()
        {
            if (scrollRect == null) yield break;

            isAutoScrolling = true;
            float currentPos = scrollRect.verticalNormalizedPosition;
            float targetPos = Mathf.Clamp01(currentPos - 0.3f); // %30 aşağı
            float journey = 0f;

            while (journey <= 1f)
            {
                journey += Time.deltaTime * scrollSpeed;
                scrollRect.verticalNormalizedPosition = Mathf.Lerp(currentPos, targetPos, journey);
                yield return null;
            }

            scrollRect.verticalNormalizedPosition = targetPos;
            isAutoScrolling = false;
        }

        public void CopyLogsToClipboard()
        {
            if (debugLogger != null)
            {
                debugLogger.CopyAllLogsToClipboard();

                // Geçici bilgi mesajı göster
                StartCoroutine(ShowTemporaryMessage("[SYSTEM] Logs copied to clipboard!"));
            }
        }

        public void ClearLogs()
        {
            if (debugLogger != null)
            {
                debugLogger.ClearLogs();
            }
        }

        private IEnumerator ShowTemporaryMessage(string message)
        {
            if (logText != null)
            {
                string originalText = logText.text;
                logText.text = originalText + "\n" + message;

                yield return new WaitForSeconds(2f);

                // Orijinal text'e geri dön
                logText.text = originalText;
            }
        }

        // Public methods for external control
        public void SetAutoScroll(bool enabled)
        {
            autoScrollToBottom = enabled;
        }

        public void SetSmoothScroll(bool enabled)
        {
            smoothScroll = enabled;
        }

        public void SetMaxDisplayLines(int lines)
        {
            maxDisplayLines = Mathf.Max(10, lines);
            if (!showFullLogs)
            {
                UpdateTextDisplay();
            }
        }

        private void ApplyScrollVelocity()
        {
            if (scrollRect != null && !isAutoScrolling)
            {
                float currentPos = scrollRect.verticalNormalizedPosition;
                float newPos = Mathf.Clamp01(currentPos + scrollVelocity);
                scrollRect.verticalNormalizedPosition = newPos;
            }
        }

        // Public methods for scroll settings
        public void SetMouseWheelSensitivity(float sensitivity)
        {
            mouseWheelSensitivity = Mathf.Max(0.1f, sensitivity);
        }

        public void SetScrollMomentum(bool enabled, float momentum = 0.95f)
        {
            enableScrollMomentum = enabled;
            scrollMomentum = Mathf.Clamp01(momentum);
        }
    }
}
