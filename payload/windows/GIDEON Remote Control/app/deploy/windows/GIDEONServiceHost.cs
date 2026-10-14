using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using Microsoft.Win32;
using System.Threading;
using System.Reflection;

[assembly: AssemblyTitle("GIDEON Remote Control Service Host")]
[assembly: AssemblyDescription("Isolated Windows SCM host for GIDEON Remote Control microservices")]
[assembly: AssemblyCompany("GIDEON CORP S.A.")]
[assembly: AssemblyProduct("GIDEON Remote Control")]
[assembly: AssemblyVersion("6.3.4.0")]
[assembly: AssemblyFileVersion("6.3.4.15")]
[assembly: AssemblyInformationalVersion("6.3.4-pre-rc31-resource-aware")]

namespace GIDEON.RemoteControl.WindowsServiceHost
{
    internal sealed class GideonService : ServiceBase
    {
        private readonly string gideonServiceName;
        private Process child;
        private volatile bool stopping;
        private volatile bool startupComplete;
        private string installRoot;
        private string appRoot;
        private string dataRoot;
        private Timer scheduleTimer;
        private Timer debounceTimer;
        private FileSystemWatcher updateWatcher;
        private int maintenanceRunning;

        internal GideonService(string serviceName)
        {
            if (!IsAllowedService(serviceName))
                throw new ArgumentException("Unsupported GIDEON service name: " + serviceName);
            gideonServiceName = serviceName;
            ServiceName = serviceName;
            CanStop = true;
            CanShutdown = true;
            AutoLog = false;
        }

        private static bool IsAllowedService(string name)
        {
            return name == "GIDEONRemoteControl" ||
                   name == "GIDEONRemoteControlGateway" ||
                   name == "GIDEONRemoteControlWebAdmin" ||
                   name == "GIDEONRemoteControlBackup" ||
                   name == "GIDEONRemoteControlUpdater" ||
                   name == "GIDEONRemoteControlDiagnostics";
        }

        private static string ReadRegistryValue(string name)
        {
            using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (RegistryKey key = baseKey.OpenSubKey(@"SOFTWARE\GIDEON\RemoteControl"))
            {
                if (key == null) throw new InvalidOperationException("HKLM\\SOFTWARE\\GIDEON\\RemoteControl (Registry64) not found");
                object value = key.GetValue(name);
                if (value == null) throw new InvalidOperationException("GIDEON registry value missing: " + name);
                return Convert.ToString(value);
            }
        }

        private void InitializeRoots()
        {
            // Windows OneClick uses fixed canonical roots. Seed these BEFORE registry
            // access so startup diagnostics still have a deterministic writable target
            // if Registry64 is temporarily inaccessible to a low-privilege service.
            installRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "GIDEON Remote Control");
            appRoot = Path.Combine(installRoot, "app");
            dataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GIDEON Remote Control");
            StartupLog("Canonical roots initialized. InstallRoot=" + installRoot + " AppRoot=" + appRoot + " DataRoot=" + dataRoot);

            try
            {
                string regInstall = ReadRegistryValue("InstallRoot");
                string regApp = ReadRegistryValue("AppRoot");
                string regData = ReadRegistryValue("DataRoot");
                if (!Path.GetFullPath(regInstall).TrimEnd('\\').Equals(Path.GetFullPath(installRoot).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) ||
                    !Path.GetFullPath(regApp).TrimEnd('\\').Equals(Path.GetFullPath(appRoot).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) ||
                    !Path.GetFullPath(regData).TrimEnd('\\').Equals(Path.GetFullPath(dataRoot).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Registry64 GIDEON roots do not match canonical Windows roots");
                StartupLog("Registry64 roots verified");
            }
            catch (Exception ex)
            {
                // Do not crash before diagnostics can be emitted. The Windows product
                // deliberately installs only to the canonical roots above. Runtime
                // health checks will still surface Registry64 as DEGRADED if needed.
                StartupLog("Registry64 root verification warning: " + ex.GetType().Name + ": " + ex.Message + ". Using canonical roots.");
            }
        }

        private void StartupLog(string message)
        {
            string line = "[" + DateTimeOffset.Now.ToString("o") + "] [service-host] " + message + Environment.NewLine;
            try
            {
                string root = dataRoot;
                if (String.IsNullOrWhiteSpace(root))
                    root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GIDEON Remote Control");
                string dir = Path.Combine(root, "logs", "services", gideonServiceName);
                Directory.CreateDirectory(dir);
                File.AppendAllText(Path.Combine(dir, "service-host.log"), line);
                return;
            }
            catch { }

            // LocalService profile TEMP remains an emergency fallback. The Python SCM
            // manager explicitly reads this well-known path during diagnostics.
            try
            {
                string fallback = Path.Combine(Path.GetTempPath(), "GIDEONServiceHost-startup-" + gideonServiceName + ".log");
                File.AppendAllText(fallback, line);
            }
            catch { }
        }

        private string LogPath()
        {
            // Each service receives Modify only on its own log directory.
            // P8H-RC4 deliberately avoids one shared writable logs folder.
            string dir = Path.Combine(dataRoot, "logs", "services", gideonServiceName);
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "service-host.log");
        }

        private void Log(string message)
        {
            StartupLog(message);
        }

        private static string Quote(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        private void LoadEnvFile(ProcessStartInfo psi, string path)
        {
            if (!File.Exists(path)) return;
            foreach (string raw in File.ReadAllLines(path))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#") || !line.Contains("=")) continue;
                int pos = line.IndexOf('=');
                string key = line.Substring(0, pos).Trim();
                string value = line.Substring(pos + 1);
                if (key.Length > 0) psi.EnvironmentVariables[key] = value;
            }
        }

        private void ValidatePrivatePythonBinding()
        {
            string cfg = Path.Combine(installRoot, "venv", "pyvenv.cfg");
            string expectedBase = Path.GetFullPath(Path.Combine(installRoot, "runtime", "python-base")).TrimEnd('\\');
            if (!File.Exists(cfg)) throw new FileNotFoundException("GIDEON pyvenv.cfg not found", cfg);
            foreach (string raw in File.ReadAllLines(cfg))
            {
                string line = raw.Trim();
                if (line.Length == 0 || !line.Contains("=")) continue;
                int pos = line.IndexOf('=');
                string key = line.Substring(0, pos).Trim().ToLowerInvariant();
                string value = line.Substring(pos + 1).Trim();
                if (key != "home" && key != "executable" && key != "command") continue;
                if (value.IndexOf("\\Users\\", StringComparison.OrdinalIgnoreCase) >= 0)
                    throw new InvalidOperationException("GIDEON venv is bound to a user-profile Python runtime: " + value);
                if (key == "home" && !Path.GetFullPath(value).TrimEnd('\\').Equals(expectedBase, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("GIDEON venv home is outside the private machine runtime. Expected " + expectedBase + "; got " + value);
            }
        }

        private ProcessStartInfo BuildPythonStartInfo(string script, string args, string envFile)
        {
            string python = Path.Combine(installRoot, "venv", "Scripts", "python.exe");
            if (!File.Exists(python)) throw new FileNotFoundException("GIDEON private Python runtime not found", python);
            ValidatePrivatePythonBinding();

            if (!File.Exists(script)) throw new FileNotFoundException("GIDEON service child script not found", script);
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = python;
            psi.Arguments = args;
            psi.WorkingDirectory = appRoot;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            // Never inherit user-scoped Python redirection into a Windows service.
            psi.EnvironmentVariables.Remove("PYTHONHOME");
            psi.EnvironmentVariables.Remove("PYTHONPATH");
            psi.EnvironmentVariables["PYTHONNOUSERSITE"] = "1";
            psi.EnvironmentVariables["PYTHONUTF8"] = "1";
            psi.EnvironmentVariables["GIDEON_INSTALL_ROOT"] = installRoot;
            psi.EnvironmentVariables["GIDEON_APP_ROOT"] = appRoot;
            psi.EnvironmentVariables["GIDEON_DATA_ROOT"] = dataRoot;
            string privateTemp = Path.Combine(dataRoot, "tmp", gideonServiceName);
            Directory.CreateDirectory(privateTemp);
            psi.EnvironmentVariables["TEMP"] = privateTemp;
            psi.EnvironmentVariables["TMP"] = privateTemp;
            psi.EnvironmentVariables["PYTHONDONTWRITEBYTECODE"] = "1";
            psi.EnvironmentVariables["PYTHONUNBUFFERED"] = "1";
            if (envFile != null) LoadEnvFile(psi, envFile);
            if (gideonServiceName == "GIDEONRemoteControlWebAdmin")
                psi.EnvironmentVariables["GIDEON_WEB_ADMIN_CONFIG"] = Path.Combine(dataRoot, "config", "web_admin.json");
            return psi;
        }

        private ProcessStartInfo BuildChildStartInfo()
        {
            string script;
            string args;
            string envFile = null;

            if (gideonServiceName == "GIDEONRemoteControlGateway")
            {
                script = Path.Combine(appRoot, "gideon_agent_gateway.py");
                args = Quote(script) + " --config " + Quote(Path.Combine(dataRoot, "config", "gateway.json"));
                envFile = Path.Combine(dataRoot, "secrets", "gateway.env");
            }
            else if (gideonServiceName == "GIDEONRemoteControlWebAdmin")
            {
                script = Path.Combine(appRoot, "gideon_web_admin.py");
                args = Quote(script) + " --config " + Quote(Path.Combine(dataRoot, "config", "web_admin.json"));
                envFile = Path.Combine(dataRoot, "secrets", "web.env");
            }
            else if (gideonServiceName == "GIDEONRemoteControlDiagnostics")
            {
                script = Path.Combine(appRoot, "gideon_diagnostics_service.py");
                args = Quote(script) + " --daemon --platform windows --data-root " + Quote(dataRoot);
            }
            else if (gideonServiceName == "GIDEONRemoteControl")
            {
                script = Path.Combine(appRoot, "gideon_coordinator.py");
                args = Quote(script) + " --daemon --data-root " + Quote(dataRoot);
            }
            else
            {
                return null;
            }

            return BuildPythonStartInfo(script, args, envFile);
        }

        private ProcessStartInfo BuildMaintenanceStartInfo()
        {
            if (gideonServiceName == "GIDEONRemoteControlBackup")
            {
                string script = Path.Combine(appRoot, "gideon_backup.py");
                string args = Quote(script) +
                    " --settings " + Quote(Path.Combine(dataRoot, "shared", "runtime_settings.json")) +
                    " --root " + Quote(Path.Combine(dataRoot, "backups", "local")) +
                    " --external-root " + Quote(Path.Combine(dataRoot, "backups", "external")) +
                    " --gateway-db " + Quote(Path.Combine(dataRoot, "gateway", "gateway.sqlite3")) +
                    " --web-db " + Quote(Path.Combine(dataRoot, "web", "security.sqlite3"));
                return BuildPythonStartInfo(script, args, null);
            }
            if (gideonServiceName == "GIDEONRemoteControlUpdater")
            {
                string script = Path.Combine(appRoot, "gideon_product_update.py");
                string args = Quote(script) +
                    " --process-inbox --platform windows" +
                    " --state-root " + Quote(Path.Combine(dataRoot, "updates")) +
                    " --app-root " + Quote(appRoot);
                return BuildPythonStartInfo(script, args, null);
            }
            throw new InvalidOperationException("Not a GIDEON maintenance service: " + gideonServiceName);
        }

        private void RunMaintenance(string reason)
        {
            if (stopping) return;
            if (Interlocked.CompareExchange(ref maintenanceRunning, 1, 0) != 0)
            {
                Log("Maintenance event coalesced while another run is active. reason=" + reason);
                return;
            }
            try
            {
                Process p = new Process();
                p.StartInfo = BuildMaintenanceStartInfo();
                p.EnableRaisingEvents = true;
                p.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) Log("stdout: " + e.Data); };
                p.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) Log("stderr: " + e.Data); };
                p.Exited += delegate(object sender, EventArgs e)
                {
                    int code = -1;
                    try { code = p.ExitCode; } catch { }
                    Log("Maintenance completed rc=" + code + " reason=" + reason);
                    try { p.Dispose(); } catch { }
                    child = null;
                    Interlocked.Exchange(ref maintenanceRunning, 0);
                    if (!stopping && gideonServiceName == "GIDEONRemoteControlUpdater" && code != 0 && debounceTimer != null)
                        debounceTimer.Change(TimeSpan.FromSeconds(30), Timeout.InfiniteTimeSpan);
                };
                child = p;
                Log("Maintenance starting reason=" + reason);
                if (!p.Start()) throw new InvalidOperationException("Maintenance Process.Start returned false");
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
            }
            catch (Exception ex)
            {
                child = null;
                Interlocked.Exchange(ref maintenanceRunning, 0);
                Log("Maintenance start failure: " + ex.GetType().Name + ": " + ex.Message);
                if (!stopping && gideonServiceName == "GIDEONRemoteControlUpdater" && debounceTimer != null)
                    debounceTimer.Change(TimeSpan.FromSeconds(30), Timeout.InfiniteTimeSpan);
            }
        }

        private void ScheduleNextBackup()
        {
            DateTime now = DateTime.Now;
            DateTime next = now.Date.AddHours(3).AddMinutes(17);
            if (next <= now) next = next.AddDays(1);
            TimeSpan due = next - now;
            if (scheduleTimer == null)
                scheduleTimer = new Timer(delegate(object state) { RunMaintenance("daily-backup"); ScheduleNextBackup(); }, null, due, Timeout.InfiniteTimeSpan);
            else
                scheduleTimer.Change(due, Timeout.InfiniteTimeSpan);
            Log("Native backup scheduler armed for " + next.ToString("o") + ". No resident Python worker.");
        }

        private void QueueUpdater(string reason)
        {
            if (stopping || debounceTimer == null) return;
            Log("Updater filesystem event queued. reason=" + reason);
            debounceTimer.Change(TimeSpan.FromMilliseconds(500), Timeout.InfiniteTimeSpan);
        }

        private void StartMaintenanceHost()
        {
            // Validate the private runtime and command paths at SCM startup, without
            // keeping Python resident while no maintenance work exists.
            BuildMaintenanceStartInfo();
            if (gideonServiceName == "GIDEONRemoteControlBackup")
            {
                if (DateTime.Now.TimeOfDay >= new TimeSpan(3, 17, 0))
                    RunMaintenance("startup-backup-catchup");
                ScheduleNextBackup();
                return;
            }

            string inbox = Path.Combine(dataRoot, "updates", "inbox");
            Directory.CreateDirectory(inbox);
            debounceTimer = new Timer(delegate(object state) { RunMaintenance("update-inbox"); }, null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            updateWatcher = new FileSystemWatcher(inbox, "*.ready");
            updateWatcher.IncludeSubdirectories = false;
            updateWatcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime;
            updateWatcher.Created += delegate(object sender, FileSystemEventArgs e) { QueueUpdater("created:" + e.Name); };
            updateWatcher.Changed += delegate(object sender, FileSystemEventArgs e) { QueueUpdater("changed:" + e.Name); };
            updateWatcher.Renamed += delegate(object sender, RenamedEventArgs e) { QueueUpdater("renamed:" + e.Name); };
            updateWatcher.Error += delegate(object sender, ErrorEventArgs e) { Log("Updater watcher error: " + e.GetException().Message); QueueUpdater("watcher-recovery"); };
            updateWatcher.EnableRaisingEvents = true;
            Log("Native update watcher armed for " + inbox + ". No 3-second Python polling.");
            QueueUpdater("startup-recovery");
        }

        protected override void OnStart(string[] args)
        {
            stopping = false;
            startupComplete = false;
            InitializeRoots();
            Log("SCM start requested. InstallRoot=" + installRoot + " AppRoot=" + appRoot + " DataRoot=" + dataRoot);

            if (gideonServiceName == "GIDEONRemoteControlBackup" || gideonServiceName == "GIDEONRemoteControlUpdater")
            {
                try
                {
                    StartMaintenanceHost();
                    startupComplete = true;
                    Log("Resource-aware maintenance host started without resident Python child.");
                    return;
                }
                catch (Exception ex)
                {
                    Log("START FAILURE: " + ex.GetType().Name + ": " + ex.Message);
                    throw;
                }
            }

            ProcessStartInfo psi = null;
            try
            {
                // Keep failures that happen while resolving the private Python
                // runtime/configuration inside the service log.  Previously this
                // call happened outside the guarded startup block, so a service
                // could terminate after only "SCM start requested" and leave the
                // installer with no actionable reason for a failed health check.
                psi = BuildChildStartInfo();
            }
            catch (Exception ex)
            {
                Log("START FAILURE (build child): " + ex.GetType().Name + ": " + ex.Message);
                throw;
            }
            child = new Process();
            child.StartInfo = psi;
            child.EnableRaisingEvents = true;
            child.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) Log("stdout: " + e.Data); };
            child.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) Log("stderr: " + e.Data); };
            child.Exited += delegate(object sender, EventArgs e)
            {
                if (stopping) return;
                int code = -1;
                try { code = child.ExitCode; } catch { }
                if (!startupComplete)
                {
                    Log("Child exited during startup rc=" + code + ". OnStart will surface the failure with captured stdout/stderr.");
                    return;
                }
                Log("Child exited unexpectedly rc=" + code + ". Terminating service host so SCM recovery can act.");
                Environment.Exit(code == 0 ? 42 : code);
            };

            try
            {
                if (!child.Start()) throw new InvalidOperationException("Process.Start returned false");
                child.BeginOutputReadLine();
                child.BeginErrorReadLine();
                Thread.Sleep(1500);
                if (child.HasExited)
                {
                    try { child.WaitForExit(); } catch { }
                    Thread.Sleep(120); // allow async stdout/stderr handlers to flush
                    throw new InvalidOperationException("GIDEON child exited during service startup rc=" + child.ExitCode);
                }
                startupComplete = true;
                Log("Child started pid=" + child.Id);
            }
            catch (Exception ex)
            {
                Log("START FAILURE: " + ex.GetType().Name + ": " + ex.Message);
                throw;
            }
        }

        protected override void OnStop()
        {
            stopping = true;
            Log("SCM stop requested");
            DisposeMaintenanceHost();
            StopChild();
            Log("Service stopped");
        }

        protected override void OnShutdown()
        {
            stopping = true;
            Log("System shutdown requested");
            DisposeMaintenanceHost();
            StopChild();
        }

        private void DisposeMaintenanceHost()
        {
            FileSystemWatcher watcher = updateWatcher;
            updateWatcher = null;
            if (watcher != null) { try { watcher.EnableRaisingEvents = false; watcher.Dispose(); } catch { } }
            Timer debounce = debounceTimer;
            debounceTimer = null;
            if (debounce != null) { try { debounce.Dispose(); } catch { } }
            Timer scheduled = scheduleTimer;
            scheduleTimer = null;
            if (scheduled != null) { try { scheduled.Dispose(); } catch { } }
        }

        private void StopChild()
        {
            Process p = child;
            if (p == null) return;
            try
            {
                if (!p.HasExited)
                {
                    p.Kill();
                    if (!p.WaitForExit(12000)) Log("Child did not exit within 12 seconds after Kill");
                }
            }
            catch (Exception ex)
            {
                Log("Child stop error: " + ex.GetType().Name + ": " + ex.Message);
            }
        }

        internal static int Main(string[] args)
        {
            try
            {
                if (args == null || args.Length != 1 || !IsAllowedService(args[0]))
                    return 2;
                ServiceBase.Run(new GideonService(args[0]));
                return 0;
            }
            catch (Exception ex)
            {
                try
                {
                    string service = (args != null && args.Length == 1) ? args[0] : "unknown";
                    string fallback = Path.Combine(Path.GetTempPath(), "GIDEONServiceHost-startup-" + service + ".log");
                    File.AppendAllText(fallback, DateTimeOffset.Now.ToString("o") + " " + ex + Environment.NewLine);
                }
                catch { }
                return 3;
            }
        }
    }
}
