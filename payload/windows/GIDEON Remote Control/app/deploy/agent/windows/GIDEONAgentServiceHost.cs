using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Threading;
using System.Reflection;

[assembly: AssemblyTitle("Gideon Rx Agent Service Host")]
[assembly: AssemblyDescription("Windows SCM host for Gideon Rx Agent")]
[assembly: AssemblyCompany("Gideon Rx Project")]
[assembly: AssemblyProduct("Gideon Rx Agent")]
[assembly: AssemblyVersion("2.4.56.0")]
[assembly: AssemblyFileVersion("2.4.56.0")]

namespace GIDEON.RemoteControl.AgentServiceHost
{
    internal sealed class GideonAgentService : ServiceBase
    {
        private const string GideonServiceName = "GIDEONAgent";
        private Process child;
        private volatile bool stopping;
        private volatile bool startupComplete;
        private string installRoot;
        private string dataRoot;
        private string logPath;

        internal GideonAgentService()
        {
            ServiceName = GideonServiceName;
            CanStop = true;
            CanShutdown = true;
            AutoLog = false;
        }

        private void InitializeRoots()
        {
            installRoot = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            dataRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "GIDEONAgent"
            );
            Directory.CreateDirectory(dataRoot);
            logPath = Path.Combine(dataRoot, "service-host.log");
            Log("Roots: install=" + installRoot + " data=" + dataRoot);
        }

        private void Log(string message)
        {
            try
            {
                if (String.IsNullOrEmpty(logPath))
                {
                    string fallback = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "GIDEONAgent"
                    );
                    Directory.CreateDirectory(fallback);
                    logPath = Path.Combine(fallback, "service-host.log");
                }
                File.AppendAllText(
                    logPath,
                    DateTimeOffset.Now.ToString("o") + " [service-host] " + message + Environment.NewLine
                );
            }
            catch { }
        }

        private ProcessStartInfo BuildChild()
        {
            string python = Path.Combine(installRoot, "runtime", "python", "python.exe");
            string script = Path.Combine(installRoot, "gideon_agent.py");
            string config = Path.Combine(installRoot, "agent.json");

            if (!File.Exists(python)) throw new FileNotFoundException("Private Python not found", python);
            if (!File.Exists(script)) throw new FileNotFoundException("gideon_agent.py not found", script);
            if (!File.Exists(config)) throw new FileNotFoundException("agent.json not found", config);

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = python;
            psi.Arguments = Quote(script) + " --config " + Quote(config);
            psi.WorkingDirectory = installRoot;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;

            psi.EnvironmentVariables.Remove("PYTHONHOME");
            psi.EnvironmentVariables.Remove("PYTHONPATH");
            psi.EnvironmentVariables["PYTHONNOUSERSITE"] = "1";
            psi.EnvironmentVariables["PYTHONUTF8"] = "1";
            psi.EnvironmentVariables["PYTHONDONTWRITEBYTECODE"] = "1";
            psi.EnvironmentVariables["PYTHONUNBUFFERED"] = "1";

            string privateTemp = Path.Combine(dataRoot, "tmp");
            Directory.CreateDirectory(privateTemp);
            psi.EnvironmentVariables["TEMP"] = privateTemp;
            psi.EnvironmentVariables["TMP"] = privateTemp;
            return psi;
        }

        private static string Quote(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        protected override void OnStart(string[] args)
        {
            stopping = false;
            startupComplete = false;
            InitializeRoots();
            Log("SCM start requested.");

            ProcessStartInfo psi = BuildChild();
            child = new Process();
            child.StartInfo = psi;
            child.EnableRaisingEvents = true;
            child.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e)
            {
                if (!String.IsNullOrEmpty(e.Data)) Log("stdout: " + e.Data);
            };
            child.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e)
            {
                if (!String.IsNullOrEmpty(e.Data)) Log("stderr: " + e.Data);
            };
            child.Exited += delegate(object sender, EventArgs e)
            {
                if (stopping) return;
                int code = -1;
                try { code = child.ExitCode; } catch { }
                if (!startupComplete)
                {
                    Log("Child exited during service startup rc=" + code);
                    return;
                }
                Log("Child exited unexpectedly rc=" + code + "; terminating host so SCM recovery can restart service.");
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
                    Thread.Sleep(100);
                    throw new InvalidOperationException("Agent child exited during startup rc=" + child.ExitCode);
                }

                startupComplete = true;
                Log("Agent child started pid=" + child.Id);
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
            Log("SCM stop requested.");
            StopChild();
            Log("Service stopped.");
        }

        protected override void OnShutdown()
        {
            stopping = true;
            Log("System shutdown requested.");
            StopChild();
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
                    if (!p.WaitForExit(12000))
                        Log("Child did not exit within 12 seconds.");
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
                ServiceBase.Run(new GideonAgentService());
                return 0;
            }
            catch (Exception ex)
            {
                try
                {
                    string root = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "GIDEONAgent"
                    );
                    Directory.CreateDirectory(root);
                    File.AppendAllText(
                        Path.Combine(root, "service-host-startup.log"),
                        DateTimeOffset.Now.ToString("o") + " " + ex + Environment.NewLine
                    );
                }
                catch { }
                return 3;
            }
        }
    }
}
