using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

[assembly: AssemblyTitle("Gideon Rx Agent Installer")]
[assembly: AssemblyProduct("Gideon Rx Agent")]
[assembly: AssemblyCompany("Gideon Rx Project")]
[assembly: AssemblyDescription("Verified cross-platform SFX bootstrap for GIDEON Agent")]
[assembly: AssemblyVersion("2.4.56.0")]
[assembly: AssemblyFileVersion("2.4.56.0")]

namespace GIDEON.AgentSfx
{
    internal static class Program
    {
        private const string MagicText = "GIDEON_AGENT_SFX_TRAILER_V1";
        private const int HashLength = 64;

        [STAThread]
        private static int Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            Form progress = new Form();
            progress.Text = "Gideon Rx Agent · Preparando instalación";
            progress.StartPosition = FormStartPosition.CenterScreen;
            progress.FormBorderStyle = FormBorderStyle.FixedDialog;
            progress.MaximizeBox = false;
            progress.MinimizeBox = false;
            progress.ControlBox = false;
            progress.ClientSize = new Size(520, 118);

            Label title = new Label();
            title.Text = "Gideon Rx Agent · Instalación / reparación";
            title.Font = new Font("Segoe UI", 11.0f, FontStyle.Bold);
            title.AutoSize = true;
            title.Location = new Point(22, 18);
            progress.Controls.Add(title);

            Label detail = new Label();
            detail.Text = "Validando y extrayendo el runtime seguro. Esto puede tardar unos segundos.";
            detail.AutoSize = false;
            detail.Size = new Size(470, 36);
            detail.Location = new Point(22, 47);
            progress.Controls.Add(detail);

            ProgressBar bar = new ProgressBar();
            bar.Style = ProgressBarStyle.Marquee;
            bar.MarqueeAnimationSpeed = 22;
            bar.Location = new Point(22, 86);
            bar.Size = new Size(470, 14);
            progress.Controls.Add(bar);
            progress.Show();
            Application.DoEvents();

            string root = Path.Combine(Path.GetTempPath(), "GIDEONAgentSetup-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(root);
                string payload = Path.Combine(root, "payload.zip");
                string bootstrap = Path.Combine(root, "bootstrap.ps1");

                detail.Text = "Extrayendo archivos del instalador…";
                Application.DoEvents();
                string expectedPayload;
                string expectedBootstrap;
                ExtractVerifiedOverlay(payload, bootstrap, out expectedPayload, out expectedBootstrap);

                detail.Text = "Validando integridad…";
                Application.DoEvents();
                if (!String.Equals(Sha256(payload), expectedPayload, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Payload SHA-256 mismatch");
                if (!String.Equals(Sha256(bootstrap), expectedBootstrap, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Bootstrap SHA-256 mismatch");

                string systemRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
                string powershell = Path.Combine(systemRoot, @"System32\WindowsPowerShell\v1.0\powershell.exe");
                if (!File.Exists(powershell)) powershell = "powershell.exe";

                detail.Text = "Abriendo identificación del Agent…";
                Application.DoEvents();
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = powershell;
                psi.Arguments = "-NoLogo -NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File \"" + bootstrap + "\"";
                psi.WorkingDirectory = root;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                Process child = Process.Start(psi);
                if (child == null) throw new InvalidOperationException("No se pudo iniciar el bootstrap PowerShell");

                System.Threading.Thread.Sleep(250);
                detail.Text = "Configurando, reparando y validando el Agent…";
                Application.DoEvents();
                while (!child.HasExited)
                {
                    Application.DoEvents();
                    System.Threading.Thread.Sleep(120);
                }

                if (child.ExitCode == 0)
                {
                    bar.Style = ProgressBarStyle.Continuous;
                    bar.Value = 100;
                    detail.Text = "Instalación validada correctamente.";
                    Application.DoEvents();
                    System.Threading.Thread.Sleep(450);
                    return 0;
                }

                bar.Style = ProgressBarStyle.Continuous;
                bar.Value = 100;
                detail.Text = "La instalación terminó con errores. Se mostrará el diagnóstico.";
                Application.DoEvents();
                string diag = FindLatestDiagnostic();
                string message = "Gideon Rx Agent no pudo completar la instalación." + Environment.NewLine
                    + Environment.NewLine + "Código: " + child.ExitCode.ToString();
                if (!String.IsNullOrWhiteSpace(diag))
                    message += Environment.NewLine + Environment.NewLine + "Diagnóstico: " + diag;
                else
                    message += Environment.NewLine + Environment.NewLine + "Revise "
                        + Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GIDEONAgent", "bootstrap-install.log");
                MessageBox.Show(message, "Gideon Rx Agent · Error de instalación", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return child.ExitCode;
            }
            catch (Exception ex)
            {
                string diag = WriteWrapperDiagnostic(ex);
                MessageBox.Show(
                    "El instalador falló antes de completar el Agent." + Environment.NewLine + Environment.NewLine
                    + ex.Message + Environment.NewLine + Environment.NewLine + "Diagnóstico: " + diag,
                    "Gideon Rx Agent · Error de bootstrap",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                return 93;
            }
            finally
            {
                try { progress.Close(); progress.Dispose(); } catch { }
                try { Directory.Delete(root, true); } catch { }
            }
        }

        private static void ExtractVerifiedOverlay(
            string payloadTarget,
            string bootstrapTarget,
            out string payloadSha256,
            out string bootstrapSha256)
        {
            byte[] magic = Encoding.ASCII.GetBytes(MagicText);
            int trailerSize = 8 + 8 + HashLength + HashLength + magic.Length;
            string executable = Assembly.GetExecutingAssembly().Location;

            using (FileStream input = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                long trailerEnd = FindTrailerEnd(input, magic);
                long trailerStart = trailerEnd - trailerSize;
                if (trailerStart <= 0) throw new InvalidDataException("SFX trailer missing");
                input.Seek(trailerStart, SeekOrigin.Begin);
                byte[] trailer = ReadExact(input, trailerSize);

                ulong rawPayloadLength = BitConverter.ToUInt64(trailer, 0);
                ulong rawBootstrapLength = BitConverter.ToUInt64(trailer, 8);
                long payloadLength = checked((long)rawPayloadLength);
                long bootstrapLength = checked((long)rawBootstrapLength);
                if (payloadLength <= 0 || bootstrapLength <= 0)
                    throw new InvalidDataException("SFX overlay lengths are invalid");

                payloadSha256 = Encoding.ASCII.GetString(trailer, 16, HashLength);
                bootstrapSha256 = Encoding.ASCII.GetString(trailer, 16 + HashLength, HashLength);
                string observedMagic = Encoding.ASCII.GetString(trailer, 16 + HashLength + HashLength, magic.Length);
                if (!String.Equals(observedMagic, MagicText, StringComparison.Ordinal))
                    throw new InvalidDataException("SFX trailer signature mismatch");

                long overlayStart = checked(trailerStart - payloadLength - bootstrapLength);
                if (overlayStart < 1024) throw new InvalidDataException("SFX overlay boundary is invalid");
                input.Seek(overlayStart, SeekOrigin.Begin);
                CopySegment(input, payloadTarget, payloadLength);
                CopySegment(input, bootstrapTarget, bootstrapLength);
            }
        }

        private static long FindTrailerEnd(FileStream input, byte[] magic)
        {
            const int maxScanBytes = 1024 * 1024;
            int scanLength = (int)Math.Min(input.Length, maxScanBytes);
            if (scanLength < magic.Length)
                throw new InvalidDataException("SFX trailer missing");

            long scanStart = input.Length - scanLength;
            input.Seek(scanStart, SeekOrigin.Begin);
            byte[] tail = ReadExact(input, scanLength);
            for (int index = tail.Length - magic.Length; index >= 0; index--)
            {
                bool matches = true;
                for (int offset = 0; offset < magic.Length; offset++)
                {
                    if (tail[index + offset] != magic[offset])
                    {
                        matches = false;
                        break;
                    }
                }
                if (matches) return scanStart + index + magic.Length;
            }

            throw new InvalidDataException("SFX trailer signature mismatch");
        }

        private static byte[] ReadExact(Stream input, int count)
        {
            byte[] result = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int read = input.Read(result, offset, count - offset);
                if (read <= 0) throw new EndOfStreamException("Unexpected end of SFX trailer");
                offset += read;
            }
            return result;
        }

        private static void CopySegment(Stream input, string target, long length)
        {
            byte[] buffer = new byte[1024 * 1024];
            long remaining = length;
            using (FileStream output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                while (remaining > 0)
                {
                    int requested = (int)Math.Min((long)buffer.Length, remaining);
                    int read = input.Read(buffer, 0, requested);
                    if (read <= 0) throw new EndOfStreamException("Unexpected end of SFX overlay");
                    output.Write(buffer, 0, read);
                    remaining -= read;
                }
                output.Flush();
            }
        }

        private static string FindLatestDiagnostic()
        {
            try
            {
                string data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GIDEONAgent");
                string diagDir = Path.Combine(data, "diagnostics");
                if (Directory.Exists(diagDir))
                {
                    FileInfo[] files = new DirectoryInfo(diagDir).GetFiles("*.txt");
                    Array.Sort(files, delegate(FileInfo a, FileInfo b) { return b.LastWriteTimeUtc.CompareTo(a.LastWriteTimeUtc); });
                    if (files.Length > 0) return files[0].FullName;
                }
                string log = Path.Combine(data, "bootstrap-install.log");
                if (File.Exists(log)) return log;
            }
            catch { }
            return "";
        }

        private static string WriteWrapperDiagnostic(Exception ex)
        {
            try
            {
                string data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GIDEONAgent");
                string diagDir = Path.Combine(data, "diagnostics");
                Directory.CreateDirectory(diagDir);
                string path = Path.Combine(diagDir, "wrapper-error-" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".txt");
                File.WriteAllText(
                    path,
                    "Gideon Rx Agent - Wrapper Diagnostic" + Environment.NewLine
                    + "Timestamp: " + DateTime.Now.ToString("o") + Environment.NewLine
                    + "Reason: " + ex.ToString(),
                    Encoding.UTF8
                );
                return path;
            }
            catch { return @"C:\ProgramData\GIDEONAgent"; }
        }

        private static string Sha256(string path)
        {
            using (SHA256 sha = SHA256.Create())
            using (FileStream stream = File.OpenRead(path))
            {
                byte[] hash = sha.ComputeHash(stream);
                StringBuilder text = new StringBuilder(hash.Length * 2);
                foreach (byte value in hash) text.Append(value.ToString("x2"));
                return text.ToString();
            }
        }
    }
}

