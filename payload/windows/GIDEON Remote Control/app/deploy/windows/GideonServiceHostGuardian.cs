
using System;
using System.IO;
using System.Threading;

namespace GIDEON.RemoteControl.WindowsServiceHost
{
    internal static class GideonServiceHostGuardian
    {
        private static Mutex _mutex;

        public static bool Acquire(string serviceName)
        {
            bool created;

            _mutex = new Mutex(
                true,
                "Global\\GIDEON_" + serviceName + "_MASTER",
                out created);

            return created;
        }

        public static void Register(string serviceName)
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "GIDEON Remote Control",
                "runtime",
                "identity");

            Directory.CreateDirectory(dir);

            File.WriteAllText(
                Path.Combine(dir, serviceName + ".json"),
                "{\n" +
                "\"service\":\"" + serviceName + "\",\n" +
                "\"pid\":\"" + Environment.ProcessId + "\",\n" +
                "\"role\":\"MASTER\"\n" +
                "}");
        }

        public static void Release()
        {
            try
            {
                _mutex?.ReleaseMutex();
                _mutex?.Dispose();
            }
            catch
            {
            }
        }
    }
}
