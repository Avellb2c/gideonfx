
using System;
using System.IO;
using System.Threading;

namespace GIDEON.RemoteControl.WindowsServiceHost
{
    internal static class GideonMasterGuardian
    {
        private static Mutex mutex;

        public static bool Acquire(string serviceName)
        {
            bool created;

            mutex = new Mutex(
                true,
                @"Global\GIDEON_" + serviceName + "_MASTER",
                out created);

            return created;
        }

        public static void Release()
        {
            try
            {
                mutex?.ReleaseMutex();
                mutex?.Dispose();
            }
            catch { }
        }

        public static void WriteIdentity(string serviceName)
        {
            var path = @"C:\ProgramData\GIDEON Remote Control\runtime";
            Directory.CreateDirectory(path);

            File.WriteAllText(
                Path.Combine(path,"servicehost-master.json"),
                "{\n" +
                "\"service\":\""+serviceName+"\",\n" +
                "\"pid\":\""+Environment.ProcessId+"\",\n" +
                "\"role\":\"MASTER\"\n" +
                "}");
        }
    }
}
