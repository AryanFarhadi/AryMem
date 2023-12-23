using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AryMem
{
	public class Ary
	{
        #region Constructor
        public Ary(string processName)
        {
            Process[] process = Process.GetProcessesByName(processName);
            if (process.Length == 0)
                throw new Exception("Process not found");
            mProcess = process[0];
        }
        #endregion
        #region Global
        public Process mProcess { get; set; }
        #endregion
        #region Methods
        public T ReadMemory<T>(ulong address) where T : struct
        {
            int sizeOfT = Marshal.SizeOf(typeof(T));
            var buffer = new byte[sizeOfT];
            int bytesRead = 0;
            if (ReadProcessMemory(mProcess.Handle, address, buffer, sizeOfT, ref bytesRead))
                if (bytesRead == sizeOfT)
                {
                    GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                    try
                    {
                        return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
                    }
                    finally
                    {
                        handle.Free();
                    }
                }
                else
                    throw new Exception("Incomplete read of memory.");
            else
                throw new Exception("Could not read memory.");
        }

        public byte[] ReadMemory(ulong address, int sizeOf)
        {
            var buffer = new byte[sizeOf];
            int bytesRead = 0;
            if (ReadProcessMemory(mProcess.Handle, address, buffer, sizeOf, ref bytesRead))
                if (bytesRead == sizeOf)
                    return buffer;
                else
                    throw new Exception("Incomplete read of memory.");
            else
                throw new Exception("Could not read memory.");
        }

        public bool WriteMemory<T>(ulong address, T value) where T : struct
        {
            int sizeOfT = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[sizeOfT];
            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                Marshal.StructureToPtr(value, handle.AddrOfPinnedObject(), false);
                int bytesWritten = 0;
                bool result = WriteProcessMemory(mProcess.Handle, address, buffer, buffer.Length, ref bytesWritten);
                if (!result && bytesWritten != sizeOfT)
                    throw new Exception("Failed to write memory.");

                return result;
            }
            finally
            {
                handle.Free();
            }
        }

        public bool WriteMemory(ulong address, byte[] value)
        {
            int bytesWritten = 0;
            bool result = WriteProcessMemory(mProcess.Handle, address, value, value.Length, ref bytesWritten);
            if (!result && bytesWritten != value.Length)
                throw new Exception("Failed to write memory.");

            return result;
        }

        public ulong GetModuleAddress(string moduleName)
        {
            ProcessModule module = mProcess.Modules.Cast<ProcessModule>().FirstOrDefault(m => string.Equals(m.ModuleName, moduleName, StringComparison.OrdinalIgnoreCase));
            if (module != null)
                return (ulong)module.BaseAddress;
            else
                return 0;
        }

        public ulong ReadPointer(ulong address, params ulong[] offsets)
        {
            ulong pointer = address;
            foreach (var offset in offsets)
            {
                pointer = ReadMemory<ulong>(pointer) + offset;
            }
            return pointer;
        }

        public ulong ReadPointer(ulong address, params int[] offsets)
        {
            ulong pointer = address;
            foreach (var offset in offsets)
            {
                pointer = ReadMemory<ulong>(pointer) + (ulong)offset;
            }
            return pointer;
        }

        public bool Nop(ulong address, int length)
        {
            byte[] array = new byte[length];
            for (int i = 0; i < length; i++)
            {
                array[i] = 0x90;
            }

            return WriteMemory(address, array);
        }
        #endregion
        #region Pinvokes
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);
        #endregion
    }
}
