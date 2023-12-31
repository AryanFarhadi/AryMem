using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace AryMemory
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
            mHandle = OpenProcess(PROCESS_ALL_ACCESS, false, process[0].Id);
        }
        #endregion
        #region Varible
        private Process mProcess;
        private IntPtr mHandle;
        #endregion
        #region Methods
        /// <summary>
        /// Read diffrents type of value except byte[], string to process memory
        /// Use : ReadMemory(ulong address, int sizeOfBytes) for byte[]
        /// Use : ReadMemory(ulong address, int lengthOfString, StringType stringType) for string
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="address"></param>
        /// <returns>Value</returns>
        /// <exception cref="Exception"></exception>
        public T ReadMemory<T>(ulong address)
        {
            int sizeOfT = Marshal.SizeOf(typeof(T));
            var buffer = new byte[sizeOfT];
            int bytesRead = 0;
            if (ReadProcessMemory(mHandle, address, buffer, sizeOfT, ref bytesRead))
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

        /// <summary>
        /// Read byte[] from proces memory
        /// </summary>
        /// <param name="address"></param>
        /// <param name="sizeOfBytes"></param>
        /// <returns>Value</returns>
        /// <exception cref="Exception"></exception>
        public byte[] ReadMemory(ulong address, int sizeOfBytes)
        {
            var buffer = new byte[sizeOfBytes];
            int bytesRead = 0;
            if (ReadProcessMemory(mHandle, address, buffer, sizeOfBytes, ref bytesRead))
                if (bytesRead == sizeOfBytes)
                    return buffer;
                else
                    throw new Exception("Incomplete read of memory.");
            else
                throw new Exception("Could not read memory.");
        }

        /// <summary>
        /// Read string from proces memory
        /// </summary>
        /// <param name="address"></param>
        /// <param name="sizeOfString"></param>
        /// <param name="stringType"></param>
        /// <returns>Value</returns>
        /// <exception cref="Exception"></exception>
        public string ReadMemory(ulong address, int lengthOfString, StringType stringType)
        {
            int sizeOfString = lengthOfString * 2;
            var buffer = new byte[sizeOfString];
            int bytesRead = 0;
            if (ReadProcessMemory(mHandle, address, buffer, sizeOfString, ref bytesRead))
                if (bytesRead == sizeOfString)
                    switch (stringType)
                    {
                        case StringType.UTF8:
                            return Encoding.UTF8.GetString(buffer);
                        case StringType.UTF32:
                            return Encoding.UTF32.GetString(buffer);
                        case StringType.ASCII:
                            return Encoding.ASCII.GetString(buffer);
                        case StringType.Uunicode:
                            return Encoding.Unicode.GetString(buffer);
                        default:
                            return Encoding.UTF8.GetString(buffer);
                    }
                else
                    throw new Exception("Incomplete read of memory.");
            else
                throw new Exception("Could not read memory.");
        }

        /// <summary>
        /// Write diffrents type of value except byte[], string to process memory
        /// Use : WriteMemory(ulong address, byte[] value) for byte[]
        /// Use : WriteMemory(ulong address, string value, StringType stringType) for string
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="address"></param>
        /// <param name="value"></param>
        /// <returns>Was write to process memory successful</returns>
        /// <exception cref="Exception"></exception>
        public bool WriteMemory<T>(ulong address, T value)
        {
            int sizeOfT = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[sizeOfT];
            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                Marshal.StructureToPtr(value, handle.AddrOfPinnedObject(), false);
                int bytesWritten = 0;
                bool result = WriteProcessMemory(mHandle, address, buffer, buffer.Length, ref bytesWritten);
                if (!result && bytesWritten != sizeOfT)
                    throw new Exception("Failed to write memory.");

                return result;
            }
            finally
            {
                handle.Free();
            }
        }
        /// <summary>
        /// Write byte[] to process memory
        /// </summary>
        /// <param name="address"></param>
        /// <param name="value"></param>
        /// <returns>Was write to process memory successful</returns>
        /// <exception cref="Exception"></exception>
        public bool WriteMemory(ulong address, byte[] value)
        {
            int bytesWritten = 0;
            bool result = WriteProcessMemory(mHandle, address, value, value.Length, ref bytesWritten);
            if (!result && bytesWritten != value.Length)
                throw new Exception("Failed to write memory.");

            return result;
        }
        /// <summary>
        /// Write 00 byte to process memory
        /// </summary>
        /// <param name="address"></param>
        /// <param name="sizeOfBytes"></param>
        /// <returns>Was write to process memory successful</returns>
        /// <exception cref="Exception"></exception>
        public bool WriteMemoryNull(ulong address, int sizeOfBytes)
        {
            byte[] buffer = new byte[sizeOfBytes];
            int bytesWritten = 0;
            bool result = WriteProcessMemory(mHandle, address, buffer, buffer.Length, ref bytesWritten);
            if (!result && bytesWritten != buffer.Length)
                throw new Exception("Failed to write memory.");

            return result;
        }

        /// <summary>
        /// Write string to process memory
        /// </summary>
        /// <param name="address"></param>
        /// <param name="value"></param>
        /// <param name="stringType"></param>
        /// <returns>Was write to process memory successful</returns>
        /// <exception cref="Exception"></exception>
        public bool WriteMemory(ulong address, string value, StringType stringType)
        {
            byte[] buffer;
            switch (stringType)
            {
                case StringType.UTF8:
                    buffer = Encoding.UTF8.GetBytes(value);
                    break;
                case StringType.UTF32:
                    buffer = Encoding.UTF32.GetBytes(value);
                    break;
                case StringType.ASCII:
                    buffer = Encoding.ASCII.GetBytes(value);
                    break;
                case StringType.Uunicode:
                    buffer = Encoding.Unicode.GetBytes(value);
                    break;
                default:
                    buffer = Encoding.UTF8.GetBytes(value);
                    break;
            }
            int bytesWritten = 0;
            bool result = WriteProcessMemory(mHandle, address, buffer, buffer.Length, ref bytesWritten);
            if (!result && bytesWritten != buffer.Length)
                throw new Exception("Failed to write memory.");

            return result;
        }

        /// <summary>
        /// Get process module baseaddress and memory size by name
        /// </summary>
        /// <param name="moduleName"></param>
        /// <returns>Process module info</returns>
        public Module GetModule(string moduleName)
        {
            ProcessModule pmodule = mProcess.Modules.Cast<ProcessModule>().FirstOrDefault(m => string.Equals(m.ModuleName, moduleName, StringComparison.OrdinalIgnoreCase));
            if (pmodule != null)
            {
                Module module = new Module() { BaseAddress = (ulong)pmodule.BaseAddress, ModuleSize = pmodule.ModuleMemorySize };
                return module;
            }
            else
                return new Module();
        }

        /// <summary>
        /// Calculate pointer to an address by offset
        /// </summary>
        /// <param name="address"></param>
        /// <param name="offsets"></param>
        /// <returns>Calcualted pointer</returns>
        public ulong ReadPointer(ulong address, params ulong[] offsets)
        {
            ulong pointer = address;
            foreach (var offset in offsets)
            {
                pointer = ReadMemory<ulong>(pointer) + offset;
            }
            return pointer;
        }


        /// <summary>
        /// Calculate pointer to an address by offset
        /// </summary>
        /// <param name="address"></param>
        /// <param name="offsets"></param>
        /// <returns>Calculated pointer</returns>
        public ulong ReadPointer(ulong address, params int[] offsets)
        {
            ulong pointer = address;
            foreach (var offset in offsets)
            {
                pointer = ReadMemory<ulong>(pointer) + (ulong)offset;
            }
            return pointer;
        }

        /// <summary>
        /// Set an instruction of target process to nop=ll
        /// </summary>
        /// <param name="address"></param>
        /// <param name="length"></param>
        /// <returns>Was instruction replaace succussful</returns>
        public bool Nop(ulong address, int length)
        {
            byte[] array = new byte[length];
            for (int i = 0; i < length; i++)
            {
                array[i] = 0x90;
            }

            return WriteMemory(address, array);
        }

        /// <summary>
        /// Get target process
        /// </summary>
        /// <returns>target process</returns>
        public Process GetProcess()
        {
            return mProcess;
        }

        private byte[] ConvertStringToBytes(string byteString)
        {
            string[] elements = byteString.Split(' ');
            byte[] convertedBytes = new byte[elements.Length];
            for (int i = 0; i < elements.Length; i++)
                if (elements[i].Contains("?"))
                    convertedBytes[i] = 0x0;
                else
                    convertedBytes[i] = Convert.ToByte(elements[i], 16);
            return convertedBytes;
        }

        /// <summary>
        /// Search for addresses by signature in target process memory
        /// </summary>
        /// <param name="signature">string of target signature : "?? 12 A8 FF ??"</param>
        /// <returns>List of found addresses</returns>
        public List<ulong> ScanAoB(string signature)
        {
            List<ulong> results = new List<ulong>();

            ulong currentAddress = 0;
            int bytesRead = 0;

            byte[] signatureByteArray = ConvertStringToBytes(signature);

            while (VirtualQueryEx(mHandle, currentAddress, out MEMORY_BASIC_INFORMATION mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))))
            {
                if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect != PAGE_READONLY))
                {
                    byte[] buffer = new byte[(int)mbi.RegionSize];
                    if (ReadProcessMemory(mHandle, (ulong)mbi.BaseAddress, buffer, buffer.Length, ref bytesRead))
                        for (int i = 0; i < bytesRead - signatureByteArray.Length; i++)
                        {
                            bool match = true;
                            for (int j = 0; j < signatureByteArray.Length; j++)
                                if (signatureByteArray[j] != 0 && buffer[i + j] != signatureByteArray[j])
                                {
                                    match = false;
                                    break;
                                }
                            if (match)
                                results.Add(mbi.BaseAddress + (ulong)i);
                        }
                }
                currentAddress = currentAddress + mbi.RegionSize;
            }
            return results;
        }
        #endregion
        #region Pinvokes
        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const uint MEM_COMMIT = 0x1000;
        private const uint PAGE_READONLY = 0x02;
        private const uint PAGE_READWRITE = 0x04;

        public struct Module
        {
            public ulong BaseAddress;
            public int ModuleSize;
        }

        public enum StringType
        {
            UTF8,
            UTF32,
            ASCII,
            Uunicode
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public ulong BaseAddress;
            public ulong AllocationBase;
            public uint AllicationProtect;
            public ulong RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualQueryEx(IntPtr hProcess, ulong lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);
        #endregion
    }
}
