using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace AryMem
{
    /// <summary>
    /// Provides functionality to manipulate another process's memory, including:
    /// - Reading/writing memory (primitive types, arrays, strings)
    /// - Architecture-aware pointer reading
    /// - Named offsets for pointer resolution
    /// - Process/thread freezing, input simulation (keyboard/mouse)
    /// - DLL injection
    /// - AoB scanning (with wildcards, module-limited scans)
    /// - Code cave allocation and hooking
    /// - Memory allocation, protection changing, and freeing
    /// - Logging callback for errors and diagnostic methods (e.g., DumpMemory)
    /// - Module enumeration
    /// - Thread enumeration (stub for GetThreadContext)
    /// </summary>
    public sealed class Ary : IDisposable
    {
        private readonly Process _process;
        private readonly IntPtr _processHandle;
        private bool _disposed;
        private bool? _is64BitProcess;
        private int _pointerSizeOverride = 0;

        // Named offsets storage
        private readonly Dictionary<string, ulong> _namedOffsets = new Dictionary<string, ulong>();

        // Logging callback
        public Action<string>? OnError { get; set; }

        /// <summary>
        /// Set or get the pointer size. 0 = automatic detection, 4 = 32-bit, 8 = 64-bit.
        /// </summary>
        public int PointerSize
        {
            get => _pointerSizeOverride;
            set
            {
                if (value != 0 && value != 4 && value != 8)
                    throw new ArgumentException("PointerSize must be 0, 4, or 8");
                _pointerSizeOverride = value;
            }
        }

        #region Constructor & Destructor

        public Ary(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName))
                throw new ArgumentNullException(nameof(processName), "Process name cannot be null or empty.");

            var processes = Process.GetProcessesByName(processName);
            if (processes.Length == 0)
                throw new InvalidOperationException($"Process '{processName}' not found.");

            _process = processes[0];
            _processHandle = NativeMethods.OpenProcess(NativeMethods.PROCESS_ALL_ACCESS, false, _process.Id);

            if (_processHandle == IntPtr.Zero)
                ThrowError("Failed to open process. Ensure you have the necessary privileges.");
        }

        ~Ary() { Dispose(false); }

        #endregion

        #region Architecture Determination

        private bool Is64BitProcess()
        {
            if (_pointerSizeOverride == 4) return false;
            if (_pointerSizeOverride == 8) return true;

            if (!_is64BitProcess.HasValue)
            {
                if (Environment.Is64BitOperatingSystem)
                {
                    bool isWow64;
                    if (!NativeMethods.IsWow64Process(_process.Handle, out isWow64))
                        ThrowError("Failed to determine process architecture.");

                    _is64BitProcess = !isWow64;
                }
                else
                {
                    _is64BitProcess = false;
                }
            }
            return _is64BitProcess.Value;
        }

        private int GetPointerSize()
        {
            if (_pointerSizeOverride == 4) return 4;
            if (_pointerSizeOverride == 8) return 8;
            return Is64BitProcess() ? 8 : 4;
        }

        #endregion

        #region Memory Reading/Writing

        public T ReadMemory<T>(ulong address, ulong offset = 0)
        {
            EnsureNotDisposed();
            int sizeOfT = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[sizeOfT];
            int bytesRead = 0;

            if (!NativeMethods.ReadProcessMemory(_processHandle, address + offset, buffer, sizeOfT, ref bytesRead) || bytesRead != sizeOfT)
                ThrowError("Failed to read expected memory.");

            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T))!;
            }
            finally
            {
                handle.Free();
            }
        }

        public byte[] ReadMemory(ulong address, int sizeOfBytes, ulong offset = 0)
        {
            EnsureNotDisposed();
            byte[] buffer = new byte[sizeOfBytes];
            int bytesRead = 0;

            if (!NativeMethods.ReadProcessMemory(_processHandle, address + offset, buffer, sizeOfBytes, ref bytesRead) || bytesRead != sizeOfBytes)
                ThrowError("Failed to read expected memory.");

            return buffer;
        }

        public string ReadMemoryString(ulong address, int lengthOfString, Encoding encoding, ulong offset = 0)
        {
            EnsureNotDisposed();
            if (encoding == null) throw new ArgumentNullException(nameof(encoding));

            int byteCount = encoding.Equals(Encoding.Unicode) ? lengthOfString * 2 : lengthOfString;
            byte[] buffer = ReadMemory(address, byteCount, offset);
            return encoding.GetString(buffer);
        }

        public bool WriteMemory<T>(ulong address, T value, ulong offset = 0)
        {
            EnsureNotDisposed();
            int sizeOfT = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[sizeOfT];

            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                Marshal.StructureToPtr(value!, handle.AddrOfPinnedObject(), false);
            }
            finally
            {
                handle.Free();
            }

            int bytesWritten = 0;
            bool result = NativeMethods.WriteProcessMemory(_processHandle, address + offset, buffer, sizeOfT, ref bytesWritten);
            if (!result || bytesWritten != sizeOfT)
                ThrowError("Failed to write expected memory.");

            return true;
        }

        public bool WriteMemory(ulong address, byte[] value, ulong offset = 0)
        {
            EnsureNotDisposed();
            if (value == null) throw new ArgumentNullException(nameof(value));

            int bytesWritten = 0;
            bool result = NativeMethods.WriteProcessMemory(_processHandle, address + offset, value, value.Length, ref bytesWritten);
            if (!result || bytesWritten != value.Length)
                ThrowError("Failed to write expected memory.");
            return true;
        }

        public bool WriteMemoryNull(ulong address, int sizeOfBytes, ulong offset = 0)
        {
            return WriteMemory(address, new byte[sizeOfBytes], offset);
        }

        public bool WriteMemoryString(ulong address, string value, Encoding encoding, ulong offset = 0)
        {
            if (string.IsNullOrEmpty(value))
                throw new ArgumentNullException(nameof(value));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));

            byte[] buffer = encoding.GetBytes(value);
            return WriteMemory(address, buffer, offset);
        }

        #endregion

        #region Pointer Reading

        private ulong ReadPointerFromMemory(ulong address)
        {
            int pointerSize = GetPointerSize();
            if (pointerSize == 8)
            {
                return ReadMemory<ulong>(address);
            }
            else
            {
                uint ptr32 = ReadMemory<uint>(address);
                return ptr32;
            }
        }

        public ulong ReadPointer(ulong address, params ulong[] offsets)
        {
            EnsureNotDisposed();
            ulong finalAddress = address;
            foreach (ulong offset in offsets)
            {
                finalAddress = ReadPointerFromMemory(finalAddress) + offset;
            }
            return finalAddress;
        }

        public ulong ReadPointer(ulong address, params int[] offsets)
        {
            EnsureNotDisposed();
            ulong finalAddress = address;
            foreach (int offset in offsets)
            {
                finalAddress = ReadPointerFromMemory(finalAddress) + (ulong)offset;
            }
            return finalAddress;
        }

        #endregion

        #region Named Offsets

        public void RegisterOffset(string name, ulong offset)
        {
            if (string.IsNullOrEmpty(name))
                throw new ArgumentNullException(nameof(name));
            _namedOffsets[name] = offset;
        }

        public ulong ReadPointerByName(ulong address, params string[] namedOffsets)
        {
            EnsureNotDisposed();
            ulong finalAddress = address;
            foreach (string name in namedOffsets)
            {
                if (!_namedOffsets.TryGetValue(name, out ulong off))
                    ThrowError($"Offset '{name}' not found.");

                finalAddress = ReadPointerFromMemory(finalAddress) + off;
            }
            return finalAddress;
        }

        #endregion

        #region Convenience Methods

        public string ReadNullTerminatedString(ulong address, Encoding encoding)
        {
            EnsureNotDisposed();
            List<byte> bytes = new List<byte>();
            int charSize = encoding.Equals(Encoding.Unicode) ? 2 : 1;

            while (true)
            {
                byte[] chunk = ReadMemory(address, charSize);
                if (chunk.Length < charSize)
                    break;

                if (encoding.Equals(Encoding.Unicode))
                {
                    if (chunk[0] == 0 && chunk[1] == 0) break;
                    bytes.AddRange(chunk);
                }
                else
                {
                    if (chunk[0] == 0) break;
                    bytes.Add(chunk[0]);
                }
                address += (ulong)charSize;
            }

            return encoding.GetString(bytes.ToArray());
        }

        public T[] ReadArray<T>(ulong address, int count) where T : struct
        {
            EnsureNotDisposed();
            int sizeOfT = Marshal.SizeOf(typeof(T));
            byte[] buffer = ReadMemory(address, sizeOfT * count);
            T[] array = new T[count];

            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                IntPtr ptr = handle.AddrOfPinnedObject();
                for (int i = 0; i < count; i++)
                {
                    array[i] = (T)Marshal.PtrToStructure(ptr + i * sizeOfT, typeof(T))!;
                }
            }
            finally
            {
                handle.Free();
            }

            return array;
        }

        public bool WriteArray<T>(ulong address, T[] array) where T : struct
        {
            EnsureNotDisposed();
            if (array == null) throw new ArgumentNullException(nameof(array));
            int sizeOfT = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[sizeOfT * array.Length];

            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                IntPtr ptr = handle.AddrOfPinnedObject();
                for (int i = 0; i < array.Length; i++)
                {
                    Marshal.StructureToPtr(array[i], ptr + i * sizeOfT, false);
                }
            }
            finally
            {
                handle.Free();
            }

            return WriteMemory(address, buffer);
        }

        #endregion

        #region Memory Allocation & Protection

        public ulong AllocateMemory(int size)
        {
            EnsureNotDisposed();
            IntPtr addr = NativeMethods.VirtualAllocEx(_processHandle, IntPtr.Zero, size, (int)NativeMethods.MEM_COMMIT | (int)NativeMethods.MEM_RESERVE, NativeMethods.PAGE_EXECUTE_READWRITE);
            if (addr == IntPtr.Zero)
                ThrowError("Failed to allocate memory.");
            return (ulong)addr;
        }

        public bool FreeMemory(ulong address)
        {
            EnsureNotDisposed();
            return NativeMethods.VirtualFreeEx(_processHandle, (IntPtr)address, 0, NativeMethods.MEM_RELEASE);
        }

        public bool ChangeMemoryProtection(ulong address, int size, MemoryProtection newProtection)
        {
            EnsureNotDisposed();
            uint oldProtect;
            bool result = NativeMethods.VirtualProtectEx(_processHandle, (IntPtr)address, (UIntPtr)size, (uint)newProtection, out oldProtect);
            if (!result)
                ThrowError("Failed to change memory protection.");
            return result;
        }

        public MemoryProtection QueryMemoryProtection(ulong address)
        {
            EnsureNotDisposed();
            if (NativeMethods.VirtualQueryEx(_processHandle, address, out NativeMethods.MEMORY_BASIC_INFORMATION mbi, (uint)Marshal.SizeOf(typeof(NativeMethods.MEMORY_BASIC_INFORMATION))))
            {
                return (MemoryProtection)mbi.Protect;
            }
            ThrowError("Failed to query memory protection.");
            return 0;
        }

        #endregion

        #region Module & Process Utilities

        public ModuleInfo GetModule(string moduleName)
        {
            EnsureNotDisposed();
            var pmodule = _process.Modules.Cast<ProcessModule>()
                .FirstOrDefault(m => string.Equals(m.ModuleName, moduleName, StringComparison.OrdinalIgnoreCase));

            if (pmodule != null)
                return new ModuleInfo { BaseAddress = (ulong)pmodule.BaseAddress, ModuleSize = pmodule.ModuleMemorySize, ModuleName = pmodule.ModuleName };

            return default;
        }

        public List<ModuleInfo> GetModules()
        {
            EnsureNotDisposed();
            return _process.Modules.Cast<ProcessModule>()
                .Select(m => new ModuleInfo { BaseAddress = (ulong)m.BaseAddress, ModuleSize = m.ModuleMemorySize, ModuleName = m.ModuleName })
                .ToList();
        }

        public bool Nop(ulong address, int length, ulong offset = 0)
        {
            EnsureNotDisposed();
            byte[] nopArray = Enumerable.Repeat((byte)0x90, length).ToArray();
            return WriteMemory(address, nopArray, offset);
        }

        public void FreezeProcess(bool state)
        {
            EnsureNotDisposed();
            foreach (ProcessThread pT in _process.Threads)
            {
                IntPtr pOpenThread = NativeMethods.OpenThread(NativeMethods.ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);
                if (pOpenThread == IntPtr.Zero)
                    continue;

                try
                {
                    if (state)
                    {
                        NativeMethods.SuspendThread(pOpenThread);
                    }
                    else
                    {
                        int suspendCount;
                        do
                        {
                            suspendCount = NativeMethods.ResumeThread(pOpenThread);
                        } while (suspendCount > 0);
                    }
                }
                finally
                {
                    NativeMethods.CloseHandle(pOpenThread);
                }
            }
        }

        public void SimulateKeyboard(KeyEventFlag simulate, Key key)
        {
            EnsureNotDisposed();
            NativeMethods.PostMessage(_process.MainWindowHandle, (IntPtr)simulate, (IntPtr)key, IntPtr.Zero);
        }

        public void SetMousePosition(int x, int y)
        {
            NativeMethods.SetCursorPos(x, y);
        }

        public void SetMousePosition(MousePoint point)
        {
            SetMousePosition(point.X, point.Y);
        }

        public MousePoint GetMousePosition()
        {
            if (!NativeMethods.GetCursorPos(out MousePoint currentMousePoint))
                return new MousePoint(0, 0);

            return currentMousePoint;
        }

        public void SimulateMouse(MouseEventFlags value)
        {
            var position = GetMousePosition();
            NativeMethods.mouse_event((int)value, position.X, position.Y, 0, 0);
        }

        public void InjectDLL(string dllPath)
        {
            EnsureNotDisposed();
            if (string.IsNullOrEmpty(dllPath))
                throw new ArgumentNullException(nameof(dllPath));

            IntPtr loadLibraryAddr = NativeMethods.GetProcAddress(NativeMethods.GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            if (loadLibraryAddr == IntPtr.Zero)
                ThrowError("Failed to retrieve LoadLibraryA address.");

            int size = (dllPath.Length + 1) * Marshal.SizeOf(typeof(char));
            IntPtr allocMemAddress = NativeMethods.VirtualAllocEx(_processHandle, IntPtr.Zero, size, (int)NativeMethods.MEM_COMMIT | (int)NativeMethods.MEM_RESERVE, (int)NativeMethods.PAGE_READWRITE);
            if (allocMemAddress == IntPtr.Zero)
                ThrowError("Failed to allocate memory for DLL path.");

            int bytesWritten = 0;
            byte[] dllBytes = Encoding.Default.GetBytes(dllPath);
            if (!NativeMethods.WriteProcessMemory(_processHandle, (ulong)allocMemAddress, dllBytes, dllBytes.Length, ref bytesWritten) || bytesWritten != dllBytes.Length)
                ThrowError("Failed to write DLL path.");

            IntPtr threadHandle = NativeMethods.CreateRemoteThread(_processHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
            if (threadHandle == IntPtr.Zero)
                ThrowError("Failed to create remote thread for DLL injection.");
        }

        #endregion

        #region AoB Scanning

        public ulong[] ScanAoB(string signature)
        {
            // Scan full process memory
            return ScanAoBInternal(signature, 0, ulong.MaxValue);
        }

        public ulong[] ScanAoBInModule(string moduleName, string signature)
        {
            var mod = GetModule(moduleName);
            if (mod.BaseAddress == 0 || mod.ModuleSize == 0)
                return Array.Empty<ulong>();

            ulong start = mod.BaseAddress;
            ulong end = start + (ulong)mod.ModuleSize;
            return ScanAoBInternal(signature, start, end);
        }

        private ulong[] ScanAoBInternal(string signature, ulong start, ulong end)
        {
            EnsureNotDisposed();
            if (string.IsNullOrWhiteSpace(signature))
                return Array.Empty<ulong>();

            byte[] signatureBytes = ConvertAoBSignature(signature);

            List<ulong> results = new List<ulong>();
            int mbiSize = Marshal.SizeOf(typeof(NativeMethods.MEMORY_BASIC_INFORMATION));
            ulong currentAddress = start;

            while (currentAddress < end && NativeMethods.VirtualQueryEx(_processHandle, currentAddress, out NativeMethods.MEMORY_BASIC_INFORMATION mbi, (uint)mbiSize))
            {
                if (mbi.BaseAddress + mbi.RegionSize > end)
                    mbi.RegionSize = end - mbi.BaseAddress;

                bool readable = (mbi.State == NativeMethods.MEM_COMMIT) &&
                                 ((mbi.Protect & (uint)MemoryProtection.ReadableMask) != 0);

                if (readable)
                {
                    int bytesRead = 0;
                    byte[] buffer = new byte[(int)mbi.RegionSize];
                    if (NativeMethods.ReadProcessMemory(_processHandle, mbi.BaseAddress, buffer, buffer.Length, ref bytesRead))
                    {
                        for (int i = 0; i <= bytesRead - signatureBytes.Length; i++)
                        {
                            if (MatchPattern(buffer, i, signatureBytes))
                                results.Add(mbi.BaseAddress + (ulong)i);
                        }
                    }
                }

                ulong newAddress = mbi.BaseAddress + mbi.RegionSize;
                if (newAddress <= currentAddress)
                    break;
                currentAddress = newAddress;
            }

            return results.ToArray();
        }

        private bool MatchPattern(byte[] buffer, int index, byte[] pattern)
        {
            for (int i = 0; i < pattern.Length; i++)
            {
                byte p = pattern[i];
                // We'll treat 0xCD as wildcard internally here
                // In ConvertAoBSignature, we use 0xCD for wildcards.
                if (p != 0xCD && buffer[index + i] != p)
                    return false;
            }
            return true;
        }

        private byte[] ConvertAoBSignature(string signature)
        {
            var elements = signature.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            byte[] converted = new byte[elements.Length];

            // Use 0xCD as a wildcard marker
            for (int i = 0; i < elements.Length; i++)
            {
                if (elements[i] == "??")
                    converted[i] = 0xCD;
                else
                    converted[i] = Convert.ToByte(elements[i], 16);
            }

            return converted;
        }

        #endregion

        #region Code Cave & Hooking

        public ulong CreateCodeCave(int size)
        {
            return AllocateMemory(size);
        }

        public void HookInstruction(ulong targetAddress, ulong caveAddress, int length)
        {
            EnsureNotDisposed();
            if (length < 5)
                ThrowError("Need at least 5 bytes to write a JMP.");

            int rel32 = (int)((long)caveAddress - ((long)targetAddress + 5));
            byte[] jmpInstruction = new byte[5];
            jmpInstruction[0] = 0xE9;
            BitConverter.GetBytes(rel32).CopyTo(jmpInstruction, 1);

            byte[] hookData = new byte[length];
            Array.Copy(jmpInstruction, hookData, 5);
            for (int i = 5; i < length; i++)
                hookData[i] = 0x90;

            WriteMemory(targetAddress, hookData);
        }

        public void WriteJumpInstruction(ulong address, ulong destination)
        {
            EnsureNotDisposed();
            int rel32 = (int)((long)destination - ((long)address + 5));
            byte[] jmp = new byte[5];
            jmp[0] = 0xE9;
            BitConverter.GetBytes(rel32).CopyTo(jmp, 1);
            WriteMemory(address, jmp);
        }

        public void WriteCaveInstructions(ulong caveAddress, byte[] instructions, ulong returnAddress)
        {
            EnsureNotDisposed();
            if (instructions == null || instructions.Length == 0)
                throw new ArgumentNullException(nameof(instructions));

            WriteMemory(caveAddress, instructions);
            ulong jumpBackAddress = caveAddress + (ulong)instructions.Length;
            WriteJumpInstruction(jumpBackAddress, returnAddress);
        }

        #endregion

        #region Thread and Diagnostics

        public List<uint> EnumerateThreads()
        {
            EnsureNotDisposed();
            return _process.Threads.Cast<ProcessThread>().Select(t => (uint)t.Id).ToList();
        }

        public byte[] GetThreadContext(uint threadId)
        {
            // Stub method: Getting thread context requires additional logic.
            ThrowError("GetThreadContext not implemented. Please implement for your architecture.");
            return Array.Empty<byte>();
        }

        public string DumpMemory(ulong address, int size)
        {
            EnsureNotDisposed();
            byte[] data = ReadMemory(address, size);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                sb.AppendFormat("{0:X2} ", data[i]);
                if ((i + 1) % 16 == 0) sb.AppendLine();
            }
            return sb.ToString();
        }

        #endregion

        #region Error Handling & Disposal

        private void ThrowError(string message)
        {
            OnError?.Invoke(message);
            throw new InvalidOperationException(message);
        }

        private void EnsureNotDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (_processHandle != IntPtr.Zero)
                    NativeMethods.CloseHandle(_processHandle);

                _disposed = true;
            }
        }

        public void Close()
        {
            Dispose();
        }

        #endregion
    }

    #region Enums, Structs, and Flags

    public enum KeyEventFlag
    {
        KEYDOWN = 0x100,
        KEYUP = 0x101
    }

    public enum Key
    {
        LeftMouseBtn = 0x01,
        RightMouseBtn = 0x02,
        CtrlBrkPrcs = 0x03,
        MidMouseBtn = 0x04,
        ThumbForward = 0x05,
        ThumbBack = 0x06,
        BackSpace = 0x08,
        Tab = 0x09,
        Clear = 0x0C,
        Enter = 0x0D,
        Shift = 0x10,
        Control = 0x11,
        Alt = 0x12,
        Pause = 0x13,
        CapsLock = 0x14,
        // ... (other keys as in the original code)
        // Shortened for brevity. You can keep the full enum if desired.
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MousePoint
    {
        public int X;
        public int Y;
        public MousePoint(int x, int y) { X = x; Y = y; }
        public override string ToString() => $"<{X}, {Y}>";
    }

    [Flags]
    public enum MouseEventFlags
    {
        LeftDown = 0x00000002,
        LeftUp = 0x00000004,
        MiddleDown = 0x00000020,
        MiddleUp = 0x00000040,
        Move = 0x00000001,
        Absolute = 0x00008000,
        RightDown = 0x00000008,
        RightUp = 0x00000010
    }

    [Flags]
    public enum MemoryProtection : uint
    {
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        Guard = 0x100,
        NoCache = 0x200,
        WriteCombine = 0x400,

        ReadableMask = ReadOnly | ReadWrite | WriteCopy | ExecuteRead | ExecuteReadWrite | ExecuteWriteCopy
    }

    public struct ModuleInfo
    {
        public ulong BaseAddress;
        public int ModuleSize;
        public string ModuleName;
    }

    #endregion

    #region Native Methods

    internal static class NativeMethods
    {
        internal const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        internal const uint MEM_COMMIT = 0x1000;
        internal const uint MEM_RESERVE = 0x2000;
        internal const uint MEM_RELEASE = 0x8000;
        internal const uint PAGE_READONLY = 0x02;
        internal const uint PAGE_READWRITE = 0x04;
        internal const int PAGE_EXECUTE_READWRITE = 0x40;

        [Flags]
        internal enum ThreadAccess : int
        {
            SUSPEND_RESUME = 0x0002
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct MEMORY_BASIC_INFORMATION
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
        internal static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteProcessMemory(IntPtr hProcess, ulong lpBaseAddress, [In] byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(IntPtr hProcess, ulong lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr hHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualQueryEx(IntPtr hProcess, ulong lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        internal static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        internal static extern int ResumeThread(IntPtr hThread);

        [DllImport("user32.dll", EntryPoint = "SetCursorPos")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetCursorPos(int x, int y);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetCursorPos(out MousePoint lpMousePoint);

        [DllImport("user32.dll")]
        internal static extern void mouse_event(int dwFlags, int dx, int dy, int dwData, int dwExtraInfo);

        [DllImport("user32.dll")]
        internal static extern bool PostMessage(IntPtr hWnd, IntPtr Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, int flAllocationType, int flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        internal static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize,
                                                         IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool IsWow64Process(IntPtr hProcess, out bool lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    }

    #endregion
}
