using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace AryMem
{
    public class Ary
    {
        #region Constructor
        /// <summary>
        /// IMPORTANT :
        /// <para>Make sure add manifest to project and set it to administrator privileges </para>
        /// </summary>
        /// <param name="processName"></param>
        /// <exception cref="Exception"></exception>
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
        /// <para>Use : ReadMemory(ulong address, int sizeOfBytes) for byte[]</para>
        /// <para>Use : ReadMemory(ulong address, int lengthOfString, StringType stringType) for string</para>
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
        /// <para>Use : WriteMemory(ulong address, byte[] value) for byte[]</para>
        /// <para>Use : WriteMemory(ulong address, string value, StringType stringType) for string</para>
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
        /// <param name="signatures">string of target signature : "?? 12 A8 FF ??"</param>
        /// <returns>List of found addresses</returns>
        public ulong[] ScanAoB(string signatures)
        {
            List<ulong> results = new List<ulong>();

            ulong currentAddress = 0;
            int bytesRead = 0;

            byte[] signatureByteArray = ConvertStringToBytes(signatures);

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
            return results.ToArray();
        }

        /// <summary>
        /// Freeze and Unfreeze process
        /// </summary>
        /// <param name="state"></param>
        public void FrezzeProcess(bool state)
        {
            if (state)
            {
                foreach (ProcessThread pT in mProcess.Threads)
                {
                    IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);
                    if (pOpenThread == IntPtr.Zero)
                    {
                        continue;
                    }
                    SuspendThread(pOpenThread);
                    CloseHandle(pOpenThread);
                }
            }
            else
            {
                foreach (ProcessThread pT in mProcess.Threads)
                {
                    IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);
                    if (pOpenThread == IntPtr.Zero)
                    {
                        continue;
                    }
                    int suspendCount = 0;
                    do
                    {
                        suspendCount = ResumeThread(pOpenThread);
                    } while (suspendCount > 0);
                    CloseHandle(pOpenThread);
                }
            }
        }
        /// <summary>
        /// Simulate key press, down, and up to foreground and non foreground process
        /// </summary>
        /// <param name="simulate"></param>
        /// <param name="key"></param>
        public void SimulateKeyboard(KeyEventFlag simulate, Key key)
        {
            PostMessage(mProcess.MainWindowHandle, (IntPtr)simulate, (IntPtr)key, IntPtr.Zero);
        }
        /// <summary>
        /// Set cursor position by x and y
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        public void SetMousePosition(int x, int y)
        {
            SetCursorPos(x, y);
        }
        /// <summary>
        /// Set cursor position by mouse point
        /// </summary>
        /// <param name="point"></param>
        public void SetMousePosition(MousePoint point)
        {
            SetCursorPos(point.X, point.Y);
        }
        /// <summary>
        /// Get mouse position
        /// </summary>
        /// <returns>Mouse point</returns>
        public MousePoint GetMousePosition()
        {
            MousePoint currentMousePoint;
            var gotPoint = GetCursorPos(out currentMousePoint);
            if (!gotPoint) { currentMousePoint = new MousePoint(0, 0); }
            return currentMousePoint;
        }
        /// <summary>
        /// Simulate mouse button clicks
        /// </summary>
        /// <param name="value"></param>
        public void SimulateMouse(MouseEventFlags value)
        {
            MousePoint position = GetMousePosition();

            mouse_event((int)value, position.X, position.Y, 0, 0);
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
        public enum KeyEventFlag
        {
            KEYDOWN = 0x100,
            KEYUP = 0x101
        }
        public enum Key
        {
            LeftMouseBtn			=0x01, //Left mouse button
	        RightMouseBtn			=0x02, //Right mouse button
	        CtrlBrkPrcs				=0x03, //Control-break processing
	        MidMouseBtn				=0x04, //Middle mouse button
	        ThumbForward			=0x05, //Thumb button back on mouse aka X1
	        ThumbBack				=0x06, //Thumb button forward on mouse aka X2
	        BackSpace				=0x08, //Backspace key
	        Tab						=0x09, //Tab key
	        Clear					=0x0C, //Clear key
	        Enter					=0x0D, //Enter or Return key
	        Shift					=0x10, //Shift key
	        Control					=0x11, //Ctrl key
	        Alt						=0x12, //Alt key
	        Pause					=0x13, //Pause key
	        CapsLock				=0x14, //Caps lock key
	        Kana					=0x15, //Kana input mode
	        Hangeul					=0x15, //Hangeul input mode
	        Hangul					=0x15, //Hangul input mode
	        Junju					=0x17, //Junja input method
	        Final					=0x18, //Final input method
	        Hanja					=0x19, //Hanja input method
	        Kanji					=0x19, //Kanji input method
	        Escape					=0x1B, //Esc key
	        Convert					=0x1C, //IME convert
	        NonConvert				=0x1D, //IME Non convert
	        Accept					=0x1E, //IME accept
	        ModeChange				=0x1F, //IME mode change
	        Space					=0x20, //Space bar
	        PageUp					=0x21, //Page up key
	        PageDown				=0x22, //Page down key
	        End						=0x23, //End key
	        Home					=0x24, //Home key
	        LeftArrow				=0x25, //Left arrow key
	        UpArrow					=0x26, //Up arrow key
	        RightArrow				=0x27, //Right arrow key
	        DownArrow				=0x28, //Down arrow key
	        Select					=0x29, //Select key
	        Print					=0x2A, //Print key
	        Execute					=0x2B, //Execute key
	        PrintScreen				=0x2C, //Print screen key
	        Inser					=0x2D, //Insert key
	        Delete					=0x2E, //Delete key
	        Help					=0x2F, //Help key
	        Num0					=0x30, //Top row 0 key (Matches '0')
	        Num1					=0x31, //Top row 1 key (Matches '1')
	        Num2					=0x32, //Top row 2 key (Matches '2')
	        Num3					=0x33, //Top row 3 key (Matches '3')
	        Num4					=0x34, //Top row 4 key (Matches '4')
	        Num5					=0x35, //Top row 5 key (Matches '5')
	        Num6					=0x36, //Top row 6 key (Matches '6')
	        Num7					=0x37, //Top row 7 key (Matches '7')
	        Num8					=0x38, //Top row 8 key (Matches '8')
	        Num9					=0x39, //Top row 9 key (Matches '9')
	        A						=0x41, //A key (Matches 'A')
	        B						=0x42, //B key (Matches 'B')
	        C						=0x43, //C key (Matches 'C')
	        D						=0x44, //D key (Matches 'D')
	        E						=0x45, //E key (Matches 'E')
	        F						=0x46, //F key (Matches 'F')
	        G						=0x47, //G key (Matches 'G')
	        H						=0x48, //H key (Matches 'H')
	        I						=0x49, //I key (Matches 'I')
	        J						=0x4A, //J key (Matches 'J')
	        K						=0x4B, //K key (Matches 'K')
	        L						=0x4C, //L key (Matches 'L')
	        M						=0x4D, //M key (Matches 'M')
	        N						=0x4E, //N key (Matches 'N')
	        O						=0x4F, //O key (Matches 'O')
	        P						=0x50, //P key (Matches 'P')
	        Q						=0x51, //Q key (Matches 'Q')
	        R						=0x52, //R key (Matches 'R')
	        S						=0x53, //S key (Matches 'S')
	        T						=0x54, //T key (Matches 'T')
	        U						=0x55, //U key (Matches 'U')
	        V						=0x56, //V key (Matches 'V')
	        W						=0x57, //W key (Matches 'W')
	        X						=0x58, //X key (Matches 'X')
	        Y						=0x59, //Y key (Matches 'Y')
	        Z						=0x5A, //Z key (Matches 'Z')
	        LeftWin					=0x5B, //Left windows key
	        RightWin				=0x5C, //Right windows key
	        Apps					=0x5D, //Applications key
	        Sleep					=0x5F, //Computer sleep key
	        Numpad0					=0x60, //Numpad 0
	        Numpad1					=0x61, //Numpad 1
	        Numpad2					=0x62, //Numpad 2
	        Numpad3					=0x63, //Numpad 3
	        Numpad4					=0x64, //Numpad 4
	        Numpad5					=0x65, //Numpad 5
	        Numpad6					=0x66, //Numpad 6
	        Numpad7					=0x67, //Numpad 7
	        Numpad8					=0x68, //Numpad 8
	        Numpad9					=0x69, //Numpad 9
	        Multiply				=0x6A, //Multiply key
	        Add						=0x6B, //Add key
	        Separator				=0x6C, //Separator key
	        Subtract				=0x6D, //Subtract key
	        Decimal					=0x6E, //Decimal key
	        Divide					=0x6F, //Divide key
	        F1						=0x70, //F1
	        F2						=0x71, //F2
	        F3						=0x72, //F3
	        F4						=0x73, //F4
	        F5						=0x74, //F5
	        F6						=0x75, //F6
	        F7						=0x76, //F7
	        F8						=0x77, //F8
	        F9						=0x78, //F9
	        F10						=0x79, //F10
	        F11						=0x7A, //F11
	        F12						=0x7B, //F12
	        F13						=0x7C, //F13
	        F14						=0x7D, //F14
	        F15						=0x7E, //F15
	        F16						=0x7F, //F16
	        F17						=0x80, //F17
	        F18						=0x81, //F18
	        F19						=0x82, //F19
	        F20						=0x83, //F20
	        F21						=0x84, //F21
	        F22						=0x85, //F22
	        F23						=0x86, //F23
	        F24						=0x87, //F24
	        NavigationView			=0x88, //reserved
	        NavigationMenu			=0x89, //reserved
	        NavigationUp			=0x8A, //reserved
	        NavigationDown			=0x8B, //reserved
	        NavigationLeft			=0x8C, //reserved
	        NavigationRight			=0x8D, //reserved
	        NavigationAccept		=0x8E, //reserved
	        NavigationCancel		=0x8F, //reserved
	        NumLock					=0x90, //Num lock key
	        ScrollLock				=0x91, //Scroll lock key
	        NumpadEqual				=0x92, //Numpad =
	        FJ_Jisho				=0x92, //Dictionary key
	        FJ_Masshou				=0x93, //Unregister word key
	        FJ_Touroku				=0x94, //Register word key
	        FJ_Loya					=0x95, //Left OYAYUBI key
	        FJ_Roya					=0x96, //Right OYAYUBI key
	        LeftShift				=0xA0, //Left shift key
	        RightShift				=0xA1, //Right shift key
	        LeftCtrl				=0xA2, //Left control key
	        RightCtrl				=0xA3, //Right control key
	        LeftMenu				=0xA4, //Left menu key
	        RightMenu				=0xA5, //Right menu
	        BrowserBack				=0xA6, //Browser back button
	        BrowserForward			=0xA7, //Browser forward button
	        BrowserRefresh			=0xA8, //Browser refresh button
	        BrowserStop				=0xA9, //Browser stop button
	        BrowserSearch			=0xAA, //Browser search button
	        BrowserFavorites		=0xAB, //Browser favorites button
	        BrowserHome				=0xAC, //Browser home button
	        VolumeMute				=0xAD, //Volume mute button
	        VolumeDown				=0xAE, //Volume down button
	        VolumeUp				=0xAF, //Volume up button
	        NextTrack				=0xB0, //Next track media button
	        PrevTrack				=0xB1, //Previous track media button
	        Stop					=0xB2, //Stop media button
	        PlayPause				=0xB3, //Play/pause media button
	        Mail					=0xB4, //Launch mail button
	        MediaSelect				=0xB5, //Launch media select button
	        App1					=0xB6, //Launch app 1 button
	        App2					=0xB7, //Launch app 2 button
	        OEM1					=0xBA, //;: key for US or misc keys for others
	        Plus					=0xBB, //Plus key
	        Comma					=0xBC, //Comma key
	        Minus					=0xBD, //Minus key
	        Period					=0xBE, //Period key
	        OEM2					=0xBF, //? for US or misc keys for others
	        OEM3					=0xC0, //~ for US or misc keys for others
	        Gamepad_A				=0xC3, //Gamepad A button
	        Gamepad_B				=0xC4, //Gamepad B button
	        Gamepad_X				=0xC5, //Gamepad X button
	        Gamepad_Y				=0xC6, //Gamepad Y button
	        GamepadRightBumper		=0xC7, //Gamepad right bumper
	        GamepadLeftBumper		=0xC8, //Gamepad left bumper
	        GamepadLeftTrigger		=0xC9, //Gamepad left trigger
	        GamepadRightTrigger		=0xCA, //Gamepad right trigger
	        GamepadDPadUp			=0xCB, //Gamepad DPad up
	        GamepadDPadDown			=0xCC, //Gamepad DPad down
	        GamepadDPadLeft			=0xCD, //Gamepad DPad left
	        GamepadDPadRight		=0xCE, //Gamepad DPad right
	        GamepadMenu				=0xCF, //Gamepad menu button
	        GamepadView				=0xD0, //Gamepad view button
	        GamepadLeftStickBtn		=0xD1, //Gamepad left stick button
	        GamepadRightStickBtn	=0xD2, //Gamepad right stick button
	        GamepadLeftStickUp		=0xD3, //Gamepad left stick up
	        GamepadLeftStickDown	=0xD4, //Gamepad left stick down
	        GamepadLeftStickRight	=0xD5, //Gamepad left stick right
	        GamepadLeftStickLeft	=0xD6, //Gamepad left stick left
	        GamepadRightStickUp		=0xD7, //Gamepad right stick up
	        GamepadRightStickDown	=0xD8, //Gamepad right stick down
	        GamepadRightStickRight	=0xD9, //Gamepad right stick right
	        GamepadRightStickLeft	=0xDA, //Gamepad right stick left
	        OEM4					=0xDB, //[ for US or misc keys for others
	        OEM5					=0xDC, //\ for US or misc keys for others
	        OEM6					=0xDD, //] for US or misc keys for others
	        OEM7					=0xDE, //' for US or misc keys for others
	        OEM8					=0xDF, //Misc keys for others
	        OEMAX					=0xE1, //AX key on Japanese AX keyboard
	        OEM102					=0xE2, //"<>" or "\|" on RT 102-key keyboard
	        ICOHelp					=0xE3, //Help key on ICO
	        ICO00					=0xE4, //00 key on ICO
	        ProcessKey				=0xE5, //Process key input method
	        OEMCLEAR				=0xE6, //OEM specific
	        Packet					=0xE7, //IDK man try to google it
	        OEMReset				=0xE9, //OEM reset button
	        OEMJump					=0xEA, //OEM jump button
	        OEMPA1					=0xEB, //OEM PA1 button
	        OEMPA2					=0xEC, //OEM PA2 button
	        OEMPA3					=0xED, //OEM PA3 button
	        OEMWSCtrl				=0xEE, //OEM WS Control button
	        OEMCusel				=0xEF, //OEM CUSEL button
	        OEMAttn					=0xF0, //OEM ATTN button
	        OEMFinish				=0xF1, //OEM finish button
	        OEMCopy					=0xF2, //OEM copy button
	        OEMAuto					=0xF3, //OEM auto button
	        OEMEnlw					=0xF4, //OEM ENLW
	        OEMBackTab				=0xF5, //OEM back tab
	        Attn					=0xF6, //Attn
	        CrSel					=0xF7, //CrSel
	        ExSel					=0xF8, //ExSel
	        EraseEOF				=0xF9, //Erase EOF key
	        Play					=0xFA, //Play key
	        Zoom					=0xFB, //Zoom key
	        NoName					=0xFC, //No name
	        PA1						=0xFD, //PA1 key
	        OEMClear				=0xFE, //OEM Clear key
        };

        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct MousePoint
        {
            public int X;
            public int Y;

            public MousePoint(int x, int y)
            {
                X = x;
                Y = y;
            }

            public override string ToString()
            {
                return $"<{X}, {Y}>";
            }
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
        [DllImport("user32.dll", EntryPoint = "SetCursorPos")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool SetCursorPos(int x, int y);
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetCursorPos(out MousePoint lpMousePoint);
        [DllImport("user32.dll")]
        static extern void mouse_event(int dwFlags, int dx, int dy, int dwData, int dwExtraInfo);
        [DllImport("user32.dll")]
        static extern bool PostMessage(IntPtr hWnd, IntPtr Msg, IntPtr wParam, IntPtr lParam);
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        static extern int ResumeThread(IntPtr hThread);
        [DllImport("kernel32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualQueryEx(IntPtr hProcess, ulong lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);
        #endregion
    }
}
