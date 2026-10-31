// Kovya Windows broker native pipe owner.

//

// This source intentionally targets the .NET Framework C# 5 compiler.  It has

// no package dependencies. Setup startup alone emits fixed progress on stderr;

// no private payload is written there. Stdout is a bounded control channel in host mode and the framed

// response transport in client mode.



using System;

using System.Collections.Generic;

using System.Diagnostics;

using System.Globalization;

using System.IO;

using System.IO.Pipes;

using System.Runtime.InteropServices;

using System.Security.Cryptography;

using System.Security.Principal;

using System.Text;

using System.Threading;

using Microsoft.Win32.SafeHandles;



// Only fixed account documents are read. The native entrypoint supplies the

// installation home from its existing role binding, never from request metadata.

internal sealed class KovyaAccountFileBoundary : IDisposable

{

    [StructLayout(LayoutKind.Sequential)]

    private struct Information {

        internal uint Attributes, CreatedLow, CreatedHigh, AccessLow, AccessHigh,

            WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;

    }

    [StructLayout(LayoutKind.Sequential)]

    private struct Disposition { [MarshalAs(UnmanagedType.Bool)] internal bool Delete; }

    [StructLayout(LayoutKind.Sequential)]

    private struct UnicodeName { internal ushort Length, MaximumLength; internal IntPtr Buffer; }

    [StructLayout(LayoutKind.Sequential)]

    private struct ObjectAttributes {

        internal uint Length; internal IntPtr RootDirectory, ObjectName;

        internal uint Attributes; internal IntPtr SecurityDescriptor, SecurityQualityOfService;

    }

    [StructLayout(LayoutKind.Sequential)]

    private struct IoStatus { internal IntPtr Status, Information; }

    [DllImport("ntdll.dll")]

    private static extern int NtCreateFile(out IntPtr handle,uint access,ref ObjectAttributes attributes,

        out IoStatus status,IntPtr allocation,uint fileAttributes,uint share,uint disposition,uint options,IntPtr ea,uint eaLength);

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]

    private static extern IntPtr CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);

    [DllImport("kernel32.dll", SetLastError=true)]

    private static extern bool GetFileInformationByHandle(IntPtr handle,out Information info);

    [DllImport("kernel32.dll", SetLastError=true)]

    private static extern bool SetFileInformationByHandle(IntPtr handle,int kind,ref Disposition value,uint size);

    [DllImport("kernel32.dll", SetLastError=true)]

    private static extern bool CloseHandle(IntPtr handle);

    private static readonly IntPtr Invalid = new IntPtr(-1);

    private readonly List<IntPtr> guards = new List<IntPtr>();

    private IntPtr homeDirectory, journalDirectory;

    private readonly bool externalLockHeld;

    private readonly bool checkedCleanup;

    internal sealed class CloseFailure : IOException {}

    private void CloseOwned(IntPtr handle) { if(!CloseHandle(handle) && checkedCleanup)throw new CloseFailure(); }

    internal IEnumerable<IntPtr> GuardHandles { get { return guards.ToArray(); } }

    internal string Home { get; private set; }

    internal bool OwnsAccountLock { get { return !externalLockHeld && homeDirectory!=IntPtr.Zero && journalDirectory!=IntPtr.Zero; } }



    internal KovyaAccountFileBoundary(string root) : this(root,false) {}

    internal KovyaAccountFileBoundary(string root,bool externalLockHeld,bool checkedCleanup=false)

    {

        this.externalLockHeld=externalLockHeld;this.checkedCleanup=checkedCleanup;

        string home=Path.GetFullPath(root);Home=home;

        if(!Path.IsPathRooted(root) || home.StartsWith(@"\\?\",StringComparison.Ordinal)

            || home.StartsWith(@"\\.\",StringComparison.Ordinal)) throw new IOException("account_home_invalid");

        try

        {

            string volume=Path.GetPathRoot(home);

            IntPtr current=CreateFile(volume,0x001000A0,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);

            if(current==Invalid) throw new IOException("account_directory_unreadable");

            HoldDirectory(current);

            foreach(string part in home.Substring(volume.Length).Split(Path.DirectorySeparatorChar))

                if(part.Length!=0) current=OpenDirectory(current,part,false);

            homeDirectory=current;

            IntPtr state=OpenDirectory(homeDirectory,"state",true);

            journalDirectory=OpenDirectory(state,"device-auth",true);

            if(!externalLockHeld) {

            IntPtr handle;

            int status=OpenRelative(journalDirectory,"install.lock",0xC0110000,0,2,0x40,out handle);

            if(status==unchecked((int)0xC0000035)) // STATUS_OBJECT_NAME_COLLISION

                status=OpenRelative(journalDirectory,"install.lock",0xC0110000,0,1,0x40,out handle);

            if(status<0) throw new IOException("account_busy_or_unreadable");

            try

            {

                Check(handle,false);

                // Only the verified ordinary lock object is marked for deletion.

                Disposition disposition=new Disposition { Delete=true };

                if(!SetFileInformationByHandle(handle,4,ref disposition,(uint)Marshal.SizeOf(typeof(Disposition))))

                    throw new IOException("account_lease_disposition_failed");

                guards.Add(handle); handle=Invalid;

            }

            finally { if(handle!=Invalid) CloseOwned(handle); }

            }

        }

        catch { if(checkedCleanup)DisposeChecked();else Dispose();throw; }

    }



    private static Information Check(IntPtr handle,bool directory)

    {

        Information info;

        if(!GetFileInformationByHandle(handle,out info) || (info.Attributes & 0x400)!=0

            || ((info.Attributes & 0x10)!=0)!=directory) throw new IOException("account_nonordinary");

        return info;

    }



    // Resolve one literal component from a verified directory object. No child

    // operation walks the absolute path again; DONT_REPARSE refuses reparsing.

    private static int OpenRelative(IntPtr parent,string name,uint access,uint share,uint disposition,uint options,out IntPtr handle)

    {

        if(parent==IntPtr.Zero || parent==Invalid || String.IsNullOrEmpty(name) || name=="." || name==".."

            || name.IndexOfAny(new char[] {'\\','/',':','\0'})>=0 || name.Length>32766)

            throw new IOException("account_component_invalid");

        UnicodeName text=new UnicodeName { Length=(ushort)(name.Length*2), MaximumLength=(ushort)(name.Length*2+2), Buffer=Marshal.StringToHGlobalUni(name) };

        IntPtr descriptor=IntPtr.Zero;

        try

        {

            descriptor=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeName)));

            Marshal.StructureToPtr(text,descriptor,false);

            ObjectAttributes attributes=new ObjectAttributes {

                Length=(uint)Marshal.SizeOf(typeof(ObjectAttributes)),RootDirectory=parent,

                ObjectName=descriptor,Attributes=0x1040 // OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE

            };

            IoStatus io;

            return NtCreateFile(out handle,access,ref attributes,out io,IntPtr.Zero,0,share,disposition,

                options|0x00200020,IntPtr.Zero,0); // OPEN_REPARSE_POINT | SYNCHRONOUS_IO_NONALERT

        }

        finally { if(descriptor!=IntPtr.Zero) Marshal.FreeHGlobal(descriptor); Marshal.FreeHGlobal(text.Buffer); }

    }



    private void HoldDirectory(IntPtr handle)

    {

        try { Check(handle,true); guards.Add(handle); }

        catch { CloseOwned(handle); throw; }

    }



    private IntPtr OpenDirectory(IntPtr parent,string component,bool create)

    {

        IntPtr handle;

        // OPEN_IF creates infrastructure without an absolute create/reopen gap.

        int status=OpenRelative(parent,component,0x001000A0,3,create?3u:1u,1,out handle);

        if(status<0) throw new IOException("account_directory_unreadable");

        HoldDirectory(handle);

        return handle;

    }



    internal Dictionary<string,string> ReadSnapshot()

    {

        if(homeDirectory==IntPtr.Zero || journalDirectory==IntPtr.Zero) throw new ObjectDisposedException("account_boundary");

        for(int i=0;i<guards.Count;i++) Check(guards[i],externalLockHeld || i<guards.Count-1);

        return new Dictionary<string,string> {

            {"manifest",ReadDocument(homeDirectory,"windows-device-auth.json",checkedCleanup)},

            {"manifest_previous",ReadDocument(homeDirectory,"windows-device-auth.json.previous",checkedCleanup)},

            {"device_journal",ReadDocument(journalDirectory,"pending.json",checkedCleanup)},

            {"device_journal_previous",ReadDocument(journalDirectory,"pending.json.previous",checkedCleanup)},

            {"browser_journal",ReadDocument(journalDirectory,"browser-pending.json",checkedCleanup)}

        };

    }



    private static string ReadDocument(IntPtr parent,string name,bool checkedCleanup=false)

    {

        IntPtr handle;

        int status=OpenRelative(parent,name,0x80100000,1,1,0x40,out handle);

        if(status<0)

        {

            // Only a missing literal leaf under the verified handle is absence.

            if(status==unchecked((int)0xC0000034)) return null; // STATUS_OBJECT_NAME_NOT_FOUND

            throw new IOException("account_document_unreadable");

        }

        try

        {

            Information info=Check(handle,false);

            if(info.SizeHigh!=0 || info.SizeLow>131072) throw new IOException("account_document_size");

            using(SafeFileHandle safe=new SafeFileHandle(handle,!checkedCleanup))

            {

                if(!checkedCleanup)handle=Invalid;

                using(FileStream stream=new FileStream(safe,FileAccess.Read))

                {

                    byte[] bytes=new byte[(int)info.SizeLow];

                    try

                    {

                        int offset=0;

                        while(offset<bytes.Length) { int count=stream.Read(bytes,offset,bytes.Length-offset); if(count<=0) throw new IOException("account_document_changed"); offset+=count; }

                        if(stream.ReadByte()!=-1) throw new IOException("account_document_changed");

                        return Convert.ToBase64String(bytes);

                    }

                    finally { Array.Clear(bytes,0,bytes.Length); }

                }

            }

        }

        finally { if(handle!=Invalid && !CloseHandle(handle) && checkedCleanup)throw new CloseFailure(); }

    }



    internal void DisposeChecked()

    {

        for(int i=guards.Count-1;i>=0;i--) { if(!CloseHandle(guards[i]))throw new CloseFailure();guards.RemoveAt(i); }

        homeDirectory=IntPtr.Zero;journalDirectory=IntPtr.Zero;

    }



    public void Dispose()

    {

        for(int i=guards.Count-1;i>=0;i--) CloseHandle(guards[i]);

        guards.Clear(); homeDirectory=IntPtr.Zero; journalDirectory=IntPtr.Zero;

    }

}



internal static partial class KovyaWindowsBrokerNative

{

#if (KOVYA_BOOTSTRAP && KOVYA_MANAGED_RUNTIME) || (KOVYA_BOOTSTRAP && KOVYA_LEGACY_LAYOUT) || (KOVYA_MANAGED_RUNTIME && KOVYA_LEGACY_LAYOUT)

#error Exactly one Kovya native role must be selected.

#endif

#if KOVYA_BOOTSTRAP

    private const string CompiledRole = "bootstrap";

#elif KOVYA_MANAGED_RUNTIME

    private const string CompiledRole = "managed_runtime";

#elif KOVYA_LEGACY_LAYOUT

    private const string CompiledRole = "legacy_layout";

#else

#error Select an explicit Kovya native role; automatic layout selection is forbidden.

#endif

    private const string IdentityTag = "KOVYA_NATIVE_IDENTITY_V2";

    private const string ConfigTag = "KOVYA_NATIVE_CONFIG_V1";

    private const string PrivateReadyTag = "KOVYA_NATIVE_PRIVATE_READY_V1";

    private const string PrivatePreambleTag = "KOVYA_NATIVE_PRIVATE_V1";

    private const string PrivateAckTag = "KOVYA_NATIVE_PRIVATE_ACK_V1";

    private const string ReadyTag = "KOVYA_NATIVE_READY_V1";

    private const string EndpointTag = "KOVYA_NATIVE_ENDPOINT_V1";

    private const string PublicPreambleTag = "KOVYA_NATIVE_PUBLIC_V1";

    private const string PublicAckTag = "KOVYA_NATIVE_ACK_V1";

    private const string TerminationEndpointTag = "KOVYA_NATIVE_TERMINATION_ENDPOINT_V1";

    private const string TerminationAckTag = "KOVYA_NATIVE_TERMINATED_V1";

    private const string AbsentTag = "KOVYA_NATIVE_ABSENT_V1";

    private const string FixedRootAbsenceTag = "KOVYA_NATIVE_FIXED_ROOT_ABSENCE_V1";

    private const string FixedRootAbsentTag = "KOVYA_NATIVE_FIXED_ROOT_ABSENT_V1";



    private const int MaximumFrameBytes = 1024 * 1024;

    private const int MaximumControlLineBytes = 2048;

    private const int MinimumTimeoutMilliseconds = 50;

    private const int MaximumTimeoutMilliseconds = 15000;

    private const int StartupHandshakeTimeoutMilliseconds = 5000;

    private const int MaximumParallelClients = 16;

    private const int CorrelationIdBytes = 16;



    private const uint ProcessQueryLimitedInformation = 0x1000;

    private const uint ProcessTerminate = 0x0001;

    private const uint Synchronize = 0x00100000;

    private const uint TokenQuery = 0x0008;

    private const uint Th32csSnapProcess = 0x00000002;

    private const uint WaitObject0 = 0x00000000;

    private const uint WaitTimeout = 0x00000102;

    private const uint PipeAccessDuplex = 0x00000003;

    private const uint FileFlagOverlapped = 0x40000000;

    private const uint FileFlagFirstPipeInstance = 0x00080000;

    private const uint PipeTypeByte = 0x00000000;

    private const uint PipeReadmodeByte = 0x00000000;

    private const uint PipeWait = 0x00000000;

    private const uint PipeRejectRemoteClients = 0x00000008;

    private const uint SecurityDescriptorRevision = 1;

    private const uint SeGroupLogonId = 0xC0000000;

    private const int ErrorNoMoreFiles = 18;

    private const int ErrorFileNotFound = 2;

    private const int ErrorPathNotFound = 3;

    private const int ErrorPipeBusy = 231;

    private const int ErrorInvalidParameter = 87;

    private const uint GenericRead = 0x80000000;

    private const uint GenericWrite = 0x40000000;

    private const uint OpenExisting = 3;

    private const uint SecuritySqosPresent = 0x00100000;

    private const uint SecurityIdentification = 0x00010000;

    private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);



    private enum TokenInformationClass

    {

        TokenUser = 1,

        TokenGroups = 2,

        TokenStatistics = 10,

        TokenSessionId = 12,

        TokenElevation = 20,

        TokenIntegrityLevel = 25

    }



    [StructLayout(LayoutKind.Sequential)]

    private struct SecurityAttributes

    {

        internal int Length;

        internal IntPtr SecurityDescriptor;

        internal int InheritHandle;

    }



    [StructLayout(LayoutKind.Sequential)]

    private struct Luid

    {

        internal uint LowPart;

        internal int HighPart;

    }



    [StructLayout(LayoutKind.Sequential)]

    private struct TokenStatistics

    {

        internal Luid TokenId;

        internal Luid AuthenticationId;

        internal long ExpirationTime;

        internal int TokenType;

        internal int ImpersonationLevel;

        internal uint DynamicCharged;

        internal uint DynamicAvailable;

        internal uint GroupCount;

        internal uint PrivilegeCount;

        internal Luid ModifiedId;

    }



    [StructLayout(LayoutKind.Sequential)]

    private struct SidAndAttributes

    {

        internal IntPtr Sid;

        internal uint Attributes;

    }



    [StructLayout(LayoutKind.Sequential)]

    private struct NativeFileTime

    {

        internal uint LowDateTime;

        internal uint HighDateTime;

    }



    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]

    private struct ProcessEntry32

    {

        internal uint Size;

        internal uint Usage;

        internal uint ProcessId;

        internal IntPtr DefaultHeapId;

        internal uint ModuleId;

        internal uint Threads;

        internal uint ParentProcessId;

        internal int BasePriority;

        internal uint Flags;



        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]

        internal string ExeFile;

    }



    private sealed class TokenIdentity

    {

        internal string UserSid;

        internal string UserSidHash;

        internal string LogonSid;

        internal string AuthenticationId;

        internal string AuthenticationIdHash;

        internal uint SessionId;

        internal bool IsElevated;

        internal string IntegritySid;

    }



    private sealed class ProcessProof

    {

        internal int ProcessId;

        internal ulong CreationFileTime;

        internal string ImagePathHash;

        internal TokenIdentity Identity;

    }



    private sealed class HostConfiguration

    {

        internal string PublicPipeLeaf;

        internal string PrivatePipeLeaf;

        internal string BrokerBinding;

        internal string BrokerInstance;

        internal string InstallationRootHash;

        internal int TimeoutMilliseconds;

    }



    private sealed class ClientEndpoint

    {

        internal string PublicPipeLeaf;

        internal int ServerProcessId;

        internal ulong ServerCreationFileTime;

        internal string ServerImagePathHash;

        internal string OwnerSidHash;

        internal string AuthenticationIdHash;

        internal uint SessionId;

        internal string BrokerBinding;

        internal string BrokerInstance;

        internal int TimeoutMilliseconds;

    }



    private sealed class TerminationEndpoint

    {

        internal ClientEndpoint Server;

        internal string InstallationRootHash;

        internal ProcessProof ParentProcess;

        internal int TimeoutMilliseconds;

    }



    private sealed class NativeFailure : Exception

    {

        internal readonly int ExitCode;



        internal NativeFailure(int exitCode)

            : base("native_refused")

        {

            ExitCode = exitCode;

        }

    }



    private sealed class TimedResult<T>

    {

        internal T Value;

        internal Exception Error;

    }



    private sealed class PendingResponse : IDisposable

    {

        internal readonly ManualResetEvent Completed = new ManualResetEvent(false);

        internal byte[] Response;

        internal readonly Queue<byte[]> Frames = new Queue<byte[]>();

        internal int FrameCount;

        internal bool Streaming;

        internal bool Failed;



        public void Dispose()

        {

            while(Frames.Count!=0) Clear(Frames.Dequeue());

            Completed.Close();

        }

    }



    private sealed class PrivateMultiplexer : IDisposable

    {

        private readonly NamedPipeServerStream _pipe;

        private readonly object _stateLock = new object();

        private readonly object _writeLock = new object();

        private readonly Dictionary<string, PendingResponse> _pending = new Dictionary<string, PendingResponse>(StringComparer.Ordinal);

        private readonly Thread _reader;

        private readonly HashSet<string> _retired = new HashSet<string>(StringComparer.Ordinal);

        private volatile bool _failed;

        private int _disposed;



        internal PrivateMultiplexer(NamedPipeServerStream pipe)

        {

            _pipe = pipe;

            _reader = new Thread(ReadResponses);

            _reader.IsBackground = true;

            _reader.Start();

        }



        internal bool IsHealthy

        {

            get

            {

                if (_failed || _pipe == null)

                {

                    return false;

                }

                try

                {

                    return _pipe.IsConnected;

                }

                catch (ObjectDisposedException)

                {

                    return false;

                }

            }

        }



        internal byte[] Exchange(byte[] publicRequest, long deadline, Action<byte[]> progress = null)

        {

            if (publicRequest == null || publicRequest.Length < 2 || publicRequest.Length > MaximumFrameBytes)

            {

                throw new NativeFailure(67);

            }



            string correlationId = null;

            PendingResponse pending = new PendingResponse();pending.Streaming=progress!=null;

            byte[] envelope = null;

            try

            {

                lock (_stateLock)

                {

                    if (_failed || _pending.Count >= MaximumParallelClients)

                    {

                        throw new NativeFailure(70);

                    }

                    for (int attempt = 0; attempt < 8; attempt += 1)

                    {

                        string candidate = NewCorrelationId();

                        if (!_pending.ContainsKey(candidate))

                        {

                            correlationId = candidate;

                            break;

                        }

                    }

                    if (correlationId == null)

                    {

                        throw new NativeFailure(70);

                    }

                    _pending.Add(correlationId, pending);

                }



                byte[] prefix = Encoding.ASCII.GetBytes(correlationId);

                try

                {

                    envelope = new byte[CorrelationIdBytes + publicRequest.Length];

                    Buffer.BlockCopy(prefix, 0, envelope, 0, CorrelationIdBytes);

                    Buffer.BlockCopy(publicRequest, 0, envelope, CorrelationIdBytes, publicRequest.Length);

                }

                finally

                {

                    Clear(prefix);

                }



                lock (_writeLock)

                {

                    if (_failed)

                    {

                        throw new NativeFailure(70);

                    }

                    try{WriteBoundedFrame(

                        _pipe,

                        envelope,

                        MaximumFrameBytes + CorrelationIdBytes,

                        deadline);}catch{FailChannel();throw;}

                }



                if(progress!=null) {

                    for(;;) {

                        if(!pending.Completed.WaitOne(RemainingMilliseconds(deadline,67)))throw new NativeFailure(67);

                        byte[] next;

                        lock(_stateLock) {

                            if(pending.Failed||pending.Frames.Count==0)throw new NativeFailure(70);

                            next=pending.Frames.Dequeue();if(pending.Frames.Count==0)pending.Completed.Reset();

                        }

                        bool terminal=PhaseEnvelope.Terminal(next);

                        if(terminal)return next;

                        try{progress(next);}finally{Clear(next);}

                    }

                }

                if (!pending.Completed.WaitOne(RemainingMilliseconds(deadline, 67)))

                {

                    FailChannel();

                    throw new NativeFailure(67);

                }



                lock (_stateLock)

                {

                    if (pending.Failed || pending.Response == null)

                    {

                        throw new NativeFailure(70);

                    }

                    byte[] response = pending.Response;

                    pending.Response = null;

                    return response;

                }

            }

            catch

            {

                // A bounded public request ending must not kill other requests

                // sharing the authenticated resident channel. Partial private

                // writes still fail the whole channel at their owning boundary.

                if(progress==null)FailChannel();

                throw;

            }

            finally

            {

                if (correlationId != null)

                {

                    lock (_stateLock)

                    {

                        _pending.Remove(correlationId);

                        if(pending.Streaming) { if(_retired.Count<256)_retired.Add(correlationId); }

                    }

                }

                Clear(envelope);

                Clear(pending.Response);

                pending.Response = null;

                pending.Dispose();

            }

        }



        private void ReadResponses()

        {

            try

            {

                while (!_failed)

                {

                    byte[] envelope = null;

                    byte[] response = null;

                    try

                    {

                        envelope = ReadBoundedFrameBlocking(

                            _pipe,

                            MaximumFrameBytes + CorrelationIdBytes);

                        if (envelope.Length < CorrelationIdBytes + 2)

                        {

                            throw new NativeFailure(70);

                        }

                        string correlationId = Encoding.ASCII.GetString(envelope, 0, CorrelationIdBytes);

                        if (!IsLowerHex(correlationId, CorrelationIdBytes))

                        {

                            throw new NativeFailure(70);

                        }

                        response = new byte[envelope.Length - CorrelationIdBytes];

                        Buffer.BlockCopy(envelope, CorrelationIdBytes, response, 0, response.Length);



                        PendingResponse pending;

                        lock (_stateLock)

                        {

                            if(_retired.Contains(correlationId))continue;
                            if(!_pending.ContainsKey(correlationId)&&response.Length>=14&&Encoding.ASCII.GetString(response,0,14)=="KOVYA_PHASE_V2\t")continue;

                            if (!_pending.TryGetValue(correlationId, out pending)

                                || pending.Response != null

                                || pending.Failed)

                            {

                                throw new NativeFailure(70);

                            }

                            if(pending.Streaming){if(++pending.FrameCount>32)throw new NativeFailure(70);pending.Frames.Enqueue(response);}

                            else pending.Response = response;

                            response = null;

                            pending.Completed.Set();

                        }

                    }

                    finally

                    {

                        Clear(envelope);

                        Clear(response);

                    }

                }

            }

            catch

            {

                FailChannel();

            }

        }



        private void FailChannel()

        {

            List<PendingResponse> waiting = null;

            lock (_stateLock)

            {

                if (_failed)

                {

                    return;

                }

                _failed = true;

                waiting = new List<PendingResponse>(_pending.Values);

                for (int index = 0; index < waiting.Count; index += 1)

                {

                    waiting[index].Failed = true;

                    Clear(waiting[index].Response);

                    waiting[index].Response = null;

                    waiting[index].Completed.Set();

                }

            }

            try

            {

                _pipe.Dispose();

            }

            catch

            {

            }

        }



        public void Dispose()

        {

            if (Interlocked.Exchange(ref _disposed, 1) != 0)

            {

                return;

            }

            FailChannel();

            if (Thread.CurrentThread != _reader)

            {

                _reader.Join(250);

            }

        }

    }



    [DllImport("kernel32.dll", SetLastError = true)]

    private static extern IntPtr CreateNamedPipe(

        string name,

        uint openMode,

        uint pipeMode,

        uint maximumInstances,

        uint outputBufferSize,

        uint inputBufferSize,

        uint defaultTimeout,

        ref SecurityAttributes securityAttributes);



    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(

        string stringSecurityDescriptor,

        uint stringSdRevision,

        out IntPtr securityDescriptor,

        out uint securityDescriptorSize);



    [DllImport("kernel32.dll", SetLastError = true)]

    private static extern IntPtr LocalFree(IntPtr memory);



    [DllImport("kernel32.dll", SetLastError = true)]

    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);



    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]

    private static extern IntPtr CreateFile(

        string fileName,

        uint desiredAccess,

        uint shareMode,

        IntPtr securityAttributes,

        uint creationDisposition,

        uint flagsAndAttributes,

        IntPtr templateFile);



    [DllImport("kernel32.dll", SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool CloseHandle(IntPtr handle);



    [DllImport("kernel32.dll", SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool TerminateProcess(IntPtr process, uint exitCode);



    [DllImport("kernel32.dll", SetLastError = true)]

    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);



    [DllImport("kernel32.dll", SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool GetProcessTimes(

        IntPtr process,

        out NativeFileTime creation,

        out NativeFileTime exit,

        out NativeFileTime kernel,

        out NativeFileTime user);



    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool QueryFullProcessImageName(

        IntPtr process,

        uint flags,

        StringBuilder imagePath,

        ref uint size);



    [DllImport("advapi32.dll", SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);



    [DllImport("advapi32.dll", SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool OpenThreadToken(IntPtr thread, uint desiredAccess, bool openAsSelf, out IntPtr token);



    [DllImport("kernel32.dll")]

    private static extern IntPtr GetCurrentProcess();



    [DllImport("kernel32.dll")]

    private static extern IntPtr GetCurrentThread();



    [DllImport("advapi32.dll", SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool GetTokenInformation(

        IntPtr token,

        TokenInformationClass tokenInformationClass,

        IntPtr tokenInformation,

        int tokenInformationLength,

        out int returnLength);



    [DllImport("advapi32.dll", SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool ImpersonateNamedPipeClient(IntPtr namedPipe);



    [DllImport("advapi32.dll", SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool RevertToSelf();



    [DllImport("kernel32.dll", SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);



    [DllImport("kernel32.dll", SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool GetNamedPipeClientSessionId(IntPtr pipe, out uint clientSessionId);



    [DllImport("kernel32.dll", SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);



    [DllImport("kernel32.dll", SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool GetNamedPipeServerSessionId(IntPtr pipe, out uint serverSessionId);



    [DllImport("kernel32.dll", SetLastError = true)]

    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);



    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);



    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

    private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);



    private static TextWriter StartupProgress=TextWriter.Null;

    private static int Main(string[] args)

    {
        KovyaStartupTrace.Entry(KovyaStartupTrace.Tick(),args);

        StartupProgress=Console.Error;

        Console.SetError(TextWriter.Null);

        // A bootstrap refusal can occur before RunRuntimeLaunch or admitted JS.

        // Classify that boundary without exposing exception text or a home path.

#if KOVYA_BOOTSTRAP

        string launchStage="native_entrypoint";

#endif

        try

        {

            if (args == null || args.Length == 0)

            {

                return 64;

            }



#if KOVYA_MSIX

            MsixInitialize();

#if KOVYA_BOOTSTRAP

            return MsixLaunch(args);

#endif

#endif

#if KOVYA_BOOTSTRAP

            if (args[0]!="launch" && args[0]!="admit-runtime") return 64;

            launchStage="bootstrap_self_pin";

            RequireBootstrapSelfPin();

            launchStage="native_launch";

            if (String.Equals(args[0], "launch", StringComparison.Ordinal)) return RunRuntimeLaunch(args);

#elif KOVYA_MANAGED_RUNTIME

#if !KOVYA_MSIX

            RuntimeProfileChild.Initialize(args[0]);

#endif

            RuntimeBrokerHome(Process.GetCurrentProcess().MainModule.FileName);

            if(args[0]=="account-worker") {

                int parent;if(args.Length!=2 || !Int32.TryParse(args[1],out parent) || parent<1)return 64;

                return RunAccountWorker(parent);

            }

            if (args[0]=="account-session" || args[0]=="account-session-external") {

                int parent;

                if(args.Length!=2 || !Int32.TryParse(args[1],out parent) || parent<1)return 64;

                return RunAccountState(parent,args[0]=="account-session-external",true);

            }

            if (String.Equals(args[0], "credential", StringComparison.Ordinal))

            {

                int parent;

                if (args.Length != 2 || !Int32.TryParse(args[1], out parent) || parent < 1) return 64;

                return RunCredential(parent);

            }

            if (String.Equals(args[0], "start-broker", StringComparison.Ordinal)) return RunRuntimeLaunch(args);

            if (String.Equals(args[0], "broker-residency", StringComparison.Ordinal)) return RunBrokerResidency(args);

#endif



#if KOVYA_BOOTSTRAP



            if (String.Equals(args[0], "admit-runtime", StringComparison.Ordinal))

            {

                int parent;

                if (args.Length != 2 || !Int32.TryParse(args[1], out parent) || parent < 1) return 64;

                return RunRuntimeAdmission(parent);

            }



#else

            if (String.Equals(args[0], "account-state", StringComparison.Ordinal) || String.Equals(args[0], "account-state-external", StringComparison.Ordinal))

            {

                int parent;

                if (args.Length != 2 || !Int32.TryParse(args[1], out parent) || parent < 1) return 64;

                return RunAccountState(parent,args[0]=="account-state-external");

            }

            if (String.Equals(args[0], "host", StringComparison.Ordinal))

            {

                if (args.Length != 2)

                {

                    return 64;

                }



                int expectedParentProcessId;

                if (!Int32.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out expectedParentProcessId)

                    || expectedParentProcessId < 1)

                {

                    return 64;

                }



                return RunHost(expectedParentProcessId);

            }



            if (String.Equals(args[0], "identity", StringComparison.Ordinal))

            {

                if (args.Length != 2)

                {

                    return 64;

                }



                int expectedParentProcessId;

                if (!Int32.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out expectedParentProcessId)

                    || expectedParentProcessId < 1)

                {

                    return 64;

                }



                return RunIdentity(expectedParentProcessId);

            }



            if (String.Equals(args[0], "client", StringComparison.Ordinal) && args.Length == 1)

            {

                return RunClient();

            }



            if (String.Equals(args[0], "terminate", StringComparison.Ordinal) && args.Length == 1)

            {

                return RunTerminate();

            }



            if (String.Equals(args[0], "assert-terminated", StringComparison.Ordinal) && args.Length == 1)

            {

                return RunAssertTerminated();

            }



            if (String.Equals(args[0], "assert-helper-absent", StringComparison.Ordinal) && args.Length == 1)

            {

                return RunAssertHelperAbsent();

            }



            if (String.Equals(args[0], "assert-fixed-root-absent", StringComparison.Ordinal) && args.Length == 1)

            {

                return RunAssertFixedRootAbsent();

            }



#endif

            return 64;

        }

        catch (NativeFailure failure)

        {

#if KOVYA_BOOTSTRAP

            if(args!=null && args.Length>0 && args[0]=="launch")

                RuntimeLaunchReport("refused",launchStage=="bootstrap_self_pin"?"bootstrap_self_pin_refused":"runtime_launch_refused",launchStage);

#endif

            return failure.ExitCode;

        }

        catch

        {

#if KOVYA_BOOTSTRAP

            if(args!=null && args.Length>0 && args[0]=="launch")

                return RuntimeLaunchReport("refused",launchStage=="bootstrap_self_pin"?"bootstrap_self_pin_refused":"runtime_launch_refused",launchStage);

#endif

            return 1;

        }

    }



#if !KOVYA_BOOTSTRAP

    private static string NewAccountNonce()

    {

        byte[] entropy=new byte[32];

        try {

            using(RandomNumberGenerator rng=RandomNumberGenerator.Create()) rng.GetBytes(entropy);

            return BitConverter.ToString(entropy).Replace("-", "").ToLowerInvariant();

        } finally { Clear(entropy); }

    }



    private static string AccountResponseLine(byte[] key, string invocation, int sequence, string kind, string payload)

    {

        string position=sequence.ToString(System.Globalization.CultureInfo.InvariantCulture);

        string frame="KOVYA_ACCOUNT_FRAME_V1\t"+position+"\t"+kind+"\t"+payload;

        byte[] material=Encoding.ASCII.GetBytes("KOVYA_ACCOUNT_FRAME_V1\nhelper-to-caller\n"+invocation+"\n"+position+"\n"+kind+"\n"+payload);

        byte[] tag=null;

        try {

            using(HMACSHA256 mac=new HMACSHA256(key)) tag=mac.ComputeHash(material);

            return frame+"\t"+BitConverter.ToString(tag).Replace("-", "").ToLowerInvariant();

        } finally { Clear(material);Clear(tag); }

    }





#if KOVYA_MANAGED_RUNTIME

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]

    private struct CredentialRecord

    {

        public uint Flags, Type;

        public IntPtr TargetName, Comment;

        public NativeFileTime LastWritten;

        public uint CredentialBlobSize;

        public IntPtr CredentialBlob;

        public uint Persist, AttributeCount;

        public IntPtr Attributes, TargetAlias, UserName;

    }

    [DllImport("advapi32.dll", EntryPoint="CredWriteW", CharSet=CharSet.Unicode, SetLastError=true)]

    private static extern bool CredentialWriteKernel(ref CredentialRecord credential,uint flags);

    [DllImport("advapi32.dll", EntryPoint="CredReadW", CharSet=CharSet.Unicode, SetLastError=true)]

    private static extern bool CredentialReadKernel(string target,uint type,uint flags,out IntPtr credential);

    [DllImport("advapi32.dll", EntryPoint="CredDeleteW", CharSet=CharSet.Unicode, SetLastError=true)]

    private static extern bool CredentialDeleteKernel(string target,uint type,uint flags);

    [DllImport("advapi32.dll", EntryPoint="CredFree")]

    private static extern void CredentialFreeKernel(IntPtr credential);



    private static void RequireProfileAccountWork() {

#if !KOVYA_MSIX

        RuntimeProfileChild.RequireAccountWork();

#endif

    }

    private static int ProfileAccountBudget(int budget) {

        RequireProfileAccountWork();

#if !KOVYA_MSIX

        ulong now=RuntimeSerialization.GetTickCount64(),until=RuntimeProfileChild.AccountDeadline;

        if(now>=until)throw new IOException("profile_startup_timeout");

        return (int)Math.Min((ulong)budget,until-now);

#else

        return budget;

#endif

    }

    private static bool CredentialWrite(ref CredentialRecord credential,uint flags) {

        RequireProfileAccountWork();

#if KOVYA_PROFILE_ACCOUNT_TEST

        return ProfileTestWrite(ref credential,flags);

#else

        return CredentialWriteKernel(ref credential,flags);

#endif

    }

    private static bool CredentialRead(string target,uint type,uint flags,out IntPtr credential) {

        RequireProfileAccountWork();

#if KOVYA_PROFILE_ACCOUNT_TEST

        return ProfileTestRead(target,type,flags,out credential);

#else

        return CredentialReadKernel(target,type,flags,out credential);

#endif

    }

    private static bool CredentialDelete(string target,uint type,uint flags) {

        RequireProfileAccountWork();

#if KOVYA_PROFILE_ACCOUNT_TEST

        return ProfileTestDelete(target,type,flags);

#else

        return CredentialDeleteKernel(target,type,flags);

#endif

    }

    private static void CredentialFree(IntPtr credential) {

#if KOVYA_PROFILE_ACCOUNT_TEST

        ProfileTestFree(credential);

#else

        CredentialFreeKernel(credential);

#endif

    }



    // The empty second segment is legal. Generic JSON frames are not this wire.

    private static byte[] CredentialSegment(Stream stream,int minimum,int maximum)

    {

        byte[] header=ReadExactBlocking(stream,4);

        try {

            uint length=BitConverter.ToUInt32(header,0);

            if(length<minimum || length>maximum) throw new IOException();

            return ReadExactBlocking(stream,(int)length);

        } finally { Clear(header); }

    }

    private static void CredentialResponse(Stream output,object metadata,byte[] secret)

    {

        byte[] bytes=new UTF8Encoding(false,true).GetBytes(RuntimeJson(metadata));

        try {

            if(bytes.Length<2 || bytes.Length>16384 || secret.Length>8192) throw new IOException();

            byte[] header=BitConverter.GetBytes((uint)bytes.Length);

            output.Write(header,0,4);output.Write(bytes,0,bytes.Length);Clear(header);

            header=BitConverter.GetBytes((uint)secret.Length);

            output.Write(header,0,4);output.Write(secret,0,secret.Length);output.Flush();Clear(header);

        } finally { Clear(bytes); }

    }

    private static int RunCredential(int expectedParent)

    {

        if(GetParentProcessId(Process.GetCurrentProcess().Id)!=expectedParent) throw new NativeFailure(65);

        IntPtr parent=OpenProcess(ProcessQueryLimitedInformation|Synchronize,false,(uint)expectedParent);

        if(parent==IntPtr.Zero) throw new NativeFailure(65);

        try {

            TokenIdentity identity=ReadCurrentIdentity();RequireOrdinaryIdentity(identity,65);

            ProcessProof proof=ReadProcessProof(parent,expectedParent);RequireOrdinaryIdentity(proof.Identity,65);

            RequireSameIdentity(identity,proof.Identity,65);RequireProcessAlive(parent,65);

            // Standalone calls serialize with owned snapshots and compare/commit.

            using(var owner=new KovyaAccountFileBoundary(RuntimeBrokerHome(Process.GetCurrentProcess().MainModule.FileName)))

                ExecuteCredential(Console.OpenStandardInput(),Console.OpenStandardOutput(),parent,false);

            return 0;

        } finally {CloseHandle(parent);}

    }

    internal const string CredentialWitnessSchema = "kovya.credential-store-witness.v1";

    private static readonly string[] WitnessDocumentNames = {"manifest","manifest_previous","device_journal","device_journal_previous","browser_journal"};

    private static string WitnessHash(byte[] bytes) {

        using(SHA256 sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();

    }

    private static void WitnessTarget(HashSet<string> targets,object value) {

        string target=value as string;

        if(String.IsNullOrEmpty(target) || target.Length>512 || !target.StartsWith("Kovya.DeviceAuth/v1/",StringComparison.Ordinal)

            || target.Contains("\\") || target.Contains("..") || target.IndexOfAny(new char[]{'\r','\n','\0'})>=0)throw new IOException("account_state_conflict");

        targets.Add(target);if(targets.Count>256)throw new IOException("account_state_conflict");

    }

    private static void WitnessField(HashSet<string> targets,Dictionary<string,object> document,string field,bool required=false) {

        object value;if(document.TryGetValue(field,out value))WitnessTarget(targets,value);else if(required)throw new IOException("account_state_conflict");

    }

    private static void WitnessArray(HashSet<string> targets,Dictionary<string,object> document,string field) {

        object value;if(!document.TryGetValue(field,out value))return;

        object[] items=value as object[];if(items==null || items.Length>256)throw new IOException("account_state_conflict");

        foreach(object item in items)WitnessTarget(targets,item);

    }

    // This seam supplies the reader for direct unit tests; production always passes

    // ReadWitnessCredential. No command-line or environment switch selects a reader.

    internal static Dictionary<string,object> CaptureCredentialStoreWitness(KovyaAccountFileBoundary boundary,Func<string,byte[]> reader,int budgetMs) {

        if(boundary==null || !boundary.OwnsAccountLock || budgetMs<1 || budgetMs>1000)throw new IOException("account_state_conflict");

        long deadline=DeadlineAfter(budgetMs);

        var documents=new Dictionary<string,object>();var targets=new HashSet<string>(StringComparer.Ordinal);

        var snapshot=boundary.ReadSnapshot();

        foreach(string name in WitnessDocumentNames) {

            RemainingMilliseconds(deadline,67);string encoded=snapshot[name];

            if(encoded==null){documents.Add(name,null);continue;}

            byte[] bytes=Convert.FromBase64String(encoded);

            try {

                documents.Add(name,WitnessHash(bytes));

                var doc=RuntimeParse(new UTF8Encoding(false,true).GetString(bytes));

                string schema=RuntimeString(doc,"schema_version");

                if(name=="manifest" || name=="manifest_previous") {

                    if(schema!="kovya.windows-device-auth.v1")throw new IOException("account_state_conflict");

                    WitnessField(targets,doc,"signing_key_target",true);WitnessField(targets,doc,"refresh_target",true);WitnessArray(targets,doc,"retired_targets");

                } else if(name=="browser_journal") {

                    if(schema!="kovya.windows-browser-auth-journal.v1")throw new IOException("account_state_conflict");

                    WitnessField(targets,doc,"secret_target",true);

                } else {

                    if(schema!="kovya.windows-device-auth-journal.v1")throw new IOException("account_state_conflict");

                    WitnessArray(targets,doc,"staged_targets");WitnessField(targets,doc,"pending_signing_target");

                    WitnessField(targets,doc,"successor_refresh_target");WitnessField(targets,doc,"committed_refresh_target");

                }

            } finally {Clear(bytes);}

        }

        var credentials=new Dictionary<string,object>();var ordered=new List<string>(targets);ordered.Sort(StringComparer.Ordinal);

        foreach(string target in ordered) {

            RemainingMilliseconds(deadline,67);byte[] value=reader(target);

            try {if(value!=null && value.Length>8192)throw new IOException("account_state_conflict");credentials.Add(target,value==null?null:WitnessHash(value));}

            finally {Clear(value);}

        }

        RemainingMilliseconds(deadline,67);

        return new Dictionary<string,object>{{"schema_version",CredentialWitnessSchema},{"home_sha256",WitnessHash(Encoding.UTF8.GetBytes(boundary.Home.ToUpperInvariant()))},{"documents",documents},{"credentials",credentials}};

    }

    private static bool WitnessMapEquals(object left,object right) {

        var a=left as Dictionary<string,object>;var b=right as Dictionary<string,object>;

        if(a==null || b==null || a.Count!=b.Count)return false;

        foreach(var pair in b) {

            object value;if(!a.TryGetValue(pair.Key,out value))return false;

            if(value==null && pair.Value==null)continue;

            if(!(value is string) || !(pair.Value is string) || !FixedEquals((string)value,(string)pair.Value))return false;

        }

        return true;

    }

    internal static bool CredentialStoreWitnessMatches(KovyaAccountFileBoundary boundary,Dictionary<string,object> expected,Func<string,byte[]> reader,int budgetMs) {

        if(expected==null || expected.Count!=4 || !expected.ContainsKey("documents") || !expected.ContainsKey("credentials")

            || RuntimeString(expected,"schema_version")!=CredentialWitnessSchema)return false;

        var current=CaptureCredentialStoreWitness(boundary,reader,budgetMs);

        return FixedEquals(RuntimeString(expected,"home_sha256"),RuntimeString(current,"home_sha256"))

            && WitnessMapEquals(expected["documents"],current["documents"]) && WitnessMapEquals(expected["credentials"],current["credentials"]);

    }

    private static byte[] ReadWitnessCredential(string target) {

        RequireProfileAccountWork();

        IntPtr pointer;

        if(!CredentialRead(target,1,0,out pointer)) {

            if(Marshal.GetLastWin32Error()==1168)return null;

            throw new IOException("account_state_conflict");

        }

        CredentialRecord record=new CredentialRecord();

        try {

            record=(CredentialRecord)Marshal.PtrToStructure(pointer,typeof(CredentialRecord));

            if(record.Type!=1 || record.CredentialBlobSize>8192)throw new IOException("account_state_conflict");

            byte[] value=new byte[(int)record.CredentialBlobSize];

            if(value.Length>0)Marshal.Copy(record.CredentialBlob,value,0,value.Length);return value;

        } finally {

            if(record.CredentialBlob!=IntPtr.Zero && record.CredentialBlobSize<=8192)

                for(int i=0;i<record.CredentialBlobSize;i++)Marshal.WriteByte(record.CredentialBlob,i,0);

            CredentialFree(pointer);

        }

    }

    internal static byte[] CredentialWitnessOperation(KovyaAccountFileBoundary boundary,uint kind,byte[] request,Func<string,byte[]> reader,out bool rejected) {

        rejected=false;

        try {

            var envelope=RuntimeParse(new UTF8Encoding(false,true).GetString(request));object budget;

            if(!envelope.TryGetValue("budget_ms",out budget) || !(budget is int) || (int)budget<1 || (int)budget>1000

                || envelope.Count!=(kind==14?1:2) || (kind!=14 && kind!=15))throw new IOException();

            object result;

            if(reader==(Func<string,byte[]>)ReadWitnessCredential)budget=ProfileAccountBudget((int)budget);

            if(kind==14)result=new Dictionary<string,object>{{"ok",true},{"witness",CaptureCredentialStoreWitness(boundary,reader,(int)budget)}};

            else {

                object expected;if(!envelope.TryGetValue("witness",out expected) || !CredentialStoreWitnessMatches(boundary,expected as Dictionary<string,object>,reader,(int)budget))throw new IOException();

                result=new Dictionary<string,object>{{"ok",true}};

            }

            byte[] bytes=Encoding.UTF8.GetBytes(RuntimeJson(result));

            if(bytes.Length>250000){Clear(bytes);throw new IOException();}

            if(reader==(Func<string,byte[]>)ReadWitnessCredential){try{RequireProfileAccountWork();}catch{Clear(bytes);throw;}}

            return bytes;

        } catch(KovyaAccountFileBoundary.CloseFailure) {throw;}

        catch {rejected=true;return Encoding.UTF8.GetBytes("{\"ok\":false,\"error\":\"account_state_conflict\"}");}

    }



    private static void ExecuteCredential(Stream input,Stream output,IntPtr parent,bool exact)

    {

            byte[] metadata=null,secret=null,result=new byte[0];

            try {

                metadata=CredentialSegment(input,2,16384);

                Dictionary<string,object> request=RuntimeParse(new UTF8Encoding(false,true).GetString(metadata));

                if(RuntimeString(request,"schema_version")!="kovya.credential-bridge.v1") throw new IOException();

                string target=RuntimeString(request,"target"),operation=RuntimeString(request,"operation");

                if(target.Length>512 || !target.StartsWith("Kovya.DeviceAuth/v1/",StringComparison.Ordinal)

                    || target.Contains("\\") || target.Contains("..") || target.IndexOfAny(new char[]{'\r','\n','\0'})>=0) throw new IOException();

                secret=CredentialSegment(input,0,8192);

                if(exact && input.Position!=input.Length)throw new IOException();

                object declared;

                if(!request.TryGetValue("secret_length",out declared) || !(declared is int) || (int)declared!=secret.Length) throw new IOException();

                RequireProcessAlive(parent,65);

                bool compound=operation=="write_read";

                if(compound && !exact) throw new IOException(); // Compound effects require the owned managed session.

                if(operation=="write" || compound) {

                    if(secret.Length==0) throw new IOException();

                    IntPtr name=IntPtr.Zero,user=IntPtr.Zero,blob=IntPtr.Zero;

                    try {

                        name=Marshal.StringToCoTaskMemUni(target);user=Marshal.StringToCoTaskMemUni("Kovya");

                        blob=Marshal.AllocHGlobal(secret.Length);Marshal.Copy(secret,0,blob,secret.Length);

                        CredentialRecord record=new CredentialRecord();record.Type=1;record.Persist=2;

                        record.TargetName=name;record.UserName=user;record.CredentialBlob=blob;record.CredentialBlobSize=(uint)secret.Length;

                        if(!CredentialWrite(ref record,0)) throw new IOException();

                    } finally {

                        if(blob!=IntPtr.Zero) {for(int i=0;i<secret.Length;i++)Marshal.WriteByte(blob,i,0);Marshal.FreeHGlobal(blob);}

                        if(name!=IntPtr.Zero)Marshal.ZeroFreeCoTaskMemUnicode(name);

                        if(user!=IntPtr.Zero)Marshal.ZeroFreeCoTaskMemUnicode(user);

                    }

                    if(!compound) {CredentialResponse(output,new {ok=true,operation=operation},result);return;}

                }

                if(operation=="read" || compound) {

                    if(!compound && secret.Length!=0) throw new IOException();

                    IntPtr pointer;

                    if(!CredentialRead(target,1,0,out pointer)) {

                        if(Marshal.GetLastWin32Error()!=1168) throw new IOException();

                        CredentialResponse(output,new {ok=false,operation=operation,missing=true},result);

                    } else {

                        CredentialRecord record=new CredentialRecord();

                        try {

                            record=(CredentialRecord)Marshal.PtrToStructure(pointer,typeof(CredentialRecord));

                            if(record.CredentialBlobSize>8192) throw new IOException();

                            result=new byte[(int)record.CredentialBlobSize];

                            if(result.Length>0)Marshal.Copy(record.CredentialBlob,result,0,result.Length);

                        } finally {

                            if(record.CredentialBlob!=IntPtr.Zero && record.CredentialBlobSize<=8192)

                                for(int i=0;i<record.CredentialBlobSize;i++)Marshal.WriteByte(record.CredentialBlob,i,0);

                            CredentialFree(pointer);

                        }

                        CredentialResponse(output,new {ok=true,operation=operation},result);

                    }

                } else if(operation=="delete") {

                    if(secret.Length!=0) throw new IOException();

                    bool deleted=CredentialDelete(target,1,0);

                    if(!deleted && Marshal.GetLastWin32Error()!=1168) throw new IOException();

                    CredentialResponse(output,new {ok=true,operation=operation,deleted=deleted},result);

                } else throw new IOException();

            } catch { CredentialResponse(output,new {ok=false,error="credential_operation_failed"},new byte[0]); }

            finally {Clear(metadata);Clear(secret);Clear(result);}

    }

#endif



#if KOVYA_MANAGED_RUNTIME

    // Header: sequence, kind, body length (u32 LE), followed by raw body and

    // HMAC-SHA256(domain/direction/invocation || header || body).

    private static byte[] AccountRpcTag(byte[] key,string invocation,string direction,byte[] header,byte[] body,bool worker=false)

    {

        byte[] prefix=Encoding.ASCII.GetBytes("KOVYA_ACCOUNT_RPC_V"+(worker?"4":"3")+"\n"+direction+"\n"+invocation+"\n");

        try {

            using(HMACSHA256 mac=new HMACSHA256(key)) {

                mac.TransformBlock(prefix,0,prefix.Length,null,0);

                mac.TransformBlock(header,0,header.Length,null,0);

                mac.TransformFinalBlock(body,0,body.Length);return mac.Hash;

            }

        } finally {Clear(prefix);}

    }

    private static void AccountRpcWrite(Stream channel,byte[] key,string invocation,uint sequence,uint kind,byte[] body,bool worker=false)

    {

        if(body.Length>1024*1024+(worker?32:0)) throw new NativeFailure(67);

        byte[] header=new byte[12],tag=null;

        Array.Copy(BitConverter.GetBytes(sequence),0,header,0,4);

        Array.Copy(BitConverter.GetBytes(kind),0,header,4,4);

        Array.Copy(BitConverter.GetBytes((uint)body.Length),0,header,8,4);

        try {

            tag=AccountRpcTag(key,invocation,"helper-to-caller",header,body,worker);

            channel.Write(header,0,header.Length);channel.Write(body,0,body.Length);

            channel.Write(tag,0,tag.Length);channel.Flush();

        } finally {Clear(header);Clear(tag);}

    }

    private static byte[] AccountRpcRead(Stream channel,byte[] key,string invocation,uint sequence,out uint kind,bool worker=false)

    {

        byte[] header=ReadExactBlocking(channel,12),body=null,tag=null,expected=null;

        try {

            uint length=BitConverter.ToUInt32(header,8);kind=BitConverter.ToUInt32(header,4);

            if(BitConverter.ToUInt32(header,0)!=sequence || length>(kind==15?262144:24584)+(worker?32:0)

                || (kind!=10 && kind!=11 && kind!=12 && kind!=14 && kind!=15 && !(worker && (kind==9 || kind==13)))) throw new NativeFailure(67);

            body=ReadExactBlocking(channel,(int)length);tag=ReadExactBlocking(channel,32);

            expected=AccountRpcTag(key,invocation,"caller-to-helper",header,body,worker);

            int difference=0;for(int i=0;i<32;i++)difference|=tag[i]^expected[i];

            if(difference!=0)throw new NativeFailure(67);

            byte[] result=body;body=null;return result;

        } finally {Clear(header);Clear(body);Clear(tag);Clear(expected);}

    }

    private static byte[] WorkerBody(byte[] nonce,byte[] value)

    {

        byte[] result=new byte[32+value.Length];Array.Copy(nonce,result,32);Array.Copy(value,0,result,32,value.Length);return result;

    }

    private static bool WorkerNonceEquals(byte[] request,byte[] nonce)

    {

        if(request.Length<32 || nonce==null)return false;

        int difference=0;for(int i=0;i<32;i++)difference|=request[i]^nonce[i];return difference==0;

    }

    private static int RunAccountWorker(int expectedParent)

    {

        if(GetParentProcessId(Process.GetCurrentProcess().Id)!=expectedParent)throw new NativeFailure(65);

        IntPtr parent=OpenProcess(ProcessQueryLimitedInformation|Synchronize|0x0040,false,(uint)expectedParent);

        if(parent==IntPtr.Zero)throw new NativeFailure(65);

        NamedPipeServerStream channel=null;KovyaAccountFileBoundary boundary=null;

        List<IntPtr> transferred=new List<IntPtr>();byte[] key=null,nonce=null;

        string invocation=null,releaseToken=null;bool potentialOwnership=false,watching=false,witnessRejected=false;

        try {

            long deadline=DeadlineAfter(RuntimeProfileChild.IdleAccount ? RuntimeProfileChild.IdentityBudget(StartupHandshakeTimeoutMilliseconds) : ProfileAccountBudget(StartupHandshakeTimeoutMilliseconds));

            TokenIdentity identity=ReadCurrentIdentity();RequireOrdinaryIdentity(identity,65);

            ProcessProof parentProof=ReadProcessProof(parent,expectedParent);

            RequireSameIdentity(identity,parentProof.Identity,65);RequireProcessAlive(parent,65);

            ProcessProof self;using(Process process=Process.GetCurrentProcess())self=ReadProcessProof(process.Handle,process.Id);

            string image=Process.GetCurrentProcess().MainModule.FileName,boundHome=RuntimeBrokerHome(image);

            Dictionary<string,object> requirement=RuntimeResidentRequirement(image,boundHome);

            string boundVersion=RuntimeString(requirement,"version"),boundDigest=RuntimeString(requirement,"digest");

            invocation=NewAccountNonce();key=new byte[32];using(RandomNumberGenerator rng=RandomNumberGenerator.Create())rng.GetBytes(key);

            channel=CreateOwnedPipe("kovya-account-private-v4-"+invocation,identity,StartupHandshakeTimeoutMilliseconds,1,true);

            IAsyncResult connection=channel.BeginWaitForConnection(null,null);

            WriteAsciiLine(Console.OpenStandardOutput(),BuildIdentityLine(self,parentProof),deadline);

            WriteAsciiLine(Console.OpenStandardOutput(),"KOVYA_ACCOUNT_PEER_V4\t"+invocation+"\t"+BitConverter.ToString(key).Replace("-","").ToLowerInvariant(),deadline);

            if(!CompleteWaitForConnection(channel,connection,parent,deadline,null))throw new NativeFailure(65);

            if(!FixedEquals(ReadAsciiLine(channel,128,deadline),"KOVYA_ACCOUNT_BEGIN_V4\t"+invocation))throw new NativeFailure(67);

            VerifyConnectedPrivateParentClient(channel.SafePipeHandle.DangerousGetHandle(),parent,parentProof,identity);

            Thread death=new Thread(delegate(){if(WaitForSingleObject(parent,UInt32.MaxValue)==WaitObject0)Environment.Exit(0);});

            death.IsBackground=true;death.Start();watching=true;

            AccountRpcWrite(channel,key,invocation,0,1,new byte[0],true);

            RuntimeProfileChild.StartAccountControl();

            for(uint sequence=1;sequence<UInt32.MaxValue;sequence++) {

                uint kind;byte[] request=AccountRpcRead(channel,key,invocation,sequence,out kind,true),value=null,reply=null;

                try {

                  lock(RuntimeProfileChild.AccountGate) {

                   RuntimeProfileChild.CaptureAccountWork();

                   try {

                    RequireProcessAlive(parent,65);

                    if(kind==13) {

                        if(boundary!=null || potentialOwnership || nonce!=null || request.Length!=0 || transferred.Count!=0)throw new NativeFailure(67);

                        AccountRpcWrite(channel,key,invocation,sequence,24,new byte[0],true);return 0;

                    }

                    if(kind==9) {

                        if(boundary!=null || potentialOwnership || nonce!=null || request.Length!=32 || transferred.Count!=0)throw new NativeFailure(67);

                        nonce=(byte[])request.Clone();potentialOwnership=true;witnessRejected=false;RuntimeProfileChild.AccountLease=true;

                        try {

                            RequireProfileAccountWork();

                            Dictionary<string,object> current=RuntimeResidentRequirement(image,boundHome);

                            if(RuntimeString(current,"version")!=boundVersion || !FixedEquals(RuntimeString(current,"digest"),boundDigest))throw new NativeFailure(65);

                            RequireProfileAccountWork();boundary=new KovyaAccountFileBoundary(boundHome,false,true);

                            Dictionary<string,string> snapshot=boundary.ReadSnapshot();

                            releaseToken=NewAccountNonce();

                            foreach(IntPtr handle in boundary.GuardHandles) {

                                IntPtr copy;if(!DuplicateHandle(GetCurrentProcess(),handle,parent,out copy,0,false,2))throw new NativeFailure(65);

                                transferred.Add(copy);

                            }

                            value=Encoding.UTF8.GetBytes(RuntimeJson(new Dictionary<string,object>{{"release_token",releaseToken},{"ownership_mode","native"},{"documents",snapshot},{"witness_schema",CredentialWitnessSchema}}));

                            snapshot.Clear();

                        } catch(KovyaAccountFileBoundary.CloseFailure) {throw;}

                        catch {

                            CloseAccountTransfers(parent,transferred,true);

                            if(boundary!=null){boundary.DisposeChecked();boundary=null;}

                            reply=WorkerBody(nonce,new byte[0]);AccountRpcWrite(channel,key,invocation,sequence,2,reply,true);

                            Clear(nonce);nonce=null;releaseToken=null;potentialOwnership=false;RuntimeProfileChild.AccountLease=false;continue;

                        }

                        reply=WorkerBody(nonce,value);AccountRpcWrite(channel,key,invocation,sequence,19,reply,true);continue;

                    }

                    if(boundary==null || !potentialOwnership || !WorkerNonceEquals(request,nonce))throw new NativeFailure(67);

                    if(kind==12) {

                        if(request.Length!=96 || !FixedEquals(Encoding.ASCII.GetString(request,32,64),releaseToken))throw new NativeFailure(67);

                        CloseAccountTransfers(parent,transferred,true);boundary.DisposeChecked();boundary=null;

                        reply=WorkerBody(nonce,new byte[0]);AccountRpcWrite(channel,key,invocation,sequence,22,reply,true);

                        Clear(nonce);nonce=null;releaseToken=null;potentialOwnership=false;RuntimeProfileChild.AccountLease=false;continue;

                    }

                    if(witnessRejected){reply=WorkerBody(nonce,new byte[0]);AccountRpcWrite(channel,key,invocation,sequence,23,reply,true);continue;}

                    if(kind==10 && request.Length!=32)throw new NativeFailure(67);

                    try {

                        RequireProfileAccountWork();

                        Dictionary<string,object> current=RuntimeResidentRequirement(image,boundHome);

                        if(RuntimeString(current,"version")!=boundVersion || !FixedEquals(RuntimeString(current,"digest"),boundDigest))throw new NativeFailure(65);

                    } catch {reply=WorkerBody(nonce,new byte[0]);AccountRpcWrite(channel,key,invocation,sequence,23,reply,true);continue;}

                    try{RequireProfileAccountWork();}catch{reply=WorkerBody(nonce,new byte[0]);AccountRpcWrite(channel,key,invocation,sequence,23,reply,true);continue;}

                    if(kind==10) {

                        Dictionary<string,string> snapshot=boundary.ReadSnapshot();

                        value=Encoding.UTF8.GetBytes(RuntimeJson(snapshot));snapshot.Clear();

                    } else if(kind==11) {

                        using(MemoryStream input=new MemoryStream(request,32,request.Length-32,false))

                        using(MemoryStream output=new MemoryStream()) {

                            try{ExecuteCredential(input,output,parent,true);value=output.ToArray();}

                            finally{Clear(output.GetBuffer());}

                        }

                    } else if(kind==14 || kind==15) {

                        byte[] payload=new byte[request.Length-32];Array.Copy(request,32,payload,0,payload.Length);

                        try{value=CredentialWitnessOperation(boundary,kind,payload,ReadWitnessCredential,out witnessRejected);}finally{Clear(payload);}

                    } else throw new NativeFailure(67);

                    reply=WorkerBody(nonce,value);AccountRpcWrite(channel,key,invocation,sequence,kind==10?20u:kind==11?21u:kind==14?25u:26u,reply,true);

                   } finally {RuntimeProfileChild.ClearCapturedWork();}

                  }

                } finally {Clear(request);Clear(value);Clear(reply);}

            }

            throw new NativeFailure(67);

        } finally {

            // Lost/partial ownership is never certified released. Parent-side

            // transferred guards survive until the existing parent fail-stop.

            if(!potentialOwnership)CloseAccountTransfers(parent,transferred,true);

            if(boundary!=null)boundary.Dispose();

            if(channel!=null)channel.Dispose();Clear(key);Clear(nonce);

            if(!watching)CloseHandle(parent);

        }

    }



#endif



    private static int RunAccountState(int expectedParent,bool externalLockHeld,bool managedSession=false)

    {

        if(GetParentProcessId(Process.GetCurrentProcess().Id)!=expectedParent) throw new NativeFailure(65);

        IntPtr parent=OpenProcess(ProcessQueryLimitedInformation|Synchronize|0x0040,false,(uint)expectedParent);

        if(parent==IntPtr.Zero) throw new NativeFailure(65);

        List<IntPtr> transferred=new List<IntPtr>();

        bool published=false, released=false, connected=false;

        KovyaAccountFileBoundary boundary=null;

        NamedPipeServerStream channel=null;

        byte[] responseKey=null;

        string invocation=null;

        try

        {

            long startupDeadline=DeadlineAfter(StartupHandshakeTimeoutMilliseconds);

            TokenIdentity identity=ReadCurrentIdentity(); RequireOrdinaryIdentity(identity,65);

            ProcessProof parentProof=ReadProcessProof(parent,expectedParent);

            RequireSameIdentity(identity,parentProof.Identity,65); RequireProcessAlive(parent,65);

            ProcessProof self;

            using(Process process=Process.GetCurrentProcess()) self=ReadProcessProof(process.Handle,process.Id);

            invocation=NewAccountNonce();

            responseKey=new byte[32];

            using(RandomNumberGenerator rng=RandomNumberGenerator.Create()) rng.GetBytes(responseKey);

            channel=CreateOwnedPipe("kovya-account-private-v1-"+invocation,identity,StartupHandshakeTimeoutMilliseconds,1,true);

            IAsyncResult pending=channel.BeginWaitForConnection(null,null);

            Stream discovery=Console.OpenStandardOutput();

            WriteAsciiLine(discovery,BuildIdentityLine(self,parentProof),startupDeadline);

            WriteAsciiLine(discovery,(managedSession?"KOVYA_ACCOUNT_PEER_V3\t":"KOVYA_ACCOUNT_PEER_V2\t")+invocation+"\t"+BitConverter.ToString(responseKey).Replace("-", "").ToLowerInvariant(),startupDeadline);

            if(!CompleteWaitForConnection(channel,pending,parent,startupDeadline,null)) throw new NativeFailure(65);

            connected=true;

            string begin=ReadAsciiLine(channel,128,startupDeadline);

            if(!FixedEquals(begin,(managedSession?"KOVYA_ACCOUNT_BEGIN_V3\t":"KOVYA_ACCOUNT_BEGIN_V2\t")+invocation+"\t"+(externalLockHeld?"external":"native"))) throw new NativeFailure(67);

            // Authenticate the process that initiated THIS connection. Stdio

            // discovery and knowledge of the invocation token confer no authority.

            VerifyConnectedPrivateParentClient(channel.SafePipeHandle.DangerousGetHandle(),parent,parentProof,identity);

            string boundHome=RuntimeBrokerHome(Process.GetCurrentProcess().MainModule.FileName);

            boundary=new KovyaAccountFileBoundary(boundHome,externalLockHeld);

            Dictionary<string,string> snapshot=boundary.ReadSnapshot();

            string releaseToken=NewAccountNonce();

            foreach(IntPtr handle in boundary.GuardHandles)

            {

                IntPtr copy;

                if(!DuplicateHandle(GetCurrentProcess(),handle,parent,out copy,0,false,2)) throw new NativeFailure(65);

                transferred.Add(copy);

            }

            Thread death=new Thread(delegate(){if(WaitForSingleObject(parent,UInt32.MaxValue)==WaitObject0) Environment.Exit(0);});

            death.IsBackground=true;death.Start();

#if KOVYA_MANAGED_RUNTIME

            if(managedSession) {

                bool witnessRejected=false;

                byte[] initial=Encoding.UTF8.GetBytes(RuntimeJson(new Dictionary<string,object>{{"release_token",releaseToken},{"ownership_mode",externalLockHeld?"external":"native"},{"documents",snapshot},{"witness_schema",externalLockHeld?null:CredentialWitnessSchema}}));

                published=true;

                try {AccountRpcWrite(channel,responseKey,invocation,0,1,initial);}finally{Clear(initial);}

                for(uint sequence=1;sequence<UInt32.MaxValue;sequence++) {

                    uint kind;byte[] request=AccountRpcRead(channel,responseKey,invocation,sequence,out kind),reply=null;

                    try {

                        RequireProcessAlive(parent,65);

                        if(kind==12) {

                            if(request.Length!=64 || !FixedEquals(Encoding.ASCII.GetString(request),releaseToken))throw new NativeFailure(67);

                            CloseAccountTransfers(parent,transferred);released=true;boundary.Dispose();boundary=null;

                            AccountRpcWrite(channel,responseKey,invocation,sequence,22,new byte[0]);return 0;

                        }

                        if(witnessRejected){AccountRpcWrite(channel,responseKey,invocation,sequence,23,new byte[0]);continue;}

                        if(kind==10 && request.Length!=0)throw new NativeFailure(67);

                        // Fresh admission before each operation; never required for release.

                        try {

                            if(!String.Equals(RuntimeBrokerHome(Process.GetCurrentProcess().MainModule.FileName),boundHome,StringComparison.OrdinalIgnoreCase))throw new NativeFailure(65);

                        } catch {AccountRpcWrite(channel,responseKey,invocation,sequence,23,new byte[0]);continue;}

                        if(kind==10) reply=Encoding.UTF8.GetBytes(RuntimeJson(boundary.ReadSnapshot()));

                        else if(kind==14 || kind==15)reply=CredentialWitnessOperation(boundary,kind,request,ReadWitnessCredential,out witnessRejected);

                        else if(kind==11) {

                            using(MemoryStream input=new MemoryStream(request,false))

                            using(MemoryStream output=new MemoryStream()) {

                                try {ExecuteCredential(input,output,parent,true);reply=output.ToArray();}

                                finally {Clear(output.GetBuffer());}

                            }

                        }

                        else throw new NativeFailure(67);

                        AccountRpcWrite(channel,responseKey,invocation,sequence,kind==10?20u:kind==11?21u:kind==14?25u:26u,reply);

                    } finally {Clear(request);Clear(reply);}

                }

                throw new NativeFailure(67);

            }

#endif

            string response=AccountResponseLine(responseKey,invocation,0,"STATE",RuntimeJson(new Dictionary<string,object>{{"release_token",releaseToken},{"ownership_mode",externalLockHeld?"external":"native"},{"documents",snapshot}}));

            byte[] bytes=Encoding.ASCII.GetBytes(response+"\n");

            if(bytes.Length>1024*1024) throw new NativeFailure(67);

            published=true; // Partial publication also leaves ownership ambiguous.

            try { channel.Write(bytes,0,bytes.Length);channel.Flush(); } finally { Clear(bytes); }

            // Callback duration is unrestricted. Parent death or pipe loss ends

            // the wait; neither stdin nor a replacement connection is consulted.

            StringBuilder command=new StringBuilder();

            for(;;)

            {

                int ch=channel.ReadByte();

                if(ch==10) break;

                if(ch<0 || ch>127 || ch==13 || command.Length>=96) throw new NativeFailure(67);

                command.Append((char)ch);

            }

            if(!FixedEquals(command.ToString(),"KOVYA_ACCOUNT_RELEASE_V1\t"+releaseToken)) throw new NativeFailure(67);

            CloseAccountTransfers(parent,transferred);released=true;

            boundary.Dispose();boundary=null;

            WriteAsciiLine(channel,AccountResponseLine(responseKey,invocation,1,"RELEASED",""),DeadlineAfter(StartupHandshakeTimeoutMilliseconds));

            return 0;

        }

        catch

        {

            if(published) throw;

            CloseAccountTransfers(parent,transferred);

            if(boundary!=null){boundary.Dispose();boundary=null;}

            // Refusal certifies no retained transfers. After connection, it is

            // sent only there, never via a second stdio authority channel.

            try {

#if KOVYA_MANAGED_RUNTIME

                if(connected && managedSession) AccountRpcWrite(channel,responseKey,invocation,0,2,new byte[0]);

                else

#endif

                if(connected) WriteAsciiLine(channel,AccountResponseLine(responseKey,invocation,0,"REFUSED",""),DeadlineAfter(StartupHandshakeTimeoutMilliseconds));

                else WriteAsciiLine(Console.OpenStandardOutput(),"KOVYA_ACCOUNT_REFUSED_V1",DeadlineAfter(StartupHandshakeTimeoutMilliseconds));

            }

            catch { }

            return 65;

        }

        finally

        {

            if(!published && !released) CloseAccountTransfers(parent,transferred);

            if(boundary!=null) boundary.Dispose();

            if(channel!=null) channel.Dispose();

            Clear(responseKey);

            // After publication the death watcher owns this pinned process handle.

            if(!published) CloseHandle(parent);

        }

    }





    private static void CloseAccountTransfers(IntPtr parent, List<IntPtr> handles,bool checkedClose=false)

    {

        for (int i = handles.Count - 1; i >= 0; i--)

        {

            IntPtr temporary;

            if (!DuplicateHandle(parent, handles[i], GetCurrentProcess(), out temporary, 0, false, 3))

                throw new NativeFailure(65);

            if(!CloseHandle(temporary) && checkedClose)throw new NativeFailure(65);handles.RemoveAt(i);

        }

    }

#endif



    // Runtime admission is synchronous on the mutex-owning thread. No Node

    // callback participates in publication. Native build/kill-point acceptance

    // is a separate release gate; this operation is not activated by hooks.

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]

    private static extern uint GetFinalPathNameByHandle(IntPtr handle, StringBuilder value, uint length, uint flags);



    private static object RuntimeSerializer()

    {

        // Framework assembly, loaded at runtime to preserve the existing C# 5

        // compiler invocation. No downloaded library or script execution.

        Type type = Type.GetType("System.Web.Script.Serialization.JavaScriptSerializer, System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35", true);

        object serializer = Activator.CreateInstance(type);

        type.GetProperty("MaxJsonLength").SetValue(serializer, 262144, null);

        type.GetProperty("RecursionLimit").SetValue(serializer, 32, null);

        return serializer;

    }

    private static string RuntimeJson(object value)

    {

        object serializer = RuntimeSerializer();

        return (string)serializer.GetType().GetMethod("Serialize", new Type[] { typeof(object) }).Invoke(serializer, new object[] { value });

    }

    private static Dictionary<string, object> RuntimeParse(string text)

    {

        if (text == null || text.Length > 262144) throw new IOException("runtime_input_invalid");

        object serializer = RuntimeSerializer();

        object value = serializer.GetType().GetMethod("DeserializeObject").Invoke(serializer, new object[] { text });

        Dictionary<string, object> result = value as Dictionary<string, object>;

        if (result == null) throw new IOException("runtime_input_invalid");

        return result;

    }

    private static string RuntimeString(Dictionary<string, object> value, string key)

    {

        object item;

        if (!value.TryGetValue(key, out item) || !(item is string)) throw new IOException("runtime_field_invalid");

        return (string)item;

    }

    private static void RuntimeOrdinary(string value, bool directory, bool missing)

    {

        string full = Path.GetFullPath(value), cursor = Path.GetPathRoot(full);

        foreach (string part in full.Substring(cursor.Length).Split(Path.DirectorySeparatorChar))

        {

            if (part.Length == 0) continue;

            cursor = Path.Combine(cursor, part);

            FileAttributes attributes;

            try { attributes = File.GetAttributes(cursor); }

            catch (FileNotFoundException) { if (missing) return; throw; }

            catch (DirectoryNotFoundException) { if (missing) return; throw; }

            if ((attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("runtime_reparse_path");

            bool isDirectory = (attributes & FileAttributes.Directory) != 0;

            if (isDirectory != (String.Equals(cursor, full, StringComparison.OrdinalIgnoreCase) ? directory : true))

                throw new IOException("runtime_path_type");

        }

    }

    private static string RuntimeCanonicalHome(string value)

    {

        if (!Path.IsPathRooted(value)) throw new IOException("runtime_home_relative");

        RuntimeOrdinary(value, true, true);

        string ancestor = Path.GetFullPath(value);

        List<string> tail = new List<string>();

        while (!Directory.Exists(ancestor)) { tail.Insert(0, Path.GetFileName(ancestor)); ancestor = Path.GetDirectoryName(ancestor); }

        IntPtr handle = CreateFile(ancestor, 0, 7, IntPtr.Zero, OpenExisting, 0x02000000, IntPtr.Zero);

        if (handle == InvalidHandleValue) throw new IOException("runtime_home_unavailable");

        try

        {

            StringBuilder buffer = new StringBuilder(32768);

            uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);

            if (length == 0 || length >= buffer.Capacity) throw new IOException("runtime_home_unavailable");

            ancestor = buffer.ToString();

            if (ancestor.StartsWith("\\\\?\\UNC\\", StringComparison.Ordinal)) ancestor = "\\\\" + ancestor.Substring(8);

            else if (ancestor.StartsWith("\\\\?\\", StringComparison.Ordinal)) ancestor = ancestor.Substring(4);

            foreach (string part in tail) ancestor = Path.Combine(ancestor, part);

            return ancestor;

        }

        finally { CloseHandle(handle); }

    }

    private static bool RuntimeVersion(string version)

    {

        return System.Text.RegularExpressions.Regex.IsMatch(version, @"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$");

    }

    private static string RuntimeRelative(string value)

    {

        // Release payload names are portable ASCII; home/source roots may be Unicode.

        if (!System.Text.RegularExpressions.Regex.IsMatch(value, @"^[A-Za-z0-9_.\-/]+$")) throw new IOException("runtime_payload_path");

        foreach (string part in value.Split('/')) if (part.Length == 0 || part == "." || part == ".." || part.EndsWith(".", StringComparison.Ordinal)) throw new IOException("runtime_payload_path");

        return value;

    }

    private static string RuntimeFileHash(string file)

    {

        RuntimeOrdinary(file, false, false);

        using (FileStream stream = File.OpenRead(file))

        using (SHA256 sha = SHA256.Create())

            return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();

    }

    private static List<Dictionary<string, object>> RuntimeFiles(Dictionary<string, object> payload)

    {

        object raw;

        if (!payload.TryGetValue("files", out raw) || !(raw is System.Collections.IEnumerable) || raw is string) throw new IOException("runtime_files");

        List<Dictionary<string, object>> files = new List<Dictionary<string, object>>();

        HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (object item in (System.Collections.IEnumerable)raw)

        {

            Dictionary<string, object> file = item as Dictionary<string, object>;

            if (file == null || files.Count >= 2048) throw new IOException("runtime_files");

            string name = RuntimeRelative(RuntimeString(file, "path"));

            string digest = RuntimeString(file, "sha256");

            if (!names.Add(name) || !System.Text.RegularExpressions.Regex.IsMatch(digest, "^[a-f0-9]{64}$")) throw new IOException("runtime_files");

            files.Add(file);

        }

        if (files.Count == 0) throw new IOException("runtime_files");

        files.Sort(delegate(Dictionary<string, object> a, Dictionary<string, object> b) { return String.CompareOrdinal(RuntimeString(a,"path"), RuntimeString(b,"path")); });

        return files;

    }

    private static void RuntimeVerify(string root, Dictionary<string, object> payload)

    {

        RuntimeVerify(root, payload, true);

    }

    private static void RuntimeVerify(string root, Dictionary<string, object> payload, bool verifyAllFiles)

    {

        RuntimeOrdinary(root, true, false);

        string version = RuntimeString(payload, "version");

        if (!RuntimeVersion(version)) throw new IOException("runtime_version");

        Dictionary<string, object> entries = payload["entrypoints"] as Dictionary<string, object>;

        if (entries == null || entries.Count != 4) throw new IOException("runtime_entries");

        List<Dictionary<string, object>> files = RuntimeFiles(payload);

        StringBuilder canonical = new StringBuilder("{\"version\":" + RuntimeJson(version) + ",\"files\":[");

        for (int i = 0; i < files.Count; i++)

        {

            string name = RuntimeString(files[i], "path"), digest = RuntimeString(files[i], "sha256");

            if (verifyAllFiles && !FixedEquals(RuntimeFileHash(Path.Combine(root, name.Replace('/', Path.DirectorySeparatorChar))), digest)) throw new IOException("runtime_payload_bytes");

            if (i != 0) canonical.Append(',');

            canonical.Append("{\"path\":").Append(RuntimeJson(name)).Append(",\"sha256\":").Append(RuntimeJson(digest)).Append('}');

        }

        canonical.Append("],\"entrypoints\":{");

        string[] roles = new string[] { "node", "broker", "native", "client" };

        for (int i = 0; i < roles.Length; i++)

        {

            string name = RuntimeRelative(RuntimeString(entries, roles[i]));

            if (!files.Exists(delegate(Dictionary<string, object> f) { return RuntimeString(f, "path") == name; })) throw new IOException("runtime_entry_not_admitted");

            if (i != 0) canonical.Append(',');

            canonical.Append(RuntimeJson(roles[i])).Append(':').Append(RuntimeJson(name));

        }

        canonical.Append("}}");

        if (!FixedEquals(Sha256Hex(canonical.ToString()), RuntimeString(payload, "digest"))) throw new IOException("runtime_payload_digest");

    }

    private static Dictionary<string, object> RuntimeReadRecord(string file)

    {

        RuntimeOrdinary(file, false, false);

        if (new FileInfo(file).Length > 262144) throw new IOException("runtime_record_size");

        return RuntimeParse(File.ReadAllText(file, new UTF8Encoding(false, true)));

    }

    private static void RuntimeWriteNew(string file, object value)

    {

        RuntimeOrdinary(Path.GetDirectoryName(file), true, false);

        string temporary = file + "." + Guid.NewGuid().ToString("N") + ".tmp";

        byte[] bytes = new UTF8Encoding(false, true).GetBytes(RuntimeJson(value) + "\n");

        using (FileStream stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }

        File.Move(temporary, file); // Never replace an existing current/admission.

    }



    // Native owner for the profile servicing rendezvous. The bootstrap is the

    // sole creator and calls CreateController only while owning M. Ordinary

    // runtime entry uses OpenExisting: disappearance never creates authority.

    // Raw handles deliberately have no finalizer: poison must retain the one

    // acquisition until its actual native thread exits, including CLR teardown.

    internal sealed class RuntimeSerialization : IDisposable

    {

        internal enum Result { Acquired, Abandoned, Timeout, Absent, Denied, Failed, Poisoned, Recursive }

        private static readonly object LocalGate = new object();

        private static readonly HashSet<uint> OwnedThreads = new HashSet<uint>();

        private static bool processPoisoned;

        private IntPtr handle;

        private readonly string home;

        private readonly List<IntPtr> directoryPins=new List<IntPtr>();

        private uint thread;

        private bool acquired, retained, recoveryRecorded;

        internal Result Outcome { get; private set; }

        internal bool Created { get; private set; }

        internal IntPtr NativeHandle { get { return handle; } }

        internal static string Name(string home) { return "Global\\Kovya.RuntimeSerialization.V1." + Sha256Hex(home.ToLowerInvariant()); }



        [DllImport("kernel32.dll", EntryPoint="CreateMutexW", CharSet=CharSet.Unicode, SetLastError=true)]

        private static extern IntPtr Create(ref SecurityAttributes attributes, bool owned, string name);

        [DllImport("kernel32.dll", EntryPoint="OpenMutexW", CharSet=CharSet.Unicode, SetLastError=true)]

        private static extern IntPtr Open(uint access, bool inherit, string name);

        [DllImport("kernel32.dll", SetLastError=true)]

        private static extern bool ReleaseMutex(IntPtr value);

        [DllImport("kernel32.dll")]

        private static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll")]

        internal static extern ulong GetTickCount64();

        [DllImport("kernel32.dll", SetLastError=true)]

        private static extern bool SetHandleInformation(IntPtr value,uint mask,uint flags);

        [DllImport("kernel32.dll", SetLastError=true)]

        private static extern bool GetHandleInformation(IntPtr value,out uint flags);

        [DllImport("advapi32.dll", SetLastError=true)]

        private static extern uint GetSecurityInfo(IntPtr value,int type,uint requested,out IntPtr owner,

            out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);

        [DllImport("advapi32.dll")]

        private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);

        [DllImport("kernel32.dll", EntryPoint="MoveFileExW", CharSet=CharSet.Unicode, SetLastError=true)]

        private static extern bool MoveFileEx(string from,string to,uint flags);

        [DllImport("kernel32.dll", SetLastError=true)]

        private static extern bool FlushFileBuffers(IntPtr value);



        private static string Sid { get { using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) return identity.User.Value; } }

        private static IntPtr Security()

        {

            IntPtr descriptor; uint bytes;

            if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:"+Sid+"D:P(A;;GA;;;"+Sid+")",1,out descriptor,out bytes))

                throw new IOException("runtime_owner_security");

            return descriptor;

        }

        internal static void CheckSecurity(IntPtr value,int type,bool directory=false)

        {

            IntPtr owner,group,dacl,sacl,descriptor;

            if(GetSecurityInfo(value,type,5,out owner,out group,out dacl,out sacl,out descriptor)!=0)

                throw new IOException("runtime_owner_security");

            try {

                byte[] bytes=new byte[GetSecurityDescriptorLength(descriptor)]; Marshal.Copy(descriptor,bytes,0,bytes.Length);

                var security=new System.Security.AccessControl.RawSecurityDescriptor(bytes,0);

                if(security.Owner==null || security.Owner.Value!=Sid || security.DiscretionaryAcl==null

                    || (security.ControlFlags & System.Security.AccessControl.ControlFlags.DiscretionaryAclProtected)==0

                    || security.DiscretionaryAcl.Count!=1) throw new IOException("runtime_owner_security");

                var ace=security.DiscretionaryAcl[0] as System.Security.AccessControl.CommonAce;

                if(ace==null || ace.IsCallback || ace.AceQualifier!=System.Security.AccessControl.AceQualifier.AccessAllowed

                    || ace.SecurityIdentifier.Value!=Sid || ace.AceFlags!=(directory

                        ? System.Security.AccessControl.AceFlags.ContainerInherit|System.Security.AccessControl.AceFlags.ObjectInherit

                        : System.Security.AccessControl.AceFlags.None))

                    throw new IOException("runtime_owner_security");

                int expected=type==6?0x1f0001:0x1f01ff;

                if(ace.AccessMask!=expected && ace.AccessMask!=unchecked((int)0x10000000)) throw new IOException("runtime_owner_security");

            } finally { LocalFree(descriptor); }

        }

        internal static void SealPhaseAudit(string home,string tuple,string header)

        {

            if(String.IsNullOrEmpty(home)||Encoding.ASCII.GetByteCount(header)>4096)throw new IOException("phase_audit_unavailable");

            string directory=Path.Combine(home,"state","broker"),full=Path.GetFullPath(directory),cursor=Path.GetPathRoot(full);

            var pins=new List<IntPtr>();

            try {

                var paths=new List<string>();paths.Add(cursor);

                foreach(string part in full.Substring(cursor.Length).Split(Path.DirectorySeparatorChar)){if(part.Length!=0){cursor=Path.Combine(cursor,part);paths.Add(cursor);}}

                foreach(string item in paths){

                    IntPtr h=CreateFile(item,0x00120080,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);if(h==InvalidHandleValue)throw new IOException("phase_audit_unavailable");pins.Add(h);NonInherited(h);

                    RuntimeMarkerInfo info;StringBuilder final=new StringBuilder(32768);uint length=GetFinalPathNameByHandle(h,final,(uint)final.Capacity,0);

                    if(!GetMarkerInfo(h,out info)||(info.Attributes&0x410)!=0x10||length==0||length>=final.Capacity||!String.Equals(final.ToString().Replace(@"\\?\","").TrimEnd('\\'),item.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))throw new IOException("phase_audit_unavailable");

                }

                CheckSecurity(pins[pins.Count-1],1,true);

                var acl=new System.Security.AccessControl.FileSecurity();using(var identity=WindowsIdentity.GetCurrent()){acl.SetOwner(identity.User);acl.SetAccessRuleProtection(true,false);acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(identity.User,System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));}

                byte[] record=new byte[4096],bytes=Encoding.ASCII.GetBytes(header);Buffer.BlockCopy(bytes,0,record,0,bytes.Length);

                using(var stream=new FileStream(Path.Combine(full,"phase-"+Sha256Hex(tuple)+".bin"),FileMode.CreateNew,System.Security.AccessControl.FileSystemRights.FullControl,FileShare.Read,4096,FileOptions.WriteThrough,acl)){

                    CheckSecurity(stream.SafeFileHandle.DangerousGetHandle(),1);stream.Write(record,0,record.Length);

                }

                Clear(record);Clear(bytes);

            } finally {for(int i=pins.Count-1;i>=0;--i)if(!CloseHandle(pins[i]))throw new IOException("phase_audit_unavailable");}

        }

        internal static void ValidateControllerMutex(IntPtr value) { CheckSecurity(value,6); }

        internal static void PrepareState(string home)

        {

            // Existing metadata directories are verified, never silently re-ACL'd.

            var security=new System.Security.AccessControl.DirectorySecurity();

            using(var identity=WindowsIdentity.GetCurrent()) {

                security.SetOwner(identity.User); security.SetAccessRuleProtection(true,false);

                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(identity.User,

                    System.Security.AccessControl.FileSystemRights.FullControl,

                    System.Security.AccessControl.InheritanceFlags.ContainerInherit|System.Security.AccessControl.InheritanceFlags.ObjectInherit,

                    System.Security.AccessControl.PropagationFlags.None,System.Security.AccessControl.AccessControlType.Allow));

            }

            // Parent-first provisioning is the sole creator for publication metadata.
            // Existing directories are checked, never re-ACL'd. Runtime and broker
            // share the exact directory DACL consumed by publicationSecurity.
            foreach(string state in new[]{Path.Combine(home,"state"),Path.Combine(home,"state","runtime"),Path.Combine(home,"state","broker")}) {
                RuntimeOrdinary(state,true,true);Directory.CreateDirectory(state,security);
                IntPtr directory=CreateFile(state,0x00120080,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
                if(directory==InvalidHandleValue)throw new IOException("runtime_owner_directory");
                try { CheckSecurity(directory,1,true); }
                finally {if(!CloseHandle(directory))throw new IOException("runtime_owner_close_failed");}
            }
        }

        private void PinPath(string path)

        {

            string full=Path.GetFullPath(path),cursor=Path.GetPathRoot(full);

            var paths=new List<string>();paths.Add(cursor);

            foreach(string part in full.Substring(cursor.Length).Split(Path.DirectorySeparatorChar)) {

                if(part.Length==0)continue;cursor=Path.Combine(cursor,part);paths.Add(cursor);

            }

            foreach(string directory in paths) {

                IntPtr value=CreateFile(directory,0x00120080,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);

                if(value==InvalidHandleValue)throw new IOException("runtime_owner_directory");

                directoryPins.Add(value);NonInherited(value);

                RuntimeMarkerInfo info;StringBuilder final=new StringBuilder(32768);

                uint length=GetFinalPathNameByHandle(value,final,(uint)final.Capacity,0);

                if(!GetMarkerInfo(value,out info) || (info.Attributes&0x410)!=0x10 || length==0 || length>=final.Capacity

                    || !String.Equals(final.ToString().Replace(@"\\?\","").TrimEnd('\\'),directory.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))

                    throw new IOException("runtime_owner_directory");

            }

            if(String.Equals(full,Path.Combine(home,"state","runtime"),StringComparison.OrdinalIgnoreCase))

                CheckSecurity(directoryPins[directoryPins.Count-1],1,true);

        }

        private static void NonInherited(IntPtr value)

        {

            uint flags;

            if(!SetHandleInformation(value,1,0) || !GetHandleInformation(value,out flags) || (flags&1)!=0)

                throw new IOException("runtime_owner_inheritance");

        }

        internal static RuntimeSerialization CreateController(string home,ulong deadline)

        { return new RuntimeSerialization(home,deadline,true); }

        internal static RuntimeSerialization OpenExisting(string home,ulong deadline)

        { return new RuntimeSerialization(home,deadline,false); }

        private RuntimeSerialization(string home,ulong deadline,bool controller)

        {

            this.home=home;

            thread=GetCurrentThreadId();

            lock(LocalGate) {

                if(processPoisoned) { Outcome=Result.Poisoned; return; }

                if(OwnedThreads.Contains(thread)) { Outcome=Result.Recursive; return; }

            }

            if(GetTickCount64()>deadline) { Outcome=Result.Timeout; return; }

            if(controller) {

                int createError=0; IntPtr security=Security();

                try {

                    SecurityAttributes attributes=new SecurityAttributes { Length=Marshal.SizeOf(typeof(SecurityAttributes)),SecurityDescriptor=security,InheritHandle=0 };

                    handle=Create(ref attributes,true,Name(home));

                    createError=Marshal.GetLastWin32Error();

                    Created=handle!=IntPtr.Zero && createError!=183;

                } finally { LocalFree(security); }

                if(handle==IntPtr.Zero) { Outcome=createError==2?Result.Absent:createError==5?Result.Denied:Result.Failed; return; }

            } else handle=Open(0x00120001,false,Name(home));

            if(handle==IntPtr.Zero) {

                int error=Marshal.GetLastWin32Error();

                Outcome=error==2?Result.Absent:error==5?Result.Denied:Result.Failed; return;

            }

            acquired=Created;

            try {

                NonInherited(handle); CheckSecurity(handle,6);

                uint result=0;

                if(!Created) {

                    ulong now=GetTickCount64();

                    if(now>deadline) { Outcome=Result.Timeout; return; }

                    result=WaitForSingleObject(handle,(uint)Math.Min(deadline-now,30000UL));

                    if(result!=0 && result!=0x80) { Outcome=result==0x102?Result.Timeout:Result.Failed; return; }

                    acquired=true;

                }

                lock(LocalGate) OwnedThreads.Add(thread);

                Outcome=result==0x80?Result.Abandoned:Result.Acquired;

                PinPath(Path.Combine(home,"state","runtime"));

                PinPath(Path.Combine(home,"runtime"));

                // Never turn a successful but late kernel wait into permission.

                if(GetTickCount64()>deadline && Outcome==Result.Acquired) { Release(); Outcome=Result.Timeout; }

            } catch { Dispose(); throw; }

        }

        internal void RequireOwned()

        {

            if(!acquired || retained || thread!=GetCurrentThreadId()) throw new IOException("runtime_owner_not_held");

            lock(LocalGate) if(processPoisoned) throw new IOException("runtime_owner_poisoned");

        }

        internal void Poison()

        {

            if(!acquired || thread!=GetCurrentThreadId()) throw new IOException("runtime_owner_not_held");

            lock(LocalGate) processPoisoned=true;

            retained=true; // No ReleaseMutex, CloseHandle, finalizer or reset.

        }

        internal void Release()

        {

            if(!acquired) return;

            if(retained || thread!=GetCurrentThreadId()) throw new IOException("runtime_owner_release_refused");

            if(Outcome==Result.Abandoned && !recoveryRecorded) { Poison(); throw new IOException("runtime_owner_refusal_not_recorded"); }

            try { CloseDirectoryPins(); } catch { Poison();throw; }

            if(!ReleaseMutex(handle)) { Poison(); throw new IOException("runtime_owner_release_failed"); }

            acquired=false; lock(LocalGate) OwnedThreads.Remove(thread);

        }

        public void Dispose()

        {

            if(retained) return;

            if(acquired) Release();

            CloseDirectoryPins();

            if(handle!=IntPtr.Zero) {

                if(!CloseHandle(handle)) throw new IOException("runtime_owner_close_failed");

                handle=IntPtr.Zero;

            }

        }

        private void CloseDirectoryPins()

        {

            for(int i=directoryPins.Count-1;i>=0;i--) {

                if(!CloseHandle(directoryPins[i])) throw new IOException("runtime_owner_close_failed");

                directoryPins.RemoveAt(i);

            }

        }

        internal void WriteRecord(string file,Dictionary<string,object> value) {
            if(!String.Equals(file,Path.Combine(home,"state","runtime","servicing.json"),StringComparison.OrdinalIgnoreCase)) throw new IOException("runtime_owner_record_path");
            WriteOwnedRecord(file,value);
        }
        internal void WriteSelectionRecord(string file,Dictionary<string,object> value) {
            if(!String.Equals(file,Path.Combine(home,"runtime","current"),StringComparison.OrdinalIgnoreCase)
                && !String.Equals(file,Path.Combine(home,"state","runtime","admission.json"),StringComparison.OrdinalIgnoreCase)) throw new IOException("runtime_owner_record_path");
            WriteOwnedRecord(file,value);
        }
        internal void WriteStartupRecord(Dictionary<string,object> value) {
            WriteOwnedRecord(Path.Combine(home,"state","runtime","startup-refusal.v1.json"),value);
        }
        private void WriteOwnedRecord(string file,Dictionary<string,object> value)
        {
            RequireOwned();

            string temporary=file+"."+Guid.NewGuid().ToString("N")+".tmp";

            try {

                RuntimeOrdinary(Path.GetDirectoryName(file),true,false); RuntimeOrdinary(file,false,true);

                string text=RuntimeJson(value)+"\n";

                byte[] bytes=new UTF8Encoding(false,true).GetBytes(text);

                var security=new System.Security.AccessControl.FileSecurity();

                using(var identity=WindowsIdentity.GetCurrent()) {

                    security.SetOwner(identity.User);security.SetAccessRuleProtection(true,false);

                    security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(identity.User,

                        System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));

                }

                using(FileStream stream=new FileStream(temporary,FileMode.CreateNew,

                    System.Security.AccessControl.FileSystemRights.Write|System.Security.AccessControl.FileSystemRights.ReadPermissions,

                    FileShare.None,4096,FileOptions.WriteThrough,security)) {

                    NonInherited(stream.SafeFileHandle.DangerousGetHandle());CheckSecurity(stream.SafeFileHandle.DangerousGetHandle(),1);

                    stream.Write(bytes,0,bytes.Length); stream.Flush(true);

                }

                if(!MoveFileEx(temporary,file,1|8)) throw new IOException("runtime_owner_record_replace");

                ReadRecord(file);

                if(File.ReadAllText(file,new UTF8Encoding(false,true))!=text) throw new IOException("runtime_owner_record_readback");

            } catch { Poison(); throw; }

        }

        internal void RecordAbandonment(string home)

        {

            RequireOwned();

            if(this.home!=home) { Poison();throw new IOException("runtime_owner_home"); }

            // Preserve the exact prior journal, including REMOVED/unknown state,

            // as an input to controller recovery. Never invent a clean generation.

            string file=Path.Combine(home,"state","runtime","servicing.json");

            Dictionary<string,object> previous=null;

            try { previous=ReadRecord(file); } catch(Exception error) {

                if(!(error is IOException || error is UnauthorizedAccessException || error is ArgumentException

                    || error is System.Reflection.TargetInvocationException)) { Poison(); throw; }

            }

            object oldState,oldSchema,oldHome;

            if(previous!=null && previous.TryGetValue("state",out oldState) && (oldState as string)=="RECOVERY_REQUIRED"

                && previous.TryGetValue("schema_version",out oldSchema) && (oldSchema as string)=="kovya.runtime-servicing.v1"

                && previous.TryGetValue("installation_root",out oldHome) && (oldHome as string)==home) {

                WriteRecord(file,previous);recoveryRecorded=true;return;

            }

            WriteRecord(file,new Dictionary<string,object> {

                {"schema_version","kovya.runtime-servicing.v1"},{"installation_root",home},

                {"owner_sid_hash",Sha256Hex(Sid)},{"state","RECOVERY_REQUIRED"},{"previous",previous}

            });

            recoveryRecorded=true;

        }

        internal static Dictionary<string,object> ReadRecord(string file)

        {

            RuntimeOrdinary(file,false,false);

            IntPtr value=CreateFile(file,0x80020000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);

            if(value==InvalidHandleValue)throw new IOException("runtime_owner_record_open");

            try {

                NonInherited(value);CheckSecurity(value,1);RuntimeMarkerInfo info;

                if(!GetMarkerInfo(value,out info) || (info.Attributes&0x410)!=0 || info.Links!=1

                    || info.SizeHigh!=0 || info.SizeLow>262144)throw new IOException("runtime_owner_record_invalid");

                using(var safe=new SafeFileHandle(value,false))

                using(var stream=new FileStream(safe,FileAccess.Read))

                using(var reader=new StreamReader(stream,new UTF8Encoding(false,true),false)) return RuntimeParse(reader.ReadToEnd());

            } finally { if(!CloseHandle(value))throw new IOException("runtime_owner_close_failed"); }

        }

        internal static IntPtr OpenWriteMarker(string file,string expected) {
            IntPtr value=CreateFile(file,0xC0020000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
            if(value==InvalidHandleValue) throw new IOException(Marshal.GetLastWin32Error()==32?"runtime_upgrade_busy":"runtime_marker_unavailable");
            try { if(HeldMarker(value,file)!=expected)throw new IOException("runtime_marker_invalid");return value; }
            catch {CloseHandle(value);throw;}
        }
        internal static string HeldMarker(IntPtr value,string file) {
            NonInherited(value);CheckSecurity(value,1);RuntimeMarkerInfo info;StringBuilder final=new StringBuilder(32768);
            uint length=GetFinalPathNameByHandle(value,final,(uint)final.Capacity,0);
            if(!GetMarkerInfo(value,out info)||(info.Attributes&0x410)!=0||info.Links!=1||info.SizeHigh!=0||info.SizeLow!=0
                ||length==0||length>=final.Capacity||!String.Equals(final.ToString().Replace(@"\\?\",""),file,StringComparison.OrdinalIgnoreCase))throw new IOException("runtime_marker_invalid");
            return info.Volume.ToString("x8")+":"+info.IndexHigh.ToString("x8")+info.IndexLow.ToString("x8");
        }

        internal static string Marker(string file,bool create)

        {

            IntPtr security=create?Security():IntPtr.Zero, value=IntPtr.Zero;

            try {

                // Native creation takes a non-inheritable, owner-only descriptor.

                if(create) {

                    SecurityAttributes attributes=new SecurityAttributes { Length=Marshal.SizeOf(typeof(SecurityAttributes)),SecurityDescriptor=security,InheritHandle=0 };

                    value=CreateMarker(file,0xC0020000,0,ref attributes,1,0x00200000,IntPtr.Zero);

                } else value=CreateFile(file,0x80020000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);

                if(value==InvalidHandleValue) throw new IOException("runtime_marker_unavailable");

                NonInherited(value); CheckSecurity(value,1);

                RuntimeMarkerInfo info;

                if(!GetMarkerInfo(value,out info) || (info.Attributes & (0x10|0x400))!=0 || info.Links!=1

                    || info.SizeHigh!=0 || info.SizeLow!=0) throw new IOException("runtime_marker_invalid");

                if(create && !FlushFileBuffers(value)) throw new IOException("runtime_marker_flush");

                return info.Volume.ToString("x8")+":"+info.IndexHigh.ToString("x8")+info.IndexLow.ToString("x8");

            } finally {

                if(security!=IntPtr.Zero) LocalFree(security);

                if(value!=IntPtr.Zero && value!=InvalidHandleValue && !CloseHandle(value)) throw new IOException("runtime_marker_close_failed");

            }

        }

        [StructLayout(LayoutKind.Sequential)]

        private struct RuntimeMarkerInfo {

            internal uint Attributes,CreatedLow,CreatedHigh,AccessLow,AccessHigh,WriteLow,WriteHigh,Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;

        }

        [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]

        private static extern IntPtr CreateMarker(string file,uint access,uint share,ref SecurityAttributes security,uint creation,uint flags,IntPtr template);

        [DllImport("kernel32.dll",EntryPoint="GetFileInformationByHandle",SetLastError=true)]

        private static extern bool GetMarkerInfo(IntPtr value,out RuntimeMarkerInfo info);

    }



    private static RuntimeSerialization RuntimeControllerSerialization(string home,int wait,bool abandonedController)

    {

        var serialization=RuntimeSerialization.CreateController(home,RuntimeSerialization.GetTickCount64()+(ulong)wait);

        try {

            if(serialization.Outcome==RuntimeSerialization.Result.Abandoned || (abandonedController && serialization.Outcome==RuntimeSerialization.Result.Acquired)) {

                serialization.RecordAbandonment(home);

                throw new IOException("runtime_servicing_recovery_required");

            }

            if(serialization.Outcome!=RuntimeSerialization.Result.Acquired)

                throw new IOException("runtime_serialization_"+serialization.Outcome.ToString().ToLowerInvariant());

            serialization.RequireOwned(); return serialization;

        } catch { serialization.Dispose(); throw; }

    }



    private static Dictionary<string,object> RuntimeServicingRead(string home,Dictionary<string,object> pointer) {
        return RuntimeServicingRead(home,pointer,IntPtr.Zero,IntPtr.Zero);
    }
    private static Dictionary<string,object> RuntimeServicingRead(string home,Dictionary<string,object> pointer,IntPtr lifetime,IntPtr work)
    {

        string state=Path.Combine(home,"state","runtime");

        var record=RuntimeSerialization.ReadRecord(Path.Combine(state,"servicing.json"));

        ulong generation;

        if(record.Count!=9 || RuntimeString(record,"schema_version")!="kovya.runtime-servicing.v1"

            || RuntimeString(record,"installation_root")!=home

            || RuntimeString(record,"state")!="COMMITTED"

            || !UInt64.TryParse(RuntimeString(record,"generation"),NumberStyles.None,CultureInfo.InvariantCulture,out generation)

            || generation==0 || generation.ToString(CultureInfo.InvariantCulture)!=RuntimeString(record,"generation")

            || !FixedEquals(RuntimeString(record,"owner_sid_hash"),ReadCurrentIdentity().UserSidHash)

            || RuntimeString(record,"version")!=RuntimeString(pointer,"version")

            || RuntimeString(record,"digest")!=RuntimeString(pointer,"digest")

            || RuntimeString(record,"lifetime_identity")!=(lifetime==IntPtr.Zero?RuntimeSerialization.Marker(Path.Combine(state,"lifetime.v1"),false):RuntimeSerialization.HeldMarker(lifetime,Path.Combine(state,"lifetime.v1")))

            || RuntimeString(record,"work_identity")!=(work==IntPtr.Zero?RuntimeSerialization.Marker(Path.Combine(state,"work.v1"),false):RuntimeSerialization.HeldMarker(work,Path.Combine(state,"work.v1"))))

            throw new IOException("runtime_servicing_recovery_required");

        return record;

    }

    private static Dictionary<string, object> RuntimePointer(Dictionary<string, object> payload)

    {

        return new Dictionary<string, object> { {"version",RuntimeString(payload,"version")},{"digest",RuntimeString(payload,"digest")} };

    }

    private static Dictionary<string, object> RuntimeExisting(string home, string runtime, string admission, string current)

    {

        Dictionary<string, object> record = RuntimeReadRecord(admission);

        if (record.Count!=5 || RuntimeString(record,"schema_version") != "kovya.plugin-runtime-admission.v2" || RuntimeString(record,"installation_root") != home) throw new IOException("incomplete_acquisition");

        Dictionary<string, object> payload = record["payload"] as Dictionary<string, object>;

        if (payload == null || !RuntimeVersion(RuntimeString(payload,"version"))) throw new IOException("incomplete_acquisition");

        TokenIdentity owner = ReadCurrentIdentity(); RequireOrdinaryIdentity(owner,65);

        if (!FixedEquals(RuntimeString(record,"owner_sid_hash"),owner.UserSidHash)) throw new IOException("incomplete_acquisition");

        RuntimeVerify(Path.Combine(runtime,RuntimeString(payload,"version")),payload);

        Dictionary<string, object> pointer = RuntimePointer(payload);

        if (File.Exists(current))

        {

            Dictionary<string, object> old = RuntimeReadRecord(current);

            if (old.Count!=2 || RuntimeString(old,"version") != RuntimeString(pointer,"version") || RuntimeString(old,"digest") != RuntimeString(pointer,"digest")) throw new IOException("incomplete_acquisition");

        }

        else throw new IOException("incomplete_acquisition");

        return pointer;

    }

    private static object[] RuntimeLeftovers(string runtime)

    {

        List<object> stages = new List<object>();

        if (!Directory.Exists(runtime)) return stages.ToArray();

        foreach (string directory in Directory.GetDirectories(runtime,"*.staging-*",SearchOption.TopDirectoryOnly))

        {

            if (stages.Count >= 128) break;

            FileAttributes attrs = File.GetAttributes(directory);

            string name = Path.GetFileName(directory);

            int split = name.IndexOf(".staging-",StringComparison.OrdinalIgnoreCase);

            if (split < 0) continue;

            string ver = name.Substring(0,split);

            if ((attrs & FileAttributes.ReparsePoint) != 0)

            {

                stages.Add(new Dictionary<string,object> { {"path",directory},{"version",ver},{"file_count",null},{"oldest_mtime",null},{"metadata_partial",true} });

                continue; // Report the entry without following the link.

            }

            int count = 0, inspected = 0; bool partial = false;

            DateTime oldest = Directory.GetLastWriteTimeUtc(directory);

            Stack<string> pending = new Stack<string>(); pending.Push(directory);

            while (pending.Count > 0 && inspected < 4096)

            {

                string parent = pending.Pop();

                foreach (string item in Directory.EnumerateFileSystemEntries(parent))

                {

                    if (++inspected > 4096) { partial = true; break; }

                    FileAttributes attributes = File.GetAttributes(item);

                    if ((attributes & FileAttributes.ReparsePoint) != 0) { partial = true; continue; }

                    DateTime modified = File.GetLastWriteTimeUtc(item); if (modified < oldest) oldest = modified;

                    if ((attributes & FileAttributes.Directory) != 0) pending.Push(item); else count++;

                }

            }

            partial = partial || pending.Count > 0;

            stages.Add(new Dictionary<string, object> { {"path",directory},{"version",ver},{"file_count",count},{"metadata_partial",partial},{"oldest_mtime",oldest.ToString("o",CultureInfo.InvariantCulture)} });

        }

        return stages.ToArray();

    }



    private static string RuntimeLaunchFile(string root, Dictionary<string, object> payload, string relative,bool verifyBytes=true)

    {

        RuntimeRelative(relative);

        List<Dictionary<string, object>> files = RuntimeFiles(payload);

        Dictionary<string, object> file = files.Find(delegate(Dictionary<string, object> f) { return RuntimeString(f,"path") == relative; });

        if (file == null) throw new IOException("runtime_entry_not_admitted");

        string result = Path.Combine(root,relative.Replace('/',Path.DirectorySeparatorChar));

        if (verifyBytes && !FixedEquals(RuntimeFileHash(result),RuntimeString(file,"sha256"))) throw new IOException("runtime_payload_bytes");

        return result;

    }

    private static bool RuntimeLaunchVersion(string value)

    {

        if (!RuntimeVersion(value)) return false;

        foreach (string part in value.Split('.'))

        {

            long number;

            if (!Int64.TryParse(part,out number) || number > 9007199254740991L) return false;

        }

        return true;

    }

    private static string RuntimeQuoteArgument(string value)

    {

        StringBuilder quoted = new StringBuilder("\""); int slashes = 0;

        foreach (char c in value)

        {

            if (c == '\\') { slashes++; continue; }

            if (c == '"') { quoted.Append('\\',slashes * 2 + 1); quoted.Append(c); slashes = 0; continue; }

            quoted.Append('\\',slashes); slashes = 0; quoted.Append(c);

        }

        quoted.Append('\\',slashes * 2); quoted.Append('"'); return quoted.ToString();

    }

    private static int RuntimeLaunchReport(string state, string reason, string stage="native_launch",bool diagnosticRecorded=false)

    {

        Console.Out.WriteLine(RuntimeJson(new Dictionary<string,object> {

            {"ok",false},{"state",state},{"reason",reason},{"stage",stage},

            {"systemMessage",reason=="runtime_missing"?"Kovya is not connected yet. Ask to connect Kovya.":"Kovya could not finish. I will diagnose the problem before proposing a repair."},
            {"diagnostic_recorded",diagnosticRecorded},

            {"saving","unverified"},{"recall","unverified"}

        }));

        return 1;

    }



    [StructLayout(LayoutKind.Sequential)]

    private struct RuntimeStartupInfo

    {

        public int cb; public IntPtr reserved, desktop, title;

        public uint x,y,xSize,ySize,xCount,yCount,fill,flags;

        public ushort show,reservedBytes; public IntPtr reservedPointer,stdin,stdout,stderr;

    }

    [StructLayout(LayoutKind.Sequential)]

    private struct RuntimeStartupInfoEx { public RuntimeStartupInfo startup; public IntPtr attributes; }

    [StructLayout(LayoutKind.Sequential)]

    private struct RuntimeProcessInfo { public IntPtr process,thread; public uint pid,tid; }

    [StructLayout(LayoutKind.Sequential)]

    private struct RuntimeJobBasic

    {

        public long processTime,jobTime; public uint flags;

        public UIntPtr minWorking,maxWorking; public uint activeProcesses;

        public UIntPtr affinity; public uint priority,scheduling;

    }

    [StructLayout(LayoutKind.Sequential)]

    private struct RuntimeJobExtended

    {

        public RuntimeJobBasic basic;

        public ulong readOps,writeOps,otherOps,readBytes,writeBytes,otherBytes;

        public UIntPtr processMemory,jobMemory,peakProcessMemory,peakJobMemory;

    }

    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]

    private static extern IntPtr CreateJobObject(IntPtr attributes,string name);

    [DllImport("kernel32.dll",SetLastError=true)]

    private static extern bool SetInformationJobObject(IntPtr job,int kind,ref RuntimeJobExtended info,uint length);

    [DllImport("kernel32.dll",SetLastError=true)]

    private static extern bool QueryInformationJobObject(IntPtr job,int kind,out RuntimeJobExtended info,uint length,IntPtr returned);

    [DllImport("kernel32.dll",SetLastError=true)]

    private static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool present);

    [DllImport("kernel32.dll",SetLastError=true)]

    private static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,uint flags,ref IntPtr size);

    [DllImport("kernel32.dll",SetLastError=true)]

    private static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);

    [DllImport("kernel32.dll")]

    private static extern void DeleteProcThreadAttributeList(IntPtr list);

    [DllImport("kernel32.dll",SetLastError=true)]

    private static extern bool DuplicateHandle(IntPtr sourceProcess,IntPtr source,IntPtr targetProcess,out IntPtr target,uint access,bool inherit,uint options);

    [DllImport("kernel32.dll",SetLastError=true)]

    private static extern IntPtr GetStdHandle(int kind);

    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]

    private static extern bool CreateProcess(string application,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,

        bool inherit,uint flags,IntPtr environment,string directory,ref RuntimeStartupInfoEx startup,out RuntimeProcessInfo result);

    [DllImport("kernel32.dll",SetLastError=true)]

    private static extern bool GetExitCodeProcess(IntPtr process,out uint code);



    private static Dictionary<string,object> RuntimeScopeProof(IntPtr process,int pid)

    {

        bool inJob;

        if (!IsProcessInJob(process,IntPtr.Zero,out inJob)) throw new IOException("broker_scope_unknown");

        ProcessProof proof = ReadProcessProof(process,pid);

        return new Dictionary<string,object> {

            {"broker_scope",inJob ? "harness_session" : "machine"},{"pid",pid},

            {"process_creation_filetime",proof.CreationFileTime.ToString(CultureInfo.InvariantCulture)},

            {"image_path_sha256",proof.ImagePathHash}

        };

    }

    // Profile startup custody is owned at the actual native CreateProcess boundary.

    // It does not mint a public request ticket or authorize credential work.

    internal static class RuntimeProfileChild

    {

        internal static ulong Deadline;

        internal static bool IdleAccount,ResidentHost;

        private static bool residentAccount;

        private static IntPtr activation;

        internal static readonly object AccountGate=new object();

        internal static bool AccountLease;

        private static bool initialized;

        private static ulong identityDeadline,instanceNonce,lastAdoption,adoption,accountDeadline;

        private static IntPtr controlRead,controlWrite,revocation,profileOwner,parentOwner;

        [ThreadStatic] private static ulong capturedAdoption;

        private static string selectedRoot,selectedDigest;

        private static uint selectedWorkVolume;

        private static ulong selectedWorkId;

        private const ulong ControlMagic=0x3150434159564f4bUL;

        internal static ulong AccountDeadline {get {return ResidentHost?0:(IdleAccount?accountDeadline:Deadline);}}

        internal static void CaptureAccountWork(){capturedAdoption=adoption;}

        internal static void ClearCapturedWork(){capturedAdoption=0;}

        internal static void RequireAccountWork() {

            ulong d=AccountDeadline,now=RuntimeSerialization.GetTickCount64();

            if(d==0||now>=d||d-now>1000)throw new IOException("profile_work_required");

            if(IdleAccount&&(adoption==0||capturedAdoption!=adoption||revocation==IntPtr.Zero

                ||WaitForSingleObject(revocation,0)!=0x102||WaitForSingleObject(parentOwner,0)!=0x102))

                throw new IOException("profile_work_revoked");

        }

        internal static int IdentityBudget(int maximum) {

            ulong now=RuntimeSerialization.GetTickCount64();

            if(!IdleAccount||now>=identityDeadline||identityDeadline-now>(residentAccount?3000UL:30000UL))throw new IOException("profile_idle_startup_expired");

            return (int)Math.Min((ulong)maximum,identityDeadline-now);

        }

        private static void ControlReply(Stream output,ulong opcode,ulong sequence) {

            byte[] bytes=new byte[72];ulong[] values={ControlMagic,opcode,sequence,0,0,0,0,instanceNonce,0};

            for(int i=0;i<values.Length;i++)Buffer.BlockCopy(BitConverter.GetBytes(values[i]),0,bytes,i*8,8);

            output.Write(bytes,0,bytes.Length);output.Flush();Clear(bytes);

        }

        private static void Grant(ulong[] frame) {

            ulong now=RuntimeSerialization.GetTickCount64(),d=frame[4];

            if(adoption!=0||AccountLease||frame[2]<=lastAdoption||frame[2]==0||frame[3]==0||d<=now||d-now>1000

                ||frame[5]!=selectedWorkVolume||frame[6]!=selectedWorkId||frame[8]==0)throw new IOException("profile_account_grant");

            IntPtr signal=new IntPtr(checked((long)frame[8]));RuntimeProfileStartup.NonInherited(signal);

            try {

                if(WaitForSingleObject(parentOwner,0)!=0x102||WaitForSingleObject(signal,0)!=0x102)throw new IOException("profile_account_grant");

                using(var owner=RuntimeSerialization.OpenExisting(Home,d)) {

                    if(owner.Outcome==RuntimeSerialization.Result.Abandoned){owner.RecordAbandonment(Home);throw new IOException("runtime_servicing_recovery_required");}

                    if(owner.Outcome!=RuntimeSerialization.Result.Acquired||!SameObject(profileOwner,owner.NativeHandle))throw new IOException("profile_child_owner_object");

                    var current=RuntimeReadRecord(Path.Combine(Home,"runtime","current"));var servicing=RuntimeServicingRead(Home,current);

                    var admission=RuntimeReadRecord(Path.Combine(Home,"state","runtime","admission.json"));var payload=admission["payload"] as Dictionary<string,object>;

                    if(RuntimeString(servicing,"generation")!=Generation||RuntimeString(servicing,"digest")!=selectedDigest

                        ||payload==null||RuntimeString(payload,"digest")!=selectedDigest

                        ||!String.Equals(selectedRoot,Path.Combine(Home,"runtime",RuntimeString(current,"version")),StringComparison.OrdinalIgnoreCase))throw new IOException("profile_child_selection");

                    // Parent Work.r remains the servicing fence. This checked open

                    // validates identity only and is closed before the grant ACK.

                    IntPtr probe=CreateFile(Path.Combine(Home,"state","runtime","work.v1"),0x80020000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);

                    if(probe==InvalidHandleValue)throw new IOException("profile_child_work_identity");

                    try {Info info;StringBuilder final=new StringBuilder(32768);uint n=GetFinalPathNameByHandle(probe,final,(uint)final.Capacity,0);

                        if(!FileInfo(probe,out info)||info.volume!=selectedWorkVolume||(((ulong)info.idHigh<<32)|info.idLow)!=selectedWorkId

                            ||(info.attributes&0x410)!=0||info.links!=1||info.sizeHigh!=0||info.sizeLow!=0||n==0||n>=final.Capacity

                            ||!String.Equals(final.ToString().Replace(@"\\?\",""),Path.Combine(Home,"state","runtime","work.v1"),StringComparison.OrdinalIgnoreCase)

                            ||RuntimeString(servicing,"work_identity")!=info.volume.ToString("x8")+":"+info.idHigh.ToString("x8")+info.idLow.ToString("x8"))throw new IOException("profile_child_work_identity");

                    }finally{if(!CloseHandle(probe))throw new IOException("profile_child_work_close");}

                }

                now=RuntimeSerialization.GetTickCount64();if(now>=d||d-now>1000||WaitForSingleObject(signal,0)!=0x102)throw new IOException("profile_account_grant");

                revocation=signal;signal=IntPtr.Zero;accountDeadline=d;adoption=frame[2];lastAdoption=adoption;

            } finally {if(signal!=IntPtr.Zero&&!CloseHandle(signal))throw new IOException("profile_account_signal_close");}

        }

        internal static void StartAccountControl() {

            if(!IdleAccount)return;

            IdentityBudget(1);

            Thread control=new Thread(delegate(){

                try {

                    using(var input=new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(controlRead,false),FileAccess.Read,72,false))

                    using(var output=new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(controlWrite,false),FileAccess.Write,72,false)) {

                        ControlReply(output,1,0);

                        for(;;){byte[] bytes=new byte[72];int at=0;while(at<bytes.Length){int n=input.Read(bytes,at,bytes.Length-at);if(n==0)throw new IOException("profile_account_control_eof");at+=n;}

                            ulong[] frame=new ulong[9];for(int i=0;i<9;i++)frame[i]=BitConverter.ToUInt64(bytes,i*8);Clear(bytes);

                            if(frame[0]!=ControlMagic||frame[7]!=instanceNonce)throw new IOException("profile_account_control_binding");

                            lock(AccountGate){

                                if(frame[1]==2){Grant(frame);ControlReply(output,3,adoption);}

                                else if(frame[1]==4){

                                    if(adoption==0||frame[2]!=adoption||AccountLease||WaitForSingleObject(revocation,0)!=0)throw new IOException("profile_account_release_uncertain");

                                    #if KOVYA_PROFILE_ACCOUNT_TEST

                                    if(File.Exists(Path.Combine(Home,"state","runtime","test-detach-close")))throw new IOException("test_account_signal_close");

#endif

                                    if(!CloseHandle(revocation))throw new IOException("profile_account_signal_close");revocation=IntPtr.Zero;accountDeadline=0;adoption=0;

                                    ControlReply(output,5,frame[2]);

                                }else throw new IOException("profile_account_control_opcode");

                            }

                        }

                    }

                }catch {Environment.Exit(70);}

            });control.IsBackground=true;control.Start();

        }

        private static IntPtr startupWork;

        internal static string Home,Generation;

        internal static readonly List<IntPtr> References=new List<IntPtr>();

        [StructLayout(LayoutKind.Sequential)]

        private struct Info { internal uint attributes,c0,c1,a0,a1,w0,w1,volume,sizeHigh,sizeLow,links,idHigh,idLow; }

        [DllImport("kernel32.dll",EntryPoint="MapViewOfFile",SetLastError=true)]

        private static extern IntPtr Map(IntPtr mapping,uint access,uint high,uint low,UIntPtr length);

        [DllImport("kernel32.dll",EntryPoint="UnmapViewOfFile")]

        private static extern bool Unmap(IntPtr address);

        [DllImport("kernelbase.dll",EntryPoint="CompareObjectHandles",SetLastError=true)]

        private static extern bool SameObject(IntPtr first,IntPtr second);

        [DllImport("kernel32.dll",EntryPoint="GetFileInformationByHandle",SetLastError=true)]

        private static extern bool FileInfo(IntPtr handle,out Info info);

        [DllImport("kernel32.dll",EntryPoint="GetProcessId")]

        private static extern uint ProcessId(IntPtr handle);

        private static IntPtr Handle(Dictionary<string,object> value,string key)

        {long number;if(!Int64.TryParse(RuntimeString(value,key),NumberStyles.None,CultureInfo.InvariantCulture,out number)||number<=0)throw new IOException("profile_child_handle");var h=new IntPtr(number);RuntimeProfileStartup.NonInherited(h);return h;}

        internal static void Initialize(string command="")

        {

            if(initialized)throw new IOException("profile_child_duplicate");

            long mapping;if(!Int64.TryParse(Environment.GetEnvironmentVariable("KOVYA_PROFILE_WORK_HANDOFF"),out mapping)||mapping<=0)throw new IOException("profile_child_custody_required");

            IntPtr map=new IntPtr(mapping);RuntimeProfileStartup.NonInherited(map);IntPtr view=Map(map,4,0,0,new UIntPtr(262144));

            if(view==IntPtr.Zero)throw new IOException("profile_child_mapping");Dictionary<string,object> value;

            try {int length=Marshal.ReadInt32(view);if(length<1||length>262140)throw new IOException("profile_child_mapping");byte[] bytes=new byte[length];Marshal.Copy(IntPtr.Add(view,4),bytes,0,length);value=RuntimeParse(new UTF8Encoding(false,true).GetString(bytes));}

            finally {Unmap(view);}

            view=Map(map,2,0,0,UIntPtr.Zero);if(view!=IntPtr.Zero){Unmap(view);throw new IOException("profile_child_mapping_writable");}

            string schema=RuntimeString(value,"schema_version");IdleAccount=schema=="kovya.profile-idle-account.v1";ResidentHost=schema=="kovya.profile-resident-host.v1";

            if((!IdleAccount&&!ResidentHost&&schema!="kovya.profile-work.v1")||(IdleAccount&&command!="account-worker")||(ResidentHost&&command!="host"))throw new IOException("profile_child_schema");

            if(IdleAccount){string kind=value.ContainsKey("startup_kind")?RuntimeString(value,"startup_kind"):"setup";if(kind!="setup"&&kind!="resident")throw new IOException("profile_child_purpose");residentAccount=kind=="resident";}

            string self=Process.GetCurrentProcess().MainModule.FileName,root=Path.GetFullPath(Path.Combine(Path.GetDirectoryName(self),"..","..",".."));

            Home=RuntimeCanonicalHome(RuntimeString(value,"home"));string selected=RuntimeString(value,"root");

            if(!String.Equals(root,selected,StringComparison.OrdinalIgnoreCase)||!String.Equals(self,Path.Combine(root,"connector","claude-code","client","kovya_windows_broker_native.exe"),StringComparison.OrdinalIgnoreCase))throw new IOException("profile_child_role");

            ulong workCeiling=KovyaRequestBudget.WarmWorkMs;
            if(!IdleAccount&&!ResidentHost&&value.ContainsKey("budget_class")){string budgetClass=RuntimeString(value,"budget_class");if(budgetClass!="warm"&&budgetClass!="cold")throw new IOException("profile_child_deadline");if(budgetClass=="cold"){if(command!="start-broker")throw new IOException("profile_child_purpose");workCeiling=KovyaRequestBudget.ColdPathWorkMs;}}
            ulong d;if(!UInt64.TryParse(RuntimeString(value,"deadline_tick64"),NumberStyles.None,CultureInfo.InvariantCulture,out d)||d<=RuntimeSerialization.GetTickCount64()||d-RuntimeSerialization.GetTickCount64()>(ResidentHost||residentAccount?3000UL:(IdleAccount?30000UL:workCeiling)))throw new IOException("profile_child_deadline");

            var identity=ReadCurrentIdentity();RequireOrdinaryIdentity(identity,65);if(identity.UserSidHash!=RuntimeString(value,"owner_sid_hash"))throw new IOException("profile_child_owner");

            IntPtr parent=Handle(value,"parent");int pid=Convert.ToInt32(value["parent_pid"]);

            if(GetParentProcessId(Process.GetCurrentProcess().Id)!=pid||ProcessId(parent)!=(uint)pid||WaitForSingleObject(parent,0)!=0x102)throw new IOException("profile_child_parent");

            var proof=ReadProcessProof(parent,pid);RequireOrdinaryIdentity(proof.Identity,65);

            if(proof.Identity.UserSidHash!=identity.UserSidHash||proof.ImagePathHash!=Sha256Hex(NormalizeImagePath(Path.Combine(root,"runtime","node","node.exe"))))throw new IOException("profile_child_parent");

            IntPtr s=Handle(value,"s"),l=Handle(value,"l"),r=(IdleAccount||ResidentHost)?IntPtr.Zero:Handle(value,"r");

            using(var owner=RuntimeSerialization.OpenExisting(Home,d)) {

                if(owner.Outcome==RuntimeSerialization.Result.Abandoned){owner.RecordAbandonment(Home);throw new IOException("runtime_servicing_recovery_required");}

                if(owner.Outcome!=RuntimeSerialization.Result.Acquired||!SameObject(s,owner.NativeHandle))throw new IOException("profile_child_owner_object");

                var current=RuntimeReadRecord(Path.Combine(Home,"runtime","current"));var servicing=RuntimeServicingRead(Home,current);

                if(RuntimeString(servicing,"generation")!=RuntimeString(value,"generation")||RuntimeString(servicing,"digest")!=RuntimeString(value,"payload_digest")

                    ||!String.Equals(root,Path.Combine(Home,"runtime",RuntimeString(current,"version")),StringComparison.OrdinalIgnoreCase))throw new IOException("profile_child_selection");

                var admission=RuntimeReadRecord(Path.Combine(Home,"state","runtime","admission.json"));var payload=admission["payload"] as Dictionary<string,object>;

                if(payload==null||RuntimeString(payload,"digest")!=RuntimeString(value,"payload_digest")||RuntimeString(admission,"owner_sid_hash")!=identity.UserSidHash||RuntimeString(admission,"installation_root")!=Home)throw new IOException("profile_child_selection");

                var paths=new HashSet<string>(StringComparer.OrdinalIgnoreCase);bool foundL=false,foundR=false;int count=0;

                foreach(object raw in (System.Collections.IEnumerable)value["guards"]) {

                    var record=raw as Dictionary<string,object>;if(record==null||++count>4096)throw new IOException("profile_child_guards");

                    IntPtr h=Handle(record,"handle");string path=RuntimeString(record,"path");Info info;StringBuilder final=new StringBuilder(32768);uint n=GetFinalPathNameByHandle(h,final,(uint)final.Capacity,0);

                    if(!FileInfo(h,out info)||(info.attributes&0x400)!=0||((info.attributes&0x10)==0&&info.links!=1)||n==0||n>=final.Capacity

                        ||!String.Equals(final.ToString().Replace(@"\\?\",""),path,StringComparison.OrdinalIgnoreCase)||!paths.Add(path)

                        ||Convert.ToUInt32(record["volume"])!=info.volume||RuntimeString(record,"file_id")!=(((ulong)info.idHigh<<32)|info.idLow).ToString(CultureInfo.InvariantCulture))throw new IOException("profile_child_guard");

                    if(h==l||h==r){string kind=h==l?"lifetime":"work";string id=info.volume.ToString("x8")+":"+info.idHigh.ToString("x8")+info.idLow.ToString("x8");

                        if((info.attributes&0x410)!=0||info.sizeHigh!=0||info.sizeLow!=0||id!=RuntimeString(servicing,kind+"_identity")||!String.Equals(path,Path.Combine(Home,"state","runtime",kind+".v1"),StringComparison.OrdinalIgnoreCase))throw new IOException("profile_child_marker");

                        if(h==l)foundL=true;else foundR=true;

                    }

                    References.Add(h);

                }

                if(!foundL||(!IdleAccount&&!ResidentHost&&!foundR)||l==r)throw new IOException("profile_child_markers");

                foreach(var file in RuntimeFiles(payload)) {

                    string target=Path.Combine(root,RuntimeString(file,"path").Replace('/',Path.DirectorySeparatorChar));

                    for(;;){if(!paths.Contains(target))throw new IOException("profile_child_coverage");string up=Path.GetDirectoryName(target);if(up==null)break;target=up;}

                }

                RuntimeVerify(root,payload,false);RuntimeProfileStartup.CheckDeadline(d);

                References.Add(s);References.Add(parent);References.Add(map);Generation=RuntimeString(value,"generation");startupWork=r;

                if(IdleAccount){

                    if(value.ContainsKey("r"))throw new IOException("profile_idle_work_authority");

                    identityDeadline=d;instanceNonce=UInt64.Parse(RuntimeString(value,"instance_nonce"),CultureInfo.InvariantCulture);

                    if(instanceNonce==0)throw new IOException("profile_account_instance");

                    controlRead=Handle(value,"control_read");controlWrite=Handle(value,"control_write");

                    References.Add(controlRead);References.Add(controlWrite);profileOwner=s;parentOwner=parent;selectedRoot=root;selectedDigest=RuntimeString(value,"payload_digest");

                    selectedWorkVolume=Convert.ToUInt32(value["work_volume"]);selectedWorkId=UInt64.Parse(RuntimeString(value,"work_id"),CultureInfo.InvariantCulture);

                    Deadline=0;

                }else {Deadline=d;if(ResidentHost){if(value.ContainsKey("r"))throw new IOException("profile_host_work_authority");activation=Handle(value,"activation");References.Add(activation);parentOwner=parent;}}

                initialized=true;

            }

            Environment.SetEnvironmentVariable("KOVYA_PROFILE_WORK_HANDOFF",null);

        }

        // Only RunHost calls this, after authenticating its private parent. The

        // transport retains lifetime/code custody but cannot carry startup Work

        // into its idle listening lifetime or use it for credential operations.

        internal static int HostStartupBudget(int maximum) {

            ulong now=RuntimeSerialization.GetTickCount64();

            if(!ResidentHost||now>=Deadline||Deadline-now>3000)throw new IOException("profile_resident_startup_expired");

            return (int)Math.Min((ulong)maximum,Deadline-now);

        }

        internal static void AwaitResidentActivation() {

            if(!ResidentHost)return;

            if(WaitForSingleObject(activation,(uint)HostStartupBudget(3000))!=0||WaitForSingleObject(parentOwner,0)!=0x102)throw new IOException("profile_resident_activation");

            RuntimeProfileStartup.CheckDeadline(Deadline);

        }

        internal static void CompleteHostStartup()

        {

            RuntimeProfileStartup.CheckDeadline(Deadline);

            if(ResidentHost){if(activation==IntPtr.Zero||WaitForSingleObject(activation,0)!=0)throw new IOException("profile_resident_activation");Deadline=0;return;}

            if(startupWork==IntPtr.Zero || !References.Contains(startupWork))throw new IOException("profile_host_work_required");

            if(!CloseHandle(startupWork))throw new IOException("profile_host_work_close");

            References.Remove(startupWork);startupWork=IntPtr.Zero;Deadline=0;

        }

    }



    internal sealed class RuntimeProfileStartup : IDisposable

    {

        private static readonly object CreationGate=new object();

        private RuntimeSerialization owner;

        private bool creationHeld, transferred;

        private Mutex controller;

        private bool controllerHeld;

        private readonly List<IntPtr> pins=new List<IntPtr>();

        private readonly List<Dictionary<string,object>> guards=new List<Dictionary<string,object>>();

        private readonly string home,root;

        private readonly ulong deadline;

        private readonly bool setupJob,residentRole;

        private readonly string accountPurpose;

        private Dictionary<string,object> servicing,payload;

        private IntPtr lifetime,work,startupAck;

        [DllImport("kernel32.dll",SetLastError=true)]

        private static extern bool CreatePipe(out IntPtr read,out IntPtr write,ref SecurityAttributes security,uint size);

        [DllImport("kernel32.dll",SetLastError=true)]

        private static extern bool PeekNamedPipe(IntPtr pipe,IntPtr buffer,uint size,IntPtr read,out uint available,IntPtr left);

        [DllImport("kernel32.dll",EntryPoint="ReadFile",SetLastError=true)]

        private static extern bool ReadAck(IntPtr pipe,byte[] buffer,uint count,out uint read,IntPtr overlapped);

        [StructLayout(LayoutKind.Sequential)]

        private struct Info { internal uint attributes,createdLow,createdHigh,accessLow,accessHigh,writeLow,writeHigh,volume,sizeHigh,sizeLow,links,idHigh,idLow; }

        [DllImport("kernel32.dll",EntryPoint="GetFileInformationByHandle",SetLastError=true)]

        private static extern bool FileInfo(IntPtr value,out Info info);

        [DllImport("kernel32.dll",EntryPoint="SetHandleInformation",SetLastError=true)]

        private static extern bool Flags(IntPtr value,uint mask,uint flags);

        [DllImport("kernel32.dll",EntryPoint="GetHandleInformation",SetLastError=true)]

        private static extern bool GetFlags(IntPtr value,out uint flags);

        [DllImport("kernel32.dll",EntryPoint="CreateFileMappingW",CharSet=CharSet.Unicode,SetLastError=true)]

        private static extern IntPtr CreateMapping(IntPtr file,IntPtr security,uint protection,uint high,uint low,string name);

        [DllImport("kernel32.dll",EntryPoint="MapViewOfFile",SetLastError=true)]

        private static extern IntPtr Map(IntPtr mapping,uint access,uint high,uint low,UIntPtr length);

        [DllImport("kernel32.dll",EntryPoint="UnmapViewOfFile")]

        private static extern bool Unmap(IntPtr view);

        internal static void CheckDeadline(ulong value) { if(RuntimeSerialization.GetTickCount64()>=value)throw new IOException("runtime_startup_timeout"); }

        internal static void NonInherited(IntPtr value) { uint flags;if(!Flags(value,1,0)||!GetFlags(value,out flags)||(flags&1)!=0)throw new IOException("runtime_custody_inheritance"); }

        private static string Identity(Info info) { return info.volume.ToString("x8")+":"+info.idHigh.ToString("x8")+info.idLow.ToString("x8"); }

        private IntPtr Hold(string path,bool directory)

        {

            // Directory pins permit child replacement; denying delete sharing still pins the directory.

            // Immutable files, including L/R, retain read-only sharing.

            IntPtr value=CreateFile(path,0x80020000,directory?3u:1u,IntPtr.Zero,3,directory?0x02200000u:0x00200000u,IntPtr.Zero);

            if(value==InvalidHandleValue)throw new IOException("runtime_custody_open");

            pins.Add(value);NonInherited(value);Info info;StringBuilder final=new StringBuilder(32768);

            uint length=GetFinalPathNameByHandle(value,final,(uint)final.Capacity,0);

            if(!FileInfo(value,out info) || (info.attributes&0x410)!=(directory?0x10u:0u)

                || (!directory&&info.links!=1) || length==0 || length>=final.Capacity

                || !String.Equals(final.ToString().Replace(@"\\?\","").TrimEnd('\\'),path.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))

                throw new IOException("runtime_custody_path");

            guards.Add(new Dictionary<string,object>{{"handle",value.ToInt64().ToString(CultureInfo.InvariantCulture)},

                {"path",path},{"volume",info.volume},{"file_id",(((ulong)info.idHigh<<32)|info.idLow).ToString(CultureInfo.InvariantCulture)}});

            return value;

        }

        private RuntimeSerialization Open(string home,ulong deadline,bool cold)

        {

            RuntimeSerialization value=RuntimeSerialization.OpenExisting(home,deadline);

            if(value.Outcome==RuntimeSerialization.Result.Absent && cold) {

                value.Dispose();value=null;

                var security=new System.Security.AccessControl.MutexSecurity();

                using(var identity=WindowsIdentity.GetCurrent()) {

                    security.SetOwner(identity.User);security.SetAccessRuleProtection(true,false);

                    security.AddAccessRule(new System.Security.AccessControl.MutexAccessRule(identity.User,System.Security.AccessControl.MutexRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));

                }

                bool created,held=false,abandoned=false;

                controller=new Mutex(false,"Global\\Kovya.RuntimeAdmission."+Sha256Hex(home.ToLowerInvariant()),out created,security);

                {

                    try {

                        RuntimeSerialization.ValidateControllerMutex(controller.SafeWaitHandle.DangerousGetHandle());CheckDeadline(deadline);

                        ulong now=RuntimeSerialization.GetTickCount64();

                        try { held=controller.WaitOne((int)(now<deadline?Math.Min(deadline-now,setupJob?30000UL:KovyaRequestBudget.OrdinaryStartupMs):0)); }

                        catch(AbandonedMutexException) { held=true;abandoned=true; }

                        if(!held)throw new IOException("runtime_startup_timeout");

                        // Only this verified cold bootstrap, under M, creates S.

                        value=RuntimeSerialization.CreateController(home,deadline);

                        if(abandoned && (value.Outcome==RuntimeSerialization.Result.Acquired || value.Outcome==RuntimeSerialization.Result.Abandoned)) {

                            value.RecordAbandonment(home);value.Dispose();value=null;

                            throw new IOException("runtime_servicing_recovery_required");

                        }

                    } finally { controllerHeld=held; }

                }

            }

            try {

                if(value.Outcome==RuntimeSerialization.Result.Abandoned) { value.RecordAbandonment(home);throw new IOException("runtime_servicing_recovery_required"); }

                if(value.Outcome!=RuntimeSerialization.Result.Acquired)throw new IOException("runtime_owner_"+value.Outcome.ToString().ToLowerInvariant());

                value.RequireOwned();CheckDeadline(deadline);return value;

            } catch { if(value!=null)value.Dispose();throw; }

        }

        internal RuntimeProfileStartup(string home,string root,Dictionary<string,object> payload,ulong deadline,bool cold,bool setupJob=false,string accountPurpose="none",bool residentRole=false)

        {

            this.home=home;this.root=root;this.payload=payload;this.deadline=deadline;this.setupJob=setupJob;this.accountPurpose=accountPurpose;this.residentRole=residentRole;if(residentRole&&setupJob)throw new IOException("runtime_resident_role");

            if(accountPurpose!="none"&&(!setupJob||(accountPurpose!="connect"&&accountPurpose!="finish")))throw new IOException("runtime_startup_purpose");

#if !KOVYA_BOOTSTRAP

            if(setupJob)throw new IOException("runtime_startup_job_role");

#endif

            try {

                if(home.StartsWith(@"\\",StringComparison.Ordinal))throw new IOException("runtime_local_ntfs_required");

                var drive=new DriveInfo(Path.GetPathRoot(home));

                if((drive.DriveType!=DriveType.Fixed&&drive.DriveType!=DriveType.Removable)||drive.DriveFormat!="NTFS")throw new IOException("runtime_local_ntfs_required");

                for(;;) {

                    owner=Open(home,deadline,cold);cold=false;

                    if(Monitor.TryEnter(CreationGate)) { creationHeld=true;break; }

                    owner.Dispose();owner=null;ReleaseController();CheckDeadline(deadline);Thread.Sleep(1);

                }

                // Re-read selection under S; no pre-wait snapshot is authority.

                var current=RuntimeReadRecord(Path.Combine(home,"runtime","current"));

                var admission=RuntimeReadRecord(Path.Combine(home,"state","runtime","admission.json"));

                var actual=admission["payload"] as Dictionary<string,object>;

                if(current.Count!=2 || admission.Count!=5 || actual==null

                    || RuntimeString(admission,"schema_version")!="kovya.plugin-runtime-admission.v2"

                    || RuntimeString(admission,"installation_root")!=home

                    || RuntimeString(admission,"owner_sid_hash")!=ReadCurrentIdentity().UserSidHash

                    || RuntimeJson(actual)!=RuntimeJson(payload)

                    || RuntimeJson(current)!=RuntimeJson(RuntimePointer(payload)))throw new IOException("runtime_custody_selection");

                servicing=RuntimeServicingRead(home,current);

                var directories=new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                var files=new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach(var file in RuntimeFiles(payload))files.Add(Path.Combine(root,RuntimeString(file,"path").Replace('/',Path.DirectorySeparatorChar)));

                files.Add(Process.GetCurrentProcess().MainModule.FileName);

                files.Add(Path.Combine(home,"state","runtime","lifetime.v1"));files.Add(Path.Combine(home,"state","runtime","work.v1"));

                foreach(string file in files) { string parent=Path.GetDirectoryName(file);while(parent!=null){directories.Add(parent);parent=Path.GetDirectoryName(parent);} }

                directories.Add(Path.Combine(home,"state","broker"));

                var ordered=new List<string>(directories);ordered.Sort(delegate(string a,string b){return a.Length.CompareTo(b.Length);});

                foreach(string directory in ordered) { CheckDeadline(deadline);IntPtr held=Hold(directory,true);if(directory==Path.Combine(home,"state")||directory==Path.Combine(home,"state","broker"))RuntimeSerialization.CheckSecurity(held,1,true); }

                foreach(string file in files) { CheckDeadline(deadline);IntPtr value=Hold(file,false);

                    if(file==Path.Combine(home,"state","runtime","lifetime.v1"))lifetime=value;

                    if(file==Path.Combine(home,"state","runtime","work.v1"))work=value;

                }

                Info l,r;if(!FileInfo(lifetime,out l)||!FileInfo(work,out r)||Identity(l)!=RuntimeString(servicing,"lifetime_identity")

                    || Identity(r)!=RuntimeString(servicing,"work_identity") || l.sizeLow!=0||l.sizeHigh!=0||r.sizeLow!=0||r.sizeHigh!=0)

                    throw new IOException("runtime_custody_markers");

                RuntimeVerify(root,payload,true);CheckDeadline(deadline);

            } catch { Dispose();throw; }

        }

        internal IntPtr Handoff(List<IntPtr> inherited)

        {

            owner.RequireOwned();CheckDeadline(deadline);var copies=new Dictionary<long,IntPtr>();var records=new List<object>();

            foreach(var record in guards) {

                IntPtr original=new IntPtr(Int64.Parse(RuntimeString(record,"handle"),CultureInfo.InvariantCulture)),copy;

                if(!DuplicateHandle(GetCurrentProcess(),original,GetCurrentProcess(),out copy,0,true,2))throw new IOException("runtime_custody_duplicate");

                inherited.Add(copy);copies.Add(original.ToInt64(),copy);var next=new Dictionary<string,object>(record);

                next["handle"]=copy.ToInt64().ToString(CultureInfo.InvariantCulture);records.Add(next);

            }

            IntPtr s,parent;

            if(!DuplicateHandle(GetCurrentProcess(),owner.NativeHandle,GetCurrentProcess(),out s,0,true,2))throw new IOException("runtime_custody_duplicate");inherited.Add(s);

            if(!DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),GetCurrentProcess(),out parent,0x00101000,true,0))throw new IOException("runtime_custody_parent");inherited.Add(parent);

            IntPtr ackWrite;var attributes=new SecurityAttributes {Length=Marshal.SizeOf(typeof(SecurityAttributes)),InheritHandle=0};

            if(!CreatePipe(out startupAck,out ackWrite,ref attributes,4096))throw new IOException("runtime_startup_ack");

            inherited.Add(ackWrite);NonInherited(startupAck);

            if(!Flags(ackWrite,1,1))throw new IOException("runtime_startup_ack");

            var data=new Dictionary<string,object>{{"startup_ack",ackWrite.ToInt64().ToString(CultureInfo.InvariantCulture)},{"schema_version",setupJob?"kovya.profile-startup-job.v1":"kovya.profile-startup.v1"},{"home",home},{"root",root},

                {"owner_sid_hash",ReadCurrentIdentity().UserSidHash},{"payload_digest",RuntimeString(payload,"digest")},{"generation",RuntimeString(servicing,"generation")},

                {"deadline_tick64",deadline.ToString(CultureInfo.InvariantCulture)},{"s",s.ToInt64().ToString(CultureInfo.InvariantCulture)},

                {"l",copies[lifetime.ToInt64()].ToInt64().ToString(CultureInfo.InvariantCulture)},{"r",copies[work.ToInt64()].ToInt64().ToString(CultureInfo.InvariantCulture)},

                {"parent",parent.ToInt64().ToString(CultureInfo.InvariantCulture)},{"parent_pid",Process.GetCurrentProcess().Id},

                {"parent_image",Process.GetCurrentProcess().MainModule.FileName},{"guards",records}};

            data.Add("runtime_role",residentRole?"resident":"entry");

            if(setupJob){data.Add("job_kind","setup");data.Add("account_purpose",accountPurpose);}

            byte[] bytes=Encoding.UTF8.GetBytes(RuntimeJson(data));if(bytes.Length>262140)throw new IOException("runtime_custody_size");

            IntPtr mapping=CreateMapping(new IntPtr(-1),IntPtr.Zero,4,0,262144,null),view=IntPtr.Zero;

            if(mapping==IntPtr.Zero)throw new IOException("runtime_custody_mapping");

            try {

                view=Map(mapping,2,0,0,UIntPtr.Zero);if(view==IntPtr.Zero)throw new IOException("runtime_custody_mapping");

                Marshal.WriteInt32(view,bytes.Length);Marshal.Copy(bytes,0,IntPtr.Add(view,4),bytes.Length);Unmap(view);view=IntPtr.Zero;

                IntPtr readOnly;if(!DuplicateHandle(GetCurrentProcess(),mapping,GetCurrentProcess(),out readOnly,5,true,0))throw new IOException("runtime_custody_mapping");

                inherited.Add(readOnly);return readOnly;

            } finally {if(view!=IntPtr.Zero)Unmap(view);CloseHandle(mapping);Clear(bytes);}

        }

        internal void BeforeCreate() { owner.RequireOwned();CheckDeadline(deadline); }

        internal void Created()

        {

            // The actual child now owns the duplicates. Drop S before readiness.

            transferred=true;owner.Release();ReleaseController();

            if(creationHeld){Monitor.Exit(CreationGate);creationHeld=false;}

            if(work!=IntPtr.Zero){if(!CloseHandle(work))throw new IOException("runtime_work_close_failed");pins.Remove(work);work=IntPtr.Zero;}

        }

        internal void AwaitStartup(IntPtr child)

        {

            // S and Creation have already been released. Waiting for Node cannot

            // extend the original ticket or keep the parent blocked forever.

            if(!transferred)throw new IOException("runtime_startup_ack");

            for(;;) {

                CheckDeadline(deadline);uint available;

                if(!PeekNamedPipe(startupAck,IntPtr.Zero,0,IntPtr.Zero,out available,IntPtr.Zero))throw new IOException("runtime_startup_refused");

                if(available>0) {

                    byte[] value=new byte[1];uint count;

                    if(!ReadAck(startupAck,value,1,out count,IntPtr.Zero)||count!=1||value[0]!=1)throw new IOException("runtime_startup_refused");

                    CheckDeadline(deadline);

                    if(!CloseHandle(startupAck))throw new IOException("runtime_startup_ack_close");startupAck=IntPtr.Zero;

                    KovyaStartupTrace.Mark("startup_ack_received");
                    if(setupJob)StartupProgress.WriteLine("Kovya startup: runtime ready; starting request (limit 1000 ms).");

                    return;

                }

                if(WaitForSingleObject(child,0)!=0x102)throw new IOException("runtime_startup_refused");

                ulong now=RuntimeSerialization.GetTickCount64();

                if(now>=deadline)throw new IOException("runtime_startup_timeout");

                Thread.Sleep((int)Math.Min(2UL,deadline-now));

            }

        }

        private void ReleaseController() { if(controllerHeld){controller.ReleaseMutex();controllerHeld=false;}if(controller!=null){controller.Dispose();controller=null;} }

        public void Dispose()

        {

            if(creationHeld) { Monitor.Exit(CreationGate);creationHeld=false; }

            if(startupAck!=IntPtr.Zero){if(!CloseHandle(startupAck))throw new IOException("runtime_startup_ack_close");startupAck=IntPtr.Zero;}

            if(transferred) {

                // Raw S/L/code handles intentionally survive CLR cleanup until

                // process exit; never rely on a finalizer or AppDomain teardown.

                if(work!=IntPtr.Zero){if(!CloseHandle(work))throw new IOException("runtime_work_close_failed");pins.Remove(work);work=IntPtr.Zero;}

                return;

            }

            for(int i=pins.Count-1;i>=0;i--){if(!CloseHandle(pins[i]))throw new IOException("runtime_custody_close_failed");pins.RemoveAt(i);}

            if(owner!=null){owner.Dispose();owner=null;}ReleaseController();

        }

    }



    internal static void RuntimeCloseInherited(List<IntPtr> values)

    {

        while(values.Count>0) {

            int last=values.Count-1;

            // A failed close must leave a non-inheritable retained reference,

            // and must not cause already-closed values to be closed again.

            RuntimeProfileStartup.NonInherited(values[last]);

            if(!CloseHandle(values[last]))throw new IOException("runtime_custody_close_failed");

            values.RemoveAt(last);

        }

    }



    private static int RuntimeRunOwned(ProcessStartInfo start,bool resident,RuntimeProfileStartup profile=null,Action awaitingStartup=null)

    {

        IntPtr job=IntPtr.Zero,list=IntPtr.Zero,handles=IntPtr.Zero,jobs=IntPtr.Zero,environment=IntPtr.Zero,nul=IntPtr.Zero,desktopPolicy=IntPtr.Zero;

        bool initialized=false,handedOff=false;

        RuntimeProcessInfo child=new RuntimeProcessInfo();

        List<IntPtr> duplicates=new List<IntPtr>();

        AnonymousPipeServerStream gate=null;

        try

        {

            if (!resident)

            {

                job=CreateJobObject(IntPtr.Zero,null);

                if (job==IntPtr.Zero) throw new IOException("runtime_job_refused");

                RuntimeJobExtended limits=new RuntimeJobExtended();

                limits.basic.flags=0x2000|0x0800; // KILL_ON_JOB_CLOSE | BREAKAWAY_OK, never SILENT.

                uint length=(uint)Marshal.SizeOf(typeof(RuntimeJobExtended));

                if (!SetInformationJobObject(job,9,ref limits,length)) throw new IOException("runtime_job_refused");

                RuntimeJobExtended observed;

                if (!QueryInformationJobObject(job,9,out observed,length,IntPtr.Zero)

                    || (observed.basic.flags & 0x3800)!=0x2800) throw new IOException("runtime_job_refused");

            }

            IntPtr[] standard=new IntPtr[3];

            if (resident)

            {

                // Broker must receive a native scope gate before any endpoint

                // publication. Starter death closes this pipe: EOF means refusal.

                gate=new AnonymousPipeServerStream(PipeDirection.Out,HandleInheritability.Inheritable);

                standard[0]=new IntPtr(Int64.Parse(gate.GetClientHandleAsString(),CultureInfo.InvariantCulture));

                nul=CreateFile("NUL",GenericRead|GenericWrite,3,IntPtr.Zero,3,0,IntPtr.Zero);

                if (nul==new IntPtr(-1)) throw new IOException("broker_breakaway_refused");

                standard[1]=nul;standard[2]=nul;

            }

            else { standard[0]=GetStdHandle(-10);standard[1]=GetStdHandle(-11);standard[2]=GetStdHandle(-12); }

            for (int i=0;i<3;i++)

            {

                IntPtr copy;

                if (!DuplicateHandle(GetCurrentProcess(),standard[i],GetCurrentProcess(),out copy,0,true,2))

                    throw new IOException("runtime_standard_handles");

                duplicates.Add(copy);

            }

            int attributeCount=resident ? 1 : 2;

            if(profile!=null)start.EnvironmentVariables["KOVYA_PROFILE_HANDOFF"]=profile.Handoff(duplicates).ToInt64().ToString(CultureInfo.InvariantCulture);

#if KOVYA_MSIX

            IntPtr custody=MsixChildCustody(duplicates);

            start.EnvironmentVariables["KOVYA_MSIX_HANDOFF"]=custody.ToInt64().ToString(CultureInfo.InvariantCulture);

            attributeCount++;

#endif

            IntPtr size=IntPtr.Zero;

            InitializeProcThreadAttributeList(IntPtr.Zero,attributeCount,0,ref size);

            list=Marshal.AllocHGlobal(size);

            if (!InitializeProcThreadAttributeList(list,attributeCount,0,ref size)) throw new IOException("runtime_job_refused");

            initialized=true;

            handles=Marshal.AllocHGlobal(IntPtr.Size*duplicates.Count);

            for(int i=0;i<duplicates.Count;i++) Marshal.WriteIntPtr(handles,i*IntPtr.Size,duplicates[i]);

            if (!UpdateProcThreadAttribute(list,0,new IntPtr(0x20002),handles,new IntPtr(IntPtr.Size*duplicates.Count),IntPtr.Zero,IntPtr.Zero))

                throw new IOException("runtime_standard_handles");

            if (!resident)

            {

                jobs=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobs,job);

                if (!UpdateProcThreadAttribute(list,0,new IntPtr(0x2000d),jobs,new IntPtr(IntPtr.Size),IntPtr.Zero,IntPtr.Zero))

                    throw new IOException("runtime_job_refused");

            }

#if KOVYA_MSIX

            desktopPolicy=Marshal.AllocHGlobal(4);Marshal.WriteInt32(desktopPolicy,6);

            if(!UpdateProcThreadAttribute(list,0,new IntPtr(0x20012),desktopPolicy,new IntPtr(4),IntPtr.Zero,IntPtr.Zero))throw new IOException("msix_context_refused");

#endif

            RuntimeStartupInfoEx startup=new RuntimeStartupInfoEx();

            startup.startup.cb=Marshal.SizeOf(typeof(RuntimeStartupInfoEx));startup.startup.flags=0x100;

            startup.startup.stdin=duplicates[0];startup.startup.stdout=duplicates[1];startup.startup.stderr=duplicates[2];startup.attributes=list;

            List<string> keys=new List<string>();

            foreach(string key in start.EnvironmentVariables.Keys) keys.Add(key);

            keys.Sort(StringComparer.OrdinalIgnoreCase);

            StringBuilder block=new StringBuilder();

            foreach(string key in keys) block.Append(key).Append('=').Append(start.EnvironmentVariables[key]).Append('\0');

            block.Append('\0');environment=Marshal.StringToHGlobalUni(block.ToString());

            uint flags=0x00080000|0x00000400; // EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT.

            flags |= resident ? 0x01000000u|0x00000008u : 0x08000000u; // explicit breakaway/detached OR no window.

            if(profile!=null)profile.BeforeCreate();

            KovyaStartupTrace.Mark(resident?"resident_createprocess_before":"worker_createprocess_before");
            if (!CreateProcess(start.FileName,new StringBuilder(RuntimeQuoteArgument(start.FileName)+" "+start.Arguments),

                IntPtr.Zero,IntPtr.Zero,true,flags,environment,null,ref startup,out child))

                throw new IOException(resident ? "broker_breakaway_refused" : "runtime_job_refused");

            // Child inherits the explicit standard/code handles, never our job or account transaction.

            RuntimeCloseInherited(duplicates);

            KovyaStartupTrace.Mark(resident?"resident_createprocess_after":"worker_createprocess_after");
            if(profile!=null){profile.Created();if(awaitingStartup!=null)awaitingStartup();profile.AwaitStartup(child.process);}

            if (resident)

            {

                gate.DisposeLocalCopyOfClientHandle();

                Dictionary<string,object> proof=RuntimeScopeProof(child.process,(int)child.pid);

                byte[] line=Encoding.UTF8.GetBytes(RuntimeJson(proof)+"\n");

                try { gate.Write(line,0,line.Length);gate.Flush(); } finally {Clear(line);}

                gate.Dispose();gate=null;

                handedOff=true;

                Console.Out.WriteLine(RuntimeJson(new Dictionary<string,object>{{"ok",true},{"state","broker_started"},{"broker",proof}}));
                KovyaStartupTrace.Mark("start_broker_reply_sent");

                return 0;

            }

            if (WaitForSingleObject(child.process,0xffffffff)!=0) throw new IOException("runtime_wait_refused");

            uint exitCode;if (!GetExitCodeProcess(child.process,out exitCode)) throw new IOException("runtime_wait_refused");

            return unchecked((int)exitCode);

        }

        finally

        {

            // Only newly created, unpublished resident children may be terminated.

            if (resident && !handedOff && child.process!=IntPtr.Zero) TerminateProcess(child.process,70);

            if (job!=IntPtr.Zero) CloseHandle(job);

            if (gate!=null) gate.Dispose();

            if (child.thread!=IntPtr.Zero) CloseHandle(child.thread);

            if (child.process!=IntPtr.Zero) CloseHandle(child.process);

            if (initialized) DeleteProcThreadAttributeList(list);

            if (list!=IntPtr.Zero) Marshal.FreeHGlobal(list);

            if (handles!=IntPtr.Zero) Marshal.FreeHGlobal(handles);

            if (jobs!=IntPtr.Zero) Marshal.FreeHGlobal(jobs);

            if (desktopPolicy!=IntPtr.Zero) Marshal.FreeHGlobal(desktopPolicy);

            if (environment!=IntPtr.Zero) Marshal.FreeHGlobal(environment);

            if (nul!=IntPtr.Zero && nul!=new IntPtr(-1)) CloseHandle(nul);

            RuntimeCloseInherited(duplicates);

        }

    }





    private static string RuntimeBrokerHome(string self)

    {

        string codeRoot=Path.GetFullPath(Path.Combine(Path.GetDirectoryName(self),"..","..",".."));

#if KOVYA_MSIX

        return MsixHome();

#elif KOVYA_LEGACY_LAYOUT

        RuntimeOrdinary(codeRoot,true,false);

        return codeRoot;

#elif KOVYA_MANAGED_RUNTIME

        string home=RuntimeCanonicalHome(Path.GetDirectoryName(Path.GetDirectoryName(codeRoot)));

        RuntimeResidentRequirement(self,home); // Exact admitted copy; never a legacy fallback.

        return home;

#else

        throw new IOException("bootstrap_broker_forbidden");

#endif

    }

    private static Dictionary<string,object> RuntimeResidentRequirement(string self,string home)

    {

#if KOVYA_MSIX

        return MsixRequirement(home);

#else

        home=RuntimeCanonicalHome(home);

        Dictionary<string,object> record=RuntimeReadRecord(Path.Combine(home,"state","runtime","admission.json"));

        Dictionary<string,object> payload=record["payload"] as Dictionary<string,object>;

        if (payload==null || !RuntimeLaunchVersion(RuntimeString(payload,"version"))

            || RuntimeString(record,"installation_root")!=home

            || RuntimeString(record,"schema_version")!="kovya.plugin-runtime-admission.v2") throw new IOException("admission_binding");

        TokenIdentity owner=ReadCurrentIdentity();RequireOrdinaryIdentity(owner,65);

        if (!FixedEquals(owner.UserSidHash,RuntimeString(record,"owner_sid_hash"))) throw new IOException("admission_binding");

        Dictionary<string,object> current=RuntimeReadRecord(Path.Combine(home,"runtime","current"));

        if (RuntimeString(current,"version")!=RuntimeString(payload,"version")

            || !FixedEquals(RuntimeString(current,"digest"),RuntimeString(payload,"digest"))) throw new IOException("admission_binding");

        string root=Path.Combine(home,"runtime",RuntimeString(payload,"version"));

        RuntimeVerify(root,payload,false);

        Dictionary<string,object> entries=payload["entrypoints"] as Dictionary<string,object>;

        string native=RuntimeLaunchFile(root,payload,RuntimeString(entries,"native"));

        if (!String.Equals(Path.GetFullPath(self),native,StringComparison.OrdinalIgnoreCase)) throw new IOException("admitted_helper_required");

        return new Dictionary<string,object>{

            {"schema_version","kovya.plugin-runtime-requirement.v1"},{"version",RuntimeString(payload,"version")},

            {"minimum",RuntimeString(payload,"version")},{"digest",RuntimeString(payload,"digest")},

            {"native_helper_sha256",RuntimeFileHash(native)}

        };

#endif

    }

#if KOVYA_MANAGED_RUNTIME

    private static int RunBrokerResidency(string[] args)

    {

        int parent;IntPtr handle=IntPtr.Zero;

        try

        {

            if(args.Length!=3 || !Int32.TryParse(args[1],out parent) || parent<1

                || GetParentProcessId(Process.GetCurrentProcess().Id)!=parent) throw new IOException("broker_scope_unknown");

            string self=Process.GetCurrentProcess().MainModule.FileName;

            RuntimeResidentRequirement(self,args[2]);

            handle=OpenProcess(ProcessQueryLimitedInformation|Synchronize,false,(uint)parent);

            if(handle==IntPtr.Zero) throw new IOException("broker_scope_unknown");

            ProcessProof proof=ReadProcessProof(handle,parent);

            RequireSameIdentity(ReadCurrentIdentity(),proof.Identity,65);

            RequireProcessAlive(handle,65);

            Console.Out.WriteLine(RuntimeJson(RuntimeScopeProof(handle,parent)));

            return 0;

        }

        catch { return RuntimeLaunchReport("refused","broker_scope_unknown"); }

        finally {if(handle!=IntPtr.Zero) CloseHandle(handle);}

    }

#endif

#if KOVYA_BOOTSTRAP || KOVYA_MANAGED_RUNTIME


    private static bool RuntimeStartupDiagnostic(string home,string stage,string reason) {
        if(String.IsNullOrEmpty(home))return false;
        try {
            RequireOrdinaryIdentity(ReadCurrentIdentity(),65);
            if(home.StartsWith(@"\\",StringComparison.Ordinal))return false;
            var drive=new DriveInfo(Path.GetPathRoot(home));if(drive.DriveFormat!="NTFS")return false;
            RuntimeOrdinary(home,true,true);Directory.CreateDirectory(home);RuntimeSerialization.PrepareState(home);
            var security=new System.Security.AccessControl.MutexSecurity();
            using(var identity=WindowsIdentity.GetCurrent()) {
                security.SetOwner(identity.User);security.SetAccessRuleProtection(true,false);
                security.AddAccessRule(new System.Security.AccessControl.MutexAccessRule(identity.User,System.Security.AccessControl.MutexRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
            }
            bool created,owned=false,abandoned=false;
            using(var mutex=new Mutex(false,"Global\\Kovya.RuntimeAdmission."+Sha256Hex(home.ToLowerInvariant()),out created,security)) {
                RuntimeSerialization.ValidateControllerMutex(mutex.SafeWaitHandle.DangerousGetHandle());
                try {
                    try {owned=mutex.WaitOne(250);}catch(AbandonedMutexException){owned=true;abandoned=true;}
                    if(!owned)return false;
                    using(var serialization=RuntimeControllerSerialization(home,250,abandoned)) {
                        string safeReason=Array.IndexOf(new[]{"version_skew","runtime_missing","admission_binding","runtime_startup_timeout","runtime_launch_refused","runtime_identity","runtime_servicing_recovery_required","marker_mismatch"},reason)>=0?reason:"runtime_launch_refused";
                        string safeStage=Array.IndexOf(new[]{"startup_selection","startup_custody","startup_readiness","native_launch"},stage)>=0?stage:"native_launch";
                        serialization.WriteStartupRecord(new Dictionary<string,object>{{"schema_version","kovya.startup-refusal.v1"},{"utc",DateTime.UtcNow.ToString("o",CultureInfo.InvariantCulture)},{"stage",safeStage},{"reason",safeReason}});
                    }
                    return true;
                } finally {if(owned)mutex.ReleaseMutex();}
            }
        } catch {return false;}
    }

    private static int RunRuntimeLaunch(string[] args)

    {

#if KOVYA_MSIX

        return MsixLaunch(args);

#else

        ulong launchStarted=RuntimeSerialization.GetTickCount64();

        bool setupJob=false;

#if KOVYA_BOOTSTRAP

        setupJob=args.Length>=2 && args[0]=="launch" && args[1]=="setup";

#endif

        ulong startupDeadline=launchStarted+(setupJob?30000UL:KovyaRequestBudget.OrdinaryStartupMs);

        string startupPhase=setupJob?"startup_selection":"native_launch";

        if(setupJob)StartupProgress.WriteLine("Kovya startup: preparing runtime (limit 30000 ms).");

        string diagnosticHome=null;
        Func<string,string,int> report=delegate(string state,string reason) {

            if(setupJob)StartupProgress.WriteLine("Kovya startup: refused during "+startupPhase+".");

            bool recorded=RuntimeStartupDiagnostic(diagnosticHome,startupPhase,reason);
            return RuntimeLaunchReport(state,reason,startupPhase,recorded);

        };

        // The package copy may launch or admit; runtime identity stays with the

        // admitted copy. No PATH discovery, acquisition or repair occurs here.

#if KOVYA_BOOTSTRAP

        if (args[0]!="launch") return 64;

        bool resident=false;

#elif KOVYA_MANAGED_RUNTIME

        if (args[0]!="start-broker") return 64;

        bool resident=true;

        startupDeadline=RuntimeProfileChild.Deadline;

#else

        return 64;

#endif

        if (resident && args.Length!=2) return report("refused","runtime_launch_arguments");

        string self = Process.GetCurrentProcess().MainModule.FileName;

        string package = Path.GetDirectoryName(self);

        for (int i=0;i<3;i++) package = Path.GetDirectoryName(package);

        Dictionary<string,object> requirement;

        try

        {

            RuntimeOrdinary(package,true,false);

            requirement = resident ? RuntimeResidentRequirement(self,args[1]) : RuntimeReadRecord(Path.Combine(package,"connector","plugin","runtime-requirement.json"));

            List<string> keys = new List<string>(requirement.Keys); keys.Sort(StringComparer.Ordinal);

            if (String.Join(",",keys.ToArray()) != "digest,minimum,native_helper_sha256,schema_version,version"

                || RuntimeString(requirement,"schema_version") != "kovya.plugin-runtime-requirement.v1"

                || !RuntimeLaunchVersion(RuntimeString(requirement,"version")) || !RuntimeLaunchVersion(RuntimeString(requirement,"minimum"))

                || RuntimeString(requirement,"version").Split('.')[0] != RuntimeString(requirement,"minimum").Split('.')[0]

                || !System.Text.RegularExpressions.Regex.IsMatch(RuntimeString(requirement,"digest"),"^[a-f0-9]{64}$")

                || !System.Text.RegularExpressions.Regex.IsMatch(RuntimeString(requirement,"native_helper_sha256"),"^[a-f0-9]{64}$"))

                return report("runtime_configuration_required","runtime_configuration_required");

            if (!FixedEquals(RuntimeFileHash(self),RuntimeString(requirement,"native_helper_sha256")))

                return report("runtime_configuration_required","native_admission_digest");

        }

        catch (Exception) { return report("runtime_configuration_required","runtime_configuration_required"); }

        try

        {

            if (!resident && (args.Length < 2 || (args[1] != "setup" && args[1] != "worker" && args[1] != "mcp")))

                return report("refused","runtime_launch_arguments");

            string script = resident ? "connector/plugin/resident-broker.mjs" : "connector/plugin/" + args[1] + ".mjs";

            string configuredHome = resident ? args[1] : Environment.GetEnvironmentVariable("KOVYA_HOME");

            string home = RuntimeCanonicalHome(String.IsNullOrEmpty(configuredHome)

                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),".kovya") : configuredHome);

            string canonicalPackage = RuntimeCanonicalHome(package);

            if (!resident && (home.Equals(canonicalPackage,StringComparison.OrdinalIgnoreCase)

                || home.StartsWith(canonicalPackage + Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)

                || canonicalPackage.StartsWith(home + Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)))

                throw new IOException("package_home_overlap");

            diagnosticHome=home;
            string currentPath = Path.Combine(home,"runtime","current");

            if (!File.Exists(currentPath)) return report("runtime_missing","runtime_missing");

            Dictionary<string,object> current = RuntimeReadRecord(currentPath);

            Dictionary<string,object> record = RuntimeReadRecord(Path.Combine(home,"state","runtime","admission.json"));

            Dictionary<string,object> payload = record["payload"] as Dictionary<string,object>;

            if (payload == null || RuntimeString(record,"schema_version") != "kovya.plugin-runtime-admission.v2"

                || RuntimeString(record,"installation_root") != home) throw new IOException("admission_binding");

            TokenIdentity identity = ReadCurrentIdentity(); RequireOrdinaryIdentity(identity,65);

            if (!FixedEquals(RuntimeString(record,"owner_sid_hash"),identity.UserSidHash)) throw new IOException("admission_binding");

            DateTime admittedAt;

            if (!DateTime.TryParse(RuntimeString(record,"admitted_at"),CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out admittedAt)) throw new IOException("admission_binding");

            string version = RuntimeString(payload,"version");

            if (!RuntimeLaunchVersion(version) || RuntimeString(current,"version") != version

                || !FixedEquals(RuntimeString(current,"digest"),RuntimeString(payload,"digest"))) throw new IOException("admission_binding");

            string[] installed = version.Split('.'), minimum = RuntimeString(requirement,"minimum").Split('.');

            bool compatible = installed[0] == RuntimeString(requirement,"version").Split('.')[0];

            if (compatible && !FixedEquals(RuntimeString(payload,"digest"),RuntimeString(requirement,"digest")))

            {

                for (int i=0;i<3;i++)

                {

                    long a = Int64.Parse(installed[i]), b = Int64.Parse(minimum[i]);

                    if (a != b) { compatible = a > b; break; }

                }

            }

            if (!compatible) return report("repair_required","version_skew");

            string root = Path.Combine(home,"runtime",version);

            KovyaStartupTrace.Mark("runtime_verify_before");
            RuntimeVerify(root,payload,false); // Full bytes are verified once, under retained native pins, before CreateProcess.
            KovyaStartupTrace.Mark("runtime_verify_after");

            Dictionary<string,object> entries = payload["entrypoints"] as Dictionary<string,object>;

            string node = RuntimeLaunchFile(root,payload,RuntimeString(entries,"node"),false);

            RuntimeLaunchFile(root,payload,RuntimeString(entries,"native"),false);

            string entry = RuntimeLaunchFile(root,payload,script,false);

            if (resident) RuntimeLaunchFile(root,payload,RuntimeString(entries,"broker"),false);

            if (args[1] == "setup") RuntimeLaunchFile(root,payload,"connector/plugin/release-config.json",false);

            string markerPath = RuntimeLaunchFile(root,payload,"runtime/kovya-runtime.json",false);

            Dictionary<string,object> marker = RuntimeReadRecord(markerPath);

            if (marker.Count != 3 || RuntimeString(marker,"schema_version") != "kovya.windows-managed-runtime.v2"

                || RuntimeString(marker,"architecture") != "x64"

                || RuntimeString(marker,"node_relative_path") != "node/node.exe"

                || RuntimeString(entries,"node") != "runtime/" + RuntimeString(marker,"node_relative_path"))

                throw new IOException("marker_mismatch");

            string system = Environment.GetFolderPath(Environment.SpecialFolder.System);

            string windows = Path.GetDirectoryName(system);

            ProcessStartInfo start = new ProcessStartInfo(node);

            string loader=RuntimeLaunchFile(root,payload,"connector/claude-code/client/kovya-profile-entry.mjs",false);

            RuntimeLaunchFile(root,payload,"connector/claude-code/client/kovya_profile_startup.node",false);

            StringBuilder arguments = new StringBuilder("--import "+RuntimeQuoteArgument(new Uri(loader).AbsoluteUri)+" "+RuntimeQuoteArgument(entry));

            if (resident) arguments.Append(" --home ").Append(RuntimeQuoteArgument(home));

            for (int i=2;i<args.Length;i++) arguments.Append(' ').Append(RuntimeQuoteArgument(args[i]));

            start.Arguments = arguments.ToString();

            start.UseShellExecute = false; start.CreateNoWindow = true;

            start.EnvironmentVariables.Clear();

            foreach (string key in new string[] {"ProgramFiles","USERPROFILE","HOME","USERDOMAIN","USERNAME","SESSIONNAME"})

            {

                string value = Environment.GetEnvironmentVariable(key);

                if (value == null) continue;

                if (Path.IsPathRooted(value))

                {

                    string physical = RuntimeCanonicalHome(value);

                    if (physical.Equals(canonicalPackage,StringComparison.OrdinalIgnoreCase)

                        || physical.StartsWith(canonicalPackage + Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))

                        throw new IOException("package_environment_path");

                }

                start.EnvironmentVariables[key] = value;

            }

            start.EnvironmentVariables["SystemRoot"] = windows; start.EnvironmentVariables["WINDIR"] = windows;

            start.EnvironmentVariables["PATH"] = Path.GetDirectoryName(node) + ";" + system;

            start.EnvironmentVariables["KOVYA_HOME"] = home;

            start.EnvironmentVariables["KOVYA_WINDOWS_AUTH_MANIFEST"] = Path.Combine(home,"windows-device-auth.json");

            start.EnvironmentVariables["KOVYA_WINDOWS_OWNER_SID_HASH"] = identity.UserSidHash;
            KovyaStartupTrace.Forward(start.EnvironmentVariables);

            // Inherit standard handles unchanged, including MCP's long-lived stdin.

            startupPhase=setupJob?"startup_custody":"native_launch";

            using(var profile=new RuntimeProfileStartup(home,root,payload,startupDeadline,!resident,setupJob,setupJob&&args.Length==4&&(args[3]=="connect"||args[3]=="finish")?args[3]:"none",resident))

                return RuntimeRunOwned(start,resident,profile,()=>{startupPhase=setupJob?"startup_readiness":"native_launch";});

        }

        catch (NativeFailure) { return report("refused","runtime_identity"); }

        catch (Exception error)

        {

            string reason = error is IOException && System.Text.RegularExpressions.Regex.IsMatch(error.Message,"^[a-z][a-z0-9_]{0,63}$")

                ? error.Message : "runtime_launch_refused";

            return report(reason == "marker_mismatch" ? "runtime_invalid" : "refused",reason);

        }

#endif

    }

#endif



#if KOVYA_BOOTSTRAP

    private static void RequireBootstrapSelfPin()

    {

        string self=Process.GetCurrentProcess().MainModule.FileName;

        string root=Path.GetFullPath(Path.Combine(Path.GetDirectoryName(self),"..","..",".."));

        RuntimeOrdinary(root,true,false);

        Dictionary<string,object> requirement=RuntimeReadRecord(Path.Combine(root,"connector","plugin","runtime-requirement.json"));

        List<string> keys=new List<string>(requirement.Keys);keys.Sort(StringComparer.Ordinal);

        if (String.Join(",",keys.ToArray())!="digest,minimum,native_helper_sha256,schema_version,version"

            || RuntimeString(requirement,"schema_version")!="kovya.plugin-runtime-requirement.v1"

            || !RuntimeLaunchVersion(RuntimeString(requirement,"version"))

            || !RuntimeLaunchVersion(RuntimeString(requirement,"minimum"))

            || RuntimeString(requirement,"version").Split('.')[0]!=RuntimeString(requirement,"minimum").Split('.')[0]

            || !System.Text.RegularExpressions.Regex.IsMatch(RuntimeString(requirement,"digest"),"^[a-f0-9]{64}$")

            || !FixedEquals(RuntimeFileHash(self),RuntimeString(requirement,"native_helper_sha256")))

            throw new IOException("bootstrap_pin_disagreement");

    }

#endif



#if KOVYA_BOOTSTRAP


    private static int RuntimeCompareVersion(string a,string b) {
        string[] x=a.Split('.'),y=b.Split('.');
        for(int i=0;i<3;i++){long left=Int64.Parse(x[i],CultureInfo.InvariantCulture),right=Int64.Parse(y[i],CultureInfo.InvariantCulture);if(left!=right)return left<right?-1:1;}return 0;
    }
    private static string RuntimeStageUpgrade(Dictionary<string,object> request,Dictionary<string,object> payload,string runtime,Dictionary<string,object> pointer) {
        string self=Process.GetCurrentProcess().MainModule.FileName;
        string package=Path.GetFullPath(Path.Combine(Path.GetDirectoryName(self),"..","..",".."));
        var requirement=RuntimeReadRecord(Path.Combine(package,"connector","plugin","runtime-requirement.json"));
        if(RuntimeString(requirement,"version")!=RuntimeString(payload,"version")||RuntimeString(requirement,"digest")!=RuntimeString(payload,"digest"))throw new IOException("runtime_payload_binding");
        string oldVersion=RuntimeString(pointer,"version"),version=RuntimeString(payload,"version");
        if(oldVersion.Split('.')[0]!=version.Split('.')[0]||RuntimeCompareVersion(version,oldVersion)<0)throw new IOException("runtime_upgrade_downgrade");
        string source=request.ContainsKey("source_root")?RuntimeCanonicalHome(RuntimeString(request,"source_root")):RuntimeCanonicalHome(RuntimeString(request,"stage"));
        RuntimeVerify(source,payload);
        if(RuntimeCompareVersion(version,oldVersion)==0) {
            if(RuntimeString(pointer,"digest")!=RuntimeString(payload,"digest"))throw new IOException("runtime_upgrade_conflict");
            return null;
        }
        string target=Path.Combine(runtime,version);
        if(Directory.Exists(target)||File.Exists(target))throw new IOException("incomplete_acquisition");
        string stage=Path.Combine(runtime,version+".staging-"+Guid.NewGuid().ToString("N"));
        RuntimeOrdinary(runtime,true,false);Directory.CreateDirectory(stage);
        foreach(var file in RuntimeFiles(payload)) {
            string relative=RuntimeString(file,"path").Replace('/',Path.DirectorySeparatorChar),destination=Path.Combine(stage,relative);
            RuntimeOrdinary(Path.Combine(source,relative),false,false);Directory.CreateDirectory(Path.GetDirectoryName(destination));
            RuntimeOrdinary(Path.GetDirectoryName(destination),true,false);File.Copy(Path.Combine(source,relative),destination,false);
        }
        RuntimeVerify(stage,payload);return stage;
    }
    private static void RuntimeCommitUpgrade(string home,string runtime,string state,Dictionary<string,object> pointer,Dictionary<string,object> payload,string stage,RuntimeSerialization serialization,ref bool incomplete) {
        var previous=RuntimeServicingRead(home,pointer);IntPtr lifetime=IntPtr.Zero,work=IntPtr.Zero;
        try {
            lifetime=RuntimeSerialization.OpenWriteMarker(Path.Combine(state,"lifetime.v1"),RuntimeString(previous,"lifetime_identity"));
            work=RuntimeSerialization.OpenWriteMarker(Path.Combine(state,"work.v1"),RuntimeString(previous,"work_identity"));
            // Validate through retained fences: reopening ordinary readers would self-conflict.
            RuntimeServicingRead(home,pointer,lifetime,work);
            ulong generation=UInt64.Parse(RuntimeString(previous,"generation"),CultureInfo.InvariantCulture);
            if(generation==UInt64.MaxValue)throw new IOException("runtime_generation_exhausted");
            var record=new Dictionary<string,object>(previous);record["generation"]=(generation+1).ToString(CultureInfo.InvariantCulture);
            record["state"]="PUBLISHING";record["version"]=RuntimeString(payload,"version");record["digest"]=RuntimeString(payload,"digest");
            string target=Path.Combine(runtime,RuntimeString(payload,"version"));
            if(Directory.Exists(target)||File.Exists(target))throw new IOException("incomplete_acquisition");
            RuntimeVerify(stage,payload);
#if KOVYA_SERVICING_FIXTURE
            KovyaServicingFixture.Checkpoint("before-intent");
#endif
            incomplete=true;
            serialization.WriteRecord(Path.Combine(state,"servicing.json"),record);
#if KOVYA_SERVICING_FIXTURE
            KovyaServicingFixture.Checkpoint("after-intent");
#endif
            Directory.Move(stage,target);
#if KOVYA_SERVICING_FIXTURE
            KovyaServicingFixture.Checkpoint("after-target-move");
#endif

            var admission=new Dictionary<string,object>{{"schema_version","kovya.plugin-runtime-admission.v2"},{"installation_root",home},{"payload",payload},{"owner_sid_hash",RuntimeString(previous,"owner_sid_hash")},{"admitted_at",DateTime.UtcNow.ToString("o",CultureInfo.InvariantCulture)}};
            serialization.WriteSelectionRecord(Path.Combine(state,"admission.json"),admission);
#if KOVYA_SERVICING_FIXTURE
            KovyaServicingFixture.Checkpoint("after-admission");
#endif

            serialization.WriteSelectionRecord(Path.Combine(runtime,"current"),RuntimePointer(payload));
#if KOVYA_SERVICING_FIXTURE
            KovyaServicingFixture.Checkpoint("after-current");
#endif

            if(RuntimeJson(RuntimeReadRecord(Path.Combine(state,"admission.json")))!=RuntimeJson(admission)
                ||RuntimeJson(RuntimeReadRecord(Path.Combine(runtime,"current")))!=RuntimeJson(RuntimePointer(payload)))throw new IOException("runtime_publication_readback");
            record["state"]="COMMITTED";serialization.WriteRecord(Path.Combine(state,"servicing.json"),record);
            RuntimeServicingRead(home,RuntimePointer(payload),lifetime,work);
#if KOVYA_SERVICING_FIXTURE
            KovyaServicingFixture.Checkpoint("after-commit-readback");
#endif

        } finally {
            bool failed=false;
            if(work!=IntPtr.Zero&&!CloseHandle(work))failed=true;
            if(lifetime!=IntPtr.Zero&&!CloseHandle(lifetime))failed=true;
            if(failed)throw new IOException("runtime_marker_close_failed");
        }
    }

    private static int RunRuntimeAdmission(int parent)

    {

        int pid = Process.GetCurrentProcess().Id;

        if (GetParentProcessId(pid) != parent) throw new NativeFailure(65);

        Dictionary<string, object> reply = new Dictionary<string, object>();

        bool incomplete = false;

        try

        {

        string line = ReadAsciiLine(Console.OpenStandardInput(), 350000, DeadlineAfter(StartupHandshakeTimeoutMilliseconds));

        // Base64 keeps Unicode paths within the existing bounded ASCII reader.

        Dictionary<string, object> request = RuntimeParse(new UTF8Encoding(false,true).GetString(Convert.FromBase64String(line)));

        Dictionary<string, object> payload = request["payload"] as Dictionary<string, object>;

        if (payload == null || !RuntimeVersion(RuntimeString(payload,"version"))) throw new IOException("runtime_payload");
        if(request.ContainsKey("operation")&&RuntimeString(request,"operation")!="upgrade")throw new IOException("runtime_operation_refused");

        if (request.ContainsKey("stage") == request.ContainsKey("source_root")) throw new IOException("runtime_source_ambiguous");

        string home = RuntimeCanonicalHome(RuntimeString(request,"home"));

        string runtime = Path.Combine(home,"runtime"), state = Path.Combine(home,"state","runtime");

        string current = Path.Combine(runtime,"current"), admission = Path.Combine(state,"admission.json");

        int wait = Convert.ToInt32(request["wait_ms"],CultureInfo.InvariantCulture);

        if (wait < 0 || wait > 30000) throw new IOException("runtime_wait");

        bool owned = false, abandonedController = false;

        var waitClock=Stopwatch.StartNew();

        var mutexSecurity=new System.Security.AccessControl.MutexSecurity();

        using(var identity=WindowsIdentity.GetCurrent()) {

            mutexSecurity.SetOwner(identity.User); mutexSecurity.SetAccessRuleProtection(true,false);

            mutexSecurity.AddAccessRule(new System.Security.AccessControl.MutexAccessRule(identity.User,

                System.Security.AccessControl.MutexRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));

        }

        bool createdController;

        // Global namespace prevents two logon sessions of the same user from

        // concurrently publishing to the same physical home.

        using (Mutex mutex = new Mutex(false,"Global\\Kovya.RuntimeAdmission." + Sha256Hex(home.ToLowerInvariant()),out createdController,mutexSecurity))

        {

            try

            {

                RuntimeSerialization.ValidateControllerMutex(mutex.SafeWaitHandle.DangerousGetHandle());

                try { owned = mutex.WaitOne(wait); } catch (AbandonedMutexException) { owned = true; abandonedController = true; }

                int serializationWait=Math.Max(0,wait-(int)Math.Min(waitClock.ElapsedMilliseconds,Int32.MaxValue));

                if (!owned) reply["state"] = "admission_timeout";

                else

                {

                    if(home.StartsWith(@"\\",StringComparison.Ordinal)) throw new IOException("runtime_local_ntfs_required");

                    var drive=new DriveInfo(Path.GetPathRoot(home));

                    if((drive.DriveType!=DriveType.Fixed && drive.DriveType!=DriveType.Removable) || drive.DriveFormat!="NTFS")

                        throw new IOException("runtime_local_ntfs_required");

                    RuntimeOrdinary(home,true,true); Directory.CreateDirectory(home);

                    // A preceding acquirer may have created the same Windows

                    // path in different casing while this process waited.

                    home = RuntimeCanonicalHome(home);

                    runtime = Path.Combine(home,"runtime"); state = Path.Combine(home,"state","runtime");

                    current = Path.Combine(runtime,"current"); admission = Path.Combine(state,"admission.json");

                    RuntimeOrdinary(runtime,true,true); RuntimeOrdinary(state,true,true);

                    Directory.CreateDirectory(runtime); RuntimeSerialization.PrepareState(home);

                    if(abandonedController) {

                        // Contain observed controller uncertainty before the

                        // potentially long existing-payload verification.

                        using(var uncertain=RuntimeControllerSerialization(home,serializationWait,true)) {}

                        throw new IOException("runtime_servicing_recovery_required");

                    }

                    if (File.Exists(current) || File.Exists(admission) || File.Exists(Path.Combine(state,"servicing.json"))

                        || File.Exists(Path.Combine(state,"lifetime.v1")) || File.Exists(Path.Combine(state,"work.v1")))

                    {

                        incomplete = true;

                        if(!File.Exists(current) || !File.Exists(admission)) throw new IOException("incomplete_acquisition");

                        var pointer=RuntimeExisting(home,runtime,admission,current);
                        bool upgrade=request.ContainsKey("operation")&&RuntimeString(request,"operation")=="upgrade";
                        if(request.ContainsKey("operation")&&!upgrade)throw new IOException("runtime_operation_refused");
                        string upgradeStage=upgrade?RuntimeStageUpgrade(request,payload,runtime,pointer):null;
                        using(var serialization=RuntimeControllerSerialization(home,serializationWait,abandonedController)) {

                            RuntimeServicingRead(home,pointer);

                            var actual=RuntimeReadRecord(current);

                            if(actual.Count!=2 || RuntimeString(actual,"version")!=RuntimeString(pointer,"version") || RuntimeString(actual,"digest")!=RuntimeString(pointer,"digest"))

                                throw new IOException("runtime_servicing_recovery_required");

                            incomplete=false;
                            if(upgrade&&upgradeStage!=null) {
                                var checkedPointer=RuntimeExisting(home,runtime,admission,current);
                                if(RuntimeJson(checkedPointer)!=RuntimeJson(pointer))throw new IOException("runtime_upgrade_conflict");
                                RuntimeCommitUpgrade(home,runtime,state,pointer,payload,upgradeStage,serialization,ref incomplete);
                                reply["current"]=RuntimePointer(payload);reply["state"]="upgraded";
                            } else {reply["current"]=pointer;reply["state"]="current_present";}
                        }
                        // Publication uncertainty remains through all owner cleanup.

                    }

                    else

                    {

                        string version = RuntimeString(payload,"version"), target = Path.Combine(runtime,version);

                        if (Directory.Exists(target) || File.Exists(target)) { incomplete = true; throw new IOException("incomplete_acquisition"); }

                        string stage;

                        if (request.ContainsKey("stage")) stage = RuntimeString(request,"stage");

                        else

                        {

                            // The same executor also stages on machines without

                            // Node. Sources are local, release-verified payloads;

                            // this operation has no download capability.

                            string source = RuntimeCanonicalHome(RuntimeString(request,"source_root"));

                            RuntimeVerify(source,payload);

                            stage = Path.Combine(runtime,version + ".staging-" + Guid.NewGuid().ToString("N"));

                            Directory.CreateDirectory(stage);

                            foreach (Dictionary<string,object> file in RuntimeFiles(payload))

                            {

                                string relative = RuntimeString(file,"path").Replace('/',Path.DirectorySeparatorChar);

                                string destination = Path.Combine(stage,relative);

                                Directory.CreateDirectory(Path.GetDirectoryName(destination));

                                RuntimeOrdinary(Path.GetDirectoryName(destination),true,false);

                                File.Copy(Path.Combine(source,relative),destination,false);

                            }

                        }

                        stage = RuntimeCanonicalHome(stage);

                        string prefix = version + ".staging-";

                        if (Path.GetDirectoryName(stage) != runtime || !Path.GetFileName(stage).StartsWith(prefix,StringComparison.Ordinal)

                            || !System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(stage).Substring(prefix.Length),"^[a-f0-9]{32}$")) throw new IOException("runtime_stage");

                        RuntimeVerify(stage,payload);

                        TokenIdentity identity = ReadCurrentIdentity(); RequireOrdinaryIdentity(identity,65);

                        using(var serialization=RuntimeControllerSerialization(home,serializationWait,abandonedController)) {

                            // Staging/verification happened under M outside S. This

                            // first-install control operation has its existing file

                            // work budget; it grants no 1000 ms public work ticket.

                            string servicing=Path.Combine(state,"servicing.json");

                            if(File.Exists(servicing) || File.Exists(current) || File.Exists(admission))

                                throw new IOException("runtime_servicing_recovery_required");

                            incomplete=true;

                            var record=new Dictionary<string,object> {

                                {"schema_version","kovya.runtime-servicing.v1"},{"installation_root",home},

                                {"owner_sid_hash",identity.UserSidHash},{"generation","1"},

                                {"state","PUBLISHING"},{"version",version},{"digest",RuntimeString(payload,"digest")}

                            };

                            // Record intent before markers or selection can change.

                            serialization.WriteRecord(servicing,record);

                            record["lifetime_identity"]=RuntimeSerialization.Marker(Path.Combine(state,"lifetime.v1"),true);

                            record["work_identity"]=RuntimeSerialization.Marker(Path.Combine(state,"work.v1"),true);

                            serialization.WriteRecord(servicing,record);

                            Directory.Move(stage,target);

                            RuntimeWriteNew(admission,new Dictionary<string, object> { {"schema_version","kovya.plugin-runtime-admission.v2"},{"installation_root",home},

                                {"payload",payload},{"owner_sid_hash",identity.UserSidHash},{"admitted_at",DateTime.UtcNow.ToString("o",CultureInfo.InvariantCulture)} });

                            RuntimeWriteNew(current,RuntimePointer(payload));

                            var readAdmission=RuntimeReadRecord(admission);

                            var readCurrent=RuntimeReadRecord(current);

                            if(RuntimeJson(readAdmission["payload"])!=RuntimeJson(payload) || RuntimeJson(readCurrent)!=RuntimeJson(RuntimePointer(payload)))

                                throw new IOException("runtime_publication_readback");

                            record["state"]="COMMITTED"; serialization.WriteRecord(servicing,record);

                            RuntimeServicingRead(home,RuntimePointer(payload));

                        }

                        // Publication uncertainty remains through all owner cleanup.

                        reply["state"] = "published"; reply["current"] = RuntimePointer(payload);

                    }

                    try

                    {

                        reply["leftover_stages"] = RuntimeLeftovers(runtime);

                        reply["leftover_stages_may_be_truncated"] = ((object[])reply["leftover_stages"]).Length >= 128;

                    }

                    catch (IOException) { reply["metadata_partial"] = true; }

                    catch (UnauthorizedAccessException) { reply["metadata_partial"] = true; }

                }

            }

            finally { if (owned) mutex.ReleaseMutex(); }

        }

        incomplete = false; // All retained markers, S, mutex release and mutex disposal succeeded.
        }

        catch (NativeFailure) { throw; }

        catch (Exception error)

        {

            if (!(error is IOException || error is UnauthorizedAccessException || error is ArgumentException

                || error is FormatException || error is OverflowException || error is KeyNotFoundException

                || error is System.Reflection.TargetInvocationException)) throw;

            reply.Clear();

            reply["state"] = incomplete ? "incomplete_acquisition" : "refused";

            if (!incomplete)

            {

                string reason = error is UnauthorizedAccessException ? "access_denied" : "runtime_admission_refused";

                if (error is IOException && System.Text.RegularExpressions.Regex.IsMatch(error.Message,"^[a-z][a-z0-9_]{0,63}$")) reason = error.Message;

                reply["reason"] = reason;

            }

        }

#if KOVYA_SERVICING_FIXTURE
        object fixtureState;
        if(reply.TryGetValue("state",out fixtureState) && (fixtureState as string)=="upgraded")
            KovyaServicingFixture.Checkpoint("before-reply");
#endif
        reply["pid"] = pid; reply["parent_pid"] = parent;

        string response = "KOVYA_NATIVE_ADMISSION_V1\t" + Convert.ToBase64String(new UTF8Encoding(false,true).GetBytes(RuntimeJson(reply)));

        if (response.Length > 350000) throw new NativeFailure(67);

        byte[] responseBytes = Encoding.ASCII.GetBytes(response + "\n");

        try

        {

            RunTimed<object>(delegate { Stream output = Console.OpenStandardOutput(); output.Write(responseBytes,0,responseBytes.Length); output.Flush(); return null; },StartupHandshakeTimeoutMilliseconds,67);

        }

        finally { Clear(responseBytes); }

        return 0;

    }

#endif



#if !KOVYA_BOOTSTRAP

    private static int RunIdentity(int expectedParentProcessId)

    {

        int currentProcessId = Process.GetCurrentProcess().Id;

        if (GetParentProcessId(currentProcessId) != expectedParentProcessId)

        {

            throw new NativeFailure(65);

        }



        IntPtr parentHandle = OpenProcess(

            ProcessQueryLimitedInformation | Synchronize,

            false,

            unchecked((uint)expectedParentProcessId));

        if (parentHandle == IntPtr.Zero)

        {

            throw new NativeFailure(65);

        }



        try

        {

            TokenIdentity currentIdentity = ReadCurrentIdentity();

            RequireOrdinaryIdentity(currentIdentity, 65);

            ProcessProof hostProof;

            using (Process currentProcess = Process.GetCurrentProcess())

            {

                hostProof = ReadProcessProof(currentProcess.Handle, currentProcessId);

            }

            ProcessProof parentProof = ReadProcessProof(parentHandle, expectedParentProcessId);

            RequireSameIdentity(currentIdentity, parentProof.Identity, 65);

            RequireProcessAlive(parentHandle, 65);

            WriteAsciiLine(

                Console.OpenStandardOutput(),

                BuildIdentityLine(hostProof, parentProof),

                DeadlineAfter(StartupHandshakeTimeoutMilliseconds));

            return 0;

        }

        finally

        {

            CloseHandle(parentHandle);

        }

    }

#endif



#if !KOVYA_BOOTSTRAP

    private static int RunHost(int expectedParentProcessId)

    {

        long startupDeadline = DeadlineAfter(StartupHandshakeTimeoutMilliseconds);

#if KOVYA_MANAGED_RUNTIME && !KOVYA_MSIX

        ulong profileHostDeadline=RuntimeProfileChild.Deadline;

        startupDeadline=DeadlineAfter(RuntimeProfileChild.ResidentHost?RuntimeProfileChild.HostStartupBudget(3000):ProfileAccountBudget(StartupHandshakeTimeoutMilliseconds));

#endif

        int currentProcessId = Process.GetCurrentProcess().Id;

        int actualParentProcessId = GetParentProcessId(currentProcessId);

        if (actualParentProcessId != expectedParentProcessId)

        {

            throw new NativeFailure(65);

        }



        IntPtr parentHandle = OpenProcess(

            ProcessQueryLimitedInformation | Synchronize,

            false,

            unchecked((uint)expectedParentProcessId));

        if (parentHandle == IntPtr.Zero)

        {

            throw new NativeFailure(65);

        }



        NamedPipeServerStream privatePipe = null;

        PrivateMultiplexer privateTransport = null;

        try

        {

            TokenIdentity currentIdentity = ReadCurrentIdentity();

            RequireOrdinaryIdentity(currentIdentity, 65);

            ProcessProof hostProof;

            using (Process currentProcess = Process.GetCurrentProcess())

            {

                hostProof = ReadProcessProof(currentProcess.Handle, currentProcessId);

            }

            ProcessProof parentProof = ReadProcessProof(parentHandle, expectedParentProcessId);

            RequireSameIdentity(currentIdentity, parentProof.Identity, 65);

            RequireProcessAlive(parentHandle, 65);



            Stream standardInput = Console.OpenStandardInput();

            Stream standardOutput = Console.OpenStandardOutput();

            WriteAsciiLine(standardOutput, BuildIdentityLine(hostProof, parentProof), startupDeadline);



            string configurationLine = ReadAsciiLine(

                standardInput,

                MaximumControlLineBytes,

                startupDeadline);

            HostConfiguration configuration = ParseHostConfiguration(configurationLine);

            string accountHome=RuntimeBrokerHome(Process.GetCurrentProcess().MainModule.FileName);

            if (!FixedEquals(configuration.InstallationRootHash,Sha256Hex(accountHome.ToLowerInvariant())))

                throw new NativeFailure(65);





            RequireProcessAlive(parentHandle, 65);

            long privateDeadline = DeadlineAfter(configuration.TimeoutMilliseconds);

#if KOVYA_MANAGED_RUNTIME && !KOVYA_MSIX

            RuntimeProfileStartup.CheckDeadline(profileHostDeadline);

            privateDeadline=RuntimeProfileChild.ResidentHost?startupDeadline:Math.Min(startupDeadline,privateDeadline);

#endif

            privatePipe = CreateOwnedPipe(

                configuration.PrivatePipeLeaf,

                currentIdentity,

                configuration.TimeoutMilliseconds,

                1,

                true);

            IAsyncResult privateAccept = privatePipe.BeginWaitForConnection(null, null);

            WriteAsciiLine(

                standardOutput,

                BuildPrivateReadyLine(hostProof, currentIdentity, configuration),

                privateDeadline);

            if (!CompleteWaitForConnection(privatePipe, privateAccept, parentHandle, privateDeadline, null))

            {

                throw new NativeFailure(65);

            }



            string privatePreamble = ReadAsciiLine(

                privatePipe,

                MaximumControlLineBytes,

                privateDeadline);

            string expectedPrivatePreamble = PrivatePreambleTag + "\t"

                + configuration.BrokerBinding + "\t" + configuration.BrokerInstance;

            if (!FixedEquals(privatePreamble, expectedPrivatePreamble))

            {

                throw new NativeFailure(65);

            }

            VerifyConnectedPrivateParentClient(

                privatePipe.SafePipeHandle.DangerousGetHandle(),

                parentHandle,

                parentProof,

                currentIdentity);

#if KOVYA_MANAGED_RUNTIME && !KOVYA_MSIX

            RuntimeProfileStartup.CheckDeadline(profileHostDeadline);

#endif

            WriteAsciiLine(

                privatePipe,

                PrivateAckTag + "\t" + configuration.BrokerBinding + "\t" + configuration.BrokerInstance,

                privateDeadline);

            privateTransport = new PrivateMultiplexer(privatePipe);



#if KOVYA_MANAGED_RUNTIME && !KOVYA_MSIX

            if(!RuntimeProfileChild.ResidentHost)RuntimeProfileChild.CompleteHostStartup();

            RuntimeProfileStartup.CheckDeadline(profileHostDeadline);

#endif

            WriteAsciiLine(

                standardOutput,

                BuildReadyLine(hostProof, currentIdentity, configuration),

                privateDeadline);



#if KOVYA_MANAGED_RUNTIME && !KOVYA_MSIX

            if(RuntimeProfileChild.ResidentHost){RuntimeProfileChild.AwaitResidentActivation();RuntimeProfileChild.CompleteHostStartup();}

#endif

            Semaphore clientSlots = new Semaphore(MaximumParallelClients, MaximumParallelClients);

            CountdownEvent activeClients = new CountdownEvent(1);

            bool firstPublicInstance = true;

            try

            {

                while (IsProcessAlive(parentHandle) && privateTransport.IsHealthy)

                {

                    if (!clientSlots.WaitOne(25))

                    {

                        continue;

                    }

                    NamedPipeServerStream publicPipe = null;

                    try

                    {

#if KOVYA_MANAGED_RUNTIME && !KOVYA_MSIX

                        if(firstPublicInstance)RuntimeProfileStartup.CheckDeadline(profileHostDeadline);

#endif

                        publicPipe = CreateOwnedPipe(

                            configuration.PublicPipeLeaf,

                            currentIdentity,

                            configuration.TimeoutMilliseconds,

                            MaximumParallelClients,

                            firstPublicInstance);

                        firstPublicInstance = false;

                        IAsyncResult publicAccept = publicPipe.BeginWaitForConnection(null, null);

                        if (!CompleteWaitForConnection(

                            publicPipe,

                            publicAccept,

                            parentHandle,

                            null,

                            privateTransport))

                        {

                            publicPipe.Dispose();

                            clientSlots.Release();

                            break;

                        }

                    }

                    catch

                    {

                        if (publicPipe != null)

                        {

                            publicPipe.Dispose();

                        }

                        clientSlots.Release();

                        throw;

                    }



                    NamedPipeServerStream acceptedPipe = publicPipe;

                    activeClients.AddCount();

                    Thread worker = new Thread(delegate()

                    {

                        try

                        {

                            HandlePublicConnection(

                                acceptedPipe,

                                privateTransport,

                                currentIdentity,

                                configuration);

                        }

                        finally

                        {

                            acceptedPipe.Dispose();

                            clientSlots.Release();

                            activeClients.Signal();

                        }

                    });

                    worker.IsBackground = true;

                    worker.Start();

                }



                activeClients.Signal();

                activeClients.Wait(configuration.TimeoutMilliseconds);

            }

            finally

            {

                if (activeClients.CurrentCount == 0)

                {

                    clientSlots.Close();

                    activeClients.Dispose();

                }

            }



            return privateTransport.IsHealthy || !IsProcessAlive(parentHandle) ? 0 : 70;

        }

        finally

        {

            if (privateTransport != null)

            {

                privateTransport.Dispose();

            }

            if (privatePipe != null)

            {

                privatePipe.Dispose();

            }

            CloseHandle(parentHandle);

        }

    }

#endif



#if !KOVYA_BOOTSTRAP

    private static int RunClient()

    {

        Stream standardInput = Console.OpenStandardInput();

        Stream standardOutput = Console.OpenStandardOutput();



        long startupDeadline = DeadlineAfter(StartupHandshakeTimeoutMilliseconds);

        string endpointLine = ReadAsciiLine(

            standardInput,

            MaximumControlLineBytes,

            startupDeadline);

        ClientEndpoint endpoint = ParseClientEndpoint(endpointLine);

        TokenIdentity currentIdentity = ReadCurrentIdentity();

        RequireOrdinaryIdentity(currentIdentity, 66);

        if (!FixedEquals(currentIdentity.UserSidHash, endpoint.OwnerSidHash)

            || !FixedEquals(currentIdentity.AuthenticationIdHash, endpoint.AuthenticationIdHash)

            || currentIdentity.SessionId != endpoint.SessionId)

        {

            throw new NativeFailure(66);

        }



        using (NamedPipeClientStream publicPipe = new NamedPipeClientStream(

            ".",

            endpoint.PublicPipeLeaf,

            PipeDirection.InOut,

            PipeOptions.Asynchronous,

            TokenImpersonationLevel.Identification,

            HandleInheritability.None))

        {

            long exchangeDeadline = DeadlineAfter(endpoint.TimeoutMilliseconds);

            publicPipe.Connect(RemainingMilliseconds(exchangeDeadline, 67));

            VerifyConnectedPublicServer(

                publicPipe.SafePipeHandle.DangerousGetHandle(),

                endpoint,

                currentIdentity);



            string preamble = PublicPreambleTag + "\t" + endpoint.BrokerBinding + "\t" + endpoint.BrokerInstance;

            WriteAsciiLine(publicPipe, preamble, exchangeDeadline);

            string acknowledgement = ReadAsciiLine(

                publicPipe,

                MaximumControlLineBytes,

                exchangeDeadline);

            string expectedAcknowledgement = PublicAckTag + "\t" + endpoint.BrokerBinding + "\t" + endpoint.BrokerInstance;

            if (!FixedEquals(acknowledgement, expectedAcknowledgement))

            {

                throw new NativeFailure(66);

            }



            byte[] request = null;

            byte[] response = null;

            try

            {

                // Private bytes are not read from the parent until the exact connected

                // server process and its non-secret binding have been verified.

                request = ReadFrame(standardInput, exchangeDeadline);

                WriteFrame(publicPipe, request, exchangeDeadline);

                response = ReadFrame(publicPipe, exchangeDeadline);

                WriteFrame(standardOutput, response, exchangeDeadline);

                return 0;

            }

            finally

            {

                Clear(request);

                Clear(response);

            }

        }

    }

#endif



#if !KOVYA_BOOTSTRAP

    private static int RunTerminate()

    {

        Stream standardInput = Console.OpenStandardInput();

        Stream standardOutput = Console.OpenStandardOutput();

        TerminationEndpoint endpoint = ParseTerminationEndpoint(ReadAsciiLine(

            standardInput,

            MaximumControlLineBytes,

            DeadlineAfter(StartupHandshakeTimeoutMilliseconds)));

        TokenIdentity currentIdentity = ReadCurrentIdentity();

        RequireOrdinaryIdentity(currentIdentity, 66);

        RequireEndpointIdentity(endpoint.Server, currentIdentity);

        RequireVerifierInstallation(endpoint);

        TerminateExactBrokerPair(endpoint, currentIdentity);

        WriteAsciiLine(

            standardOutput,

            TerminationAckTag + "\t" + endpoint.Server.BrokerBinding + "\t" + endpoint.Server.BrokerInstance,

            DeadlineAfter(endpoint.TimeoutMilliseconds));

        return 0;

    }

#endif



    private static void RequireVerifierInstallation(TerminationEndpoint endpoint)

    {

        ProcessProof verifierProof;

        string verifierImagePath;

        using (Process verifier = Process.GetCurrentProcess())

        {

            verifierProof = ReadProcessProof(verifier.Handle, verifier.Id);

            verifierImagePath = ReadNormalizedProcessImagePath(verifier.Handle);

        }

        string verifierDirectory = Path.GetDirectoryName(verifierImagePath);

        string expectedSuffix = Path.DirectorySeparatorChar + "CONNECTOR"

            + Path.DirectorySeparatorChar + "CLAUDE-CODE"

            + Path.DirectorySeparatorChar + "CLIENT"

            + Path.DirectorySeparatorChar + "KOVYA_WINDOWS_BROKER_NATIVE.EXE";

        if (String.IsNullOrEmpty(verifierDirectory)

            || !verifierImagePath.EndsWith(expectedSuffix, StringComparison.Ordinal))

        {

            throw new NativeFailure(66);

        }

        string installationRoot = NormalizeImagePath(RuntimeBrokerHome(verifierImagePath));

        if (!FixedEquals(verifierProof.ImagePathHash, endpoint.Server.ServerImagePathHash)

            || !FixedEquals(Sha256Hex(installationRoot.ToLowerInvariant()), endpoint.InstallationRootHash))

        {

            throw new NativeFailure(66);

        }

    }



    private static void TerminateExactBrokerPair(

        TerminationEndpoint endpoint,

        TokenIdentity currentIdentity)

    {

        ProcessProof helperProof;

        ProcessProof parentProof;

        IntPtr helperHandle = OpenExactProcessForTermination(

            ToProcessProof(endpoint.Server), currentIdentity, out helperProof);

        IntPtr parentHandle = OpenExactProcessForTermination(

            endpoint.ParentProcess, currentIdentity, out parentProof);

        try

        {

            if (helperHandle != IntPtr.Zero)

            {

                RequireProcessAlive(helperHandle, 66);

                if (GetParentProcessId(helperProof.ProcessId) != endpoint.ParentProcess.ProcessId)

                {

                    throw new NativeFailure(66);

                }

                RequireProcessAlive(helperHandle, 66);

            }

            // The Node credential owner is never terminated from its endpoint

            // claim alone.  A held, exact helper handle and the live

            // helper-to-parent relationship are the authority for terminating

            // that parent.  An exact orphan helper may still be removed after

            // its parent has provably exited.

            if (helperHandle == IntPtr.Zero && parentHandle != IntPtr.Zero)

            {

                throw new NativeFailure(66);

            }

            if (helperHandle == IntPtr.Zero && parentHandle == IntPtr.Zero)

            {

                return;

            }



            long deadline = DeadlineAfter(endpoint.TimeoutMilliseconds);

            if (parentHandle != IntPtr.Zero)

            {

                RequireProcessAlive(helperHandle, 66);

                if (GetParentProcessId(helperProof.ProcessId) != endpoint.ParentProcess.ProcessId)

                {

                    throw new NativeFailure(66);

                }

                RequireProcessAlive(helperHandle, 66);

                RequireProcessAlive(parentHandle, 66);

                if (!TerminateProcess(parentHandle, 0x4b4f5659)

                    && WaitForSingleObject(parentHandle, 0) != WaitObject0)

                {

                    throw new NativeFailure(66);

                }

                if (WaitForSingleObject(

                    parentHandle,

                    unchecked((uint)RemainingMilliseconds(deadline, 66))) != WaitObject0)

                {

                    throw new NativeFailure(66);

                }

            }

            if (helperHandle != IntPtr.Zero

                && WaitForSingleObject(helperHandle, 250) != WaitObject0)

            {

                if (!TerminateProcess(helperHandle, 0x4b4f5659))

                {

                    if (WaitForSingleObject(helperHandle, 0) != WaitObject0)

                    {

                        throw new NativeFailure(66);

                    }

                }

                if (WaitForSingleObject(

                    helperHandle,

                    unchecked((uint)RemainingMilliseconds(deadline, 66))) != WaitObject0)

                {

                    throw new NativeFailure(66);

                }

            }

        }

        finally

        {

            if (parentHandle != IntPtr.Zero)

            {

                CloseHandle(parentHandle);

            }

            if (helperHandle != IntPtr.Zero)

            {

                CloseHandle(helperHandle);

            }

        }

    }



    private static IntPtr OpenExactProcessForTermination(

        ProcessProof expected,

        TokenIdentity currentIdentity,

        out ProcessProof actual)

    {

        actual = null;

        IntPtr handle = OpenProcess(

            ProcessQueryLimitedInformation | Synchronize | ProcessTerminate,

            false,

            unchecked((uint)expected.ProcessId));

        if (handle == IntPtr.Zero)

        {

            if (Marshal.GetLastWin32Error() == ErrorInvalidParameter)

            {

                return IntPtr.Zero;

            }

            throw new NativeFailure(66);

        }

        try

        {

            if (!IsProcessAlive(handle))

            {

                CloseHandle(handle);

                return IntPtr.Zero;

            }

            try

            {

                actual = ReadProcessProof(handle, expected.ProcessId);

            }

            catch (NativeFailure)

            {

                if (!IsProcessAlive(handle))

                {

                    CloseHandle(handle);

                    return IntPtr.Zero;

                }

                throw;

            }

            if (actual.CreationFileTime != expected.CreationFileTime)

            {

                // A reused PID is not proof that the claimed process is

                // absent.  Refuse rather than allowing one side of a claimed

                // pair to authorize termination of the other.

                throw new NativeFailure(66);

            }

            if (!FixedEquals(actual.ImagePathHash, expected.ImagePathHash))

            {

                throw new NativeFailure(66);

            }

            RequireSameIdentity(currentIdentity, actual.Identity, 66);

            RequireProcessAlive(handle, 66);

            return handle;

        }

        catch

        {

            CloseHandle(handle);

            throw;

        }

    }



#if !KOVYA_BOOTSTRAP

    private static int RunAssertTerminated()

    {

        Stream standardInput = Console.OpenStandardInput();

        Stream standardOutput = Console.OpenStandardOutput();

        TerminationEndpoint endpoint = ParseTerminationEndpoint(ReadAsciiLine(

            standardInput,

            MaximumControlLineBytes,

            DeadlineAfter(StartupHandshakeTimeoutMilliseconds)));

        TokenIdentity currentIdentity = ReadCurrentIdentity();

        RequireOrdinaryIdentity(currentIdentity, 66);

        RequireEndpointIdentity(endpoint.Server, currentIdentity);

        RequireVerifierInstallation(endpoint);

        RequireExactProcessAbsent(endpoint.ParentProcess);

        RequireExactProcessAbsent(ToProcessProof(endpoint.Server));

        RequireNoMatchingHelperProcess(endpoint.Server.ServerImagePathHash, currentIdentity);

        RequirePipeAbsent(endpoint.Server.PublicPipeLeaf, endpoint.TimeoutMilliseconds);

        WriteAsciiLine(

            standardOutput,

            AbsentTag + "\t" + endpoint.Server.BrokerBinding + "\t" + endpoint.Server.BrokerInstance,

            DeadlineAfter(endpoint.TimeoutMilliseconds));

        return 0;

    }

#endif



#if !KOVYA_BOOTSTRAP

    private static int RunAssertHelperAbsent()

    {

        Stream standardOutput = Console.OpenStandardOutput();

        TokenIdentity currentIdentity = ReadCurrentIdentity();

        RequireOrdinaryIdentity(currentIdentity, 66);

        ProcessProof currentProof;

        using (Process current = Process.GetCurrentProcess())

        {

            currentProof = ReadProcessProof(current.Handle, current.Id);

        }

        RequireNoMatchingHelperProcess(currentProof.ImagePathHash, currentIdentity);

        WriteAsciiLine(

            standardOutput,

            AbsentTag,

            DeadlineAfter(StartupHandshakeTimeoutMilliseconds));

        return 0;

    }

#endif



#if !KOVYA_BOOTSTRAP

    private static int RunAssertFixedRootAbsent()

    {

        Stream standardInput = Console.OpenStandardInput();

        Stream standardOutput = Console.OpenStandardOutput();

        string[] fields = SplitControlLine(ReadAsciiLine(

            standardInput,

            MaximumControlLineBytes,

            DeadlineAfter(StartupHandshakeTimeoutMilliseconds)), 5);

        if (!FixedEquals(fields[0], FixedRootAbsenceTag)

            || !IsLowerHex(fields[1], 64)

            || !IsLowerHex(fields[2], 64)

            || !FixedEquals(fields[4], "END"))

        {

            throw new NativeFailure(64);

        }

        int timeoutMilliseconds = ParseTimeout(fields[3]);

        TokenIdentity currentIdentity = ReadCurrentIdentity();

        RequireOrdinaryIdentity(currentIdentity, 66);

        RequireNoMatchingHelperProcess(fields[2], currentIdentity);

        WriteAsciiLine(

            standardOutput,

            FixedRootAbsentTag + "\t" + fields[1],

            DeadlineAfter(timeoutMilliseconds));

        return 0;

    }

#endif



    [DllImport("kernel32.dll",EntryPoint="GetTickCount64")]

    private static extern ulong PhaseTicks();

    private sealed class PhaseEnvelope

    {

        internal string Tuple,RequestId,Operation,Instance;

        internal ulong Deadline;

        private string server,stage="sent";

        private ulong sequence,account,memory;

        private bool sealedTerminal;

        private static ulong Number(string value,bool zero=false) {

            ulong result;if(String.IsNullOrEmpty(value)||value.Length>20||!UInt64.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out result)||(!zero&&result==0)||result.ToString(CultureInfo.InvariantCulture)!=value)throw new NativeFailure(70);return result;

        }

        private static string[] Header(byte[] bytes) {

            int end=Array.IndexOf(bytes,(byte)10);if(end<0||end>1024)throw new NativeFailure(70);

            for(int i=0;i<end;i++)if(bytes[i]!=9&&(bytes[i]<32||bytes[i]>126))throw new NativeFailure(70);

            return Encoding.ASCII.GetString(bytes,0,end).Split('\t');

        }

        internal static PhaseEnvelope Read(byte[] bytes,HostConfiguration configuration) {

            string[] f=Header(bytes);Guid id;

            if(f.Length!=8||f[0]!="KOVYA_REQUEST_V2"||!IsLowerHex(f[1],64)||!Guid.TryParseExact(f[2],"D",out id)||id.ToString("D")!=f[2]

                ||f[6]!=configuration.BrokerInstance||!IsLowerHex(f[6],32))throw new NativeFailure(70);

            Number(f[3]);Number(f[4]);ulong deadline=Number(f[7]);if(deadline>PhaseTicks()+1000)throw new NativeFailure(70);

            if(f[5]!="recall"&&f[5]!="capture"&&f[5]!="turn_prompt"&&f[5]!="hello"&&f[5]!="status"&&f[5]!="shutdown")throw new NativeFailure(70);

#if KOVYA_MANAGED_RUNTIME && !KOVYA_MSIX

            if(f[4]!=RuntimeProfileChild.Generation)throw new NativeFailure(70);

#else

            throw new NativeFailure(70);

#endif

            return new PhaseEnvelope{Tuple=String.Join("\t",f,1,7),RequestId=f[2],Operation=f[5],Instance=f[6],Deadline=deadline};

        }

        internal static bool Terminal(byte[] bytes) {string[] f=Header(bytes);if(f.Length!=16||f[0]!="KOVYA_PHASE_V2"||(f[15]!="0"&&f[15]!="1"))throw new NativeFailure(70);return f[15]=="1";}

        internal void Accept(byte[] bytes) {

            string[] f=Header(bytes);bool terminal=Terminal(bytes);

            if(sealedTerminal||String.Join("\t",f,1,7)!=Tuple||Number(f[9])!=sequence+1||sequence>=32)throw new NativeFailure(70);

            Number(f[8]);if(server!=null&&server!=f[8])throw new NativeFailure(70);

            ulong a=Number(f[12],true),m=Number(f[13],true);if(a<account||m<memory||a>8||m>8)throw new NativeFailure(70);

            if(f[11].Length<1||f[11].Length>80)throw new NativeFailure(70);

            foreach(char c in f[11])if((c<'a'||c>'z')&&(c<'0'||c>'9')&&c!='_')throw new NativeFailure(70);

            if(!terminal){

                if(f[11]!="none")throw new NativeFailure(70);

                if(f[10]=="received"){if(sequence!=0||a!=0||m!=0)throw new NativeFailure(70);}

                else if(f[10]=="admitted"){if(stage!="received"||a!=0||m!=0)throw new NativeFailure(70);}

                else if(f[10]=="started"){if((stage!="admitted"&&stage!="started")||a+m<=account+memory)throw new NativeFailure(70);}

                else throw new NativeFailure(70);

            }else {

                if(f[10]!="terminal"&&f[10]!="refused_queue")throw new NativeFailure(70);

                if(f[10]=="refused_queue"&&(stage!="received"||a!=0||m!=0||f[11]!="broker_deadline_refused"))throw new NativeFailure(70);

                if(f[11]=="none"&&stage!="admitted"&&stage!="started")throw new NativeFailure(70);

            }

            server=f[8];stage=f[10];sequence++;account=a;memory=m;sealedTerminal=terminal;

        }

        internal byte[] RefuseArrival() {

            if(sealedTerminal)throw new NativeFailure(70);sealedTerminal=true;

            string header="KOVYA_PHASE_V2\t"+Tuple+"\t-\t1\trefused_arrival\tbroker_deadline_refused\t0\t0\tnone\t1\n";

            // Fixed projection, no request body, path, arbitrary reason or secrets.

#if KOVYA_PHASE_TEST && KOVYA_MANAGED_RUNTIME
            if(File.Exists(Path.Combine(RuntimeProfileChild.Home,"phase-crash")))Environment.Exit(74);
#endif
            SealIngressAudit("KOVYA_AUDIT_V3\tserver\t"+Tuple+"\tnull\t1\trefused_arrival\tbroker_deadline_refused\tnone\t1\t1\t0\t0\n");

            string body="{\"broker_instance\":\""+Instance+"\",\"error_code\":\"broker_deadline_refused\",\"failure_reason\":\"broker_deadline_refused\",\"ok\":false,\"operation\":\""+Operation+"\",\"request_id\":\""+RequestId+"\",\"schema_version\":\"kovya.windows-memory-broker.v1\"}";

            return Encoding.UTF8.GetBytes(header+body);

        }

        private void SealIngressAudit(string header) {

#if KOVYA_MANAGED_RUNTIME && !KOVYA_MSIX

            if(Environment.GetEnvironmentVariable("KOVYA_AUTH_LOG_LEVEL")=="off")return;

            // The refusal transition owns exactly one fixed-size create/write.

            // A failed attempt is unavailable; there is no delayed flush/retry.

            try { RuntimeSerialization.SealPhaseAudit(RuntimeProfileChild.Home,Tuple,header); } catch { }

#endif

        }

    }



    private static void HandlePublicConnection(

        NamedPipeServerStream publicPipe,

        PrivateMultiplexer privateTransport,

        TokenIdentity ownerIdentity,

        HostConfiguration configuration)

    {

        byte[] request = null;

        byte[] response = null;

        try

        {

            long exchangeDeadline = DeadlineAfter(configuration.TimeoutMilliseconds);

            string preamble = ReadAsciiLine(

                publicPipe,

                MaximumControlLineBytes,

                exchangeDeadline);

            string expectedPreamble = PublicPreambleTag + "\t" + configuration.BrokerBinding + "\t" + configuration.BrokerInstance;

            bool phaseProtocol=FixedEquals(preamble,"KOVYA_NATIVE_PUBLIC_V2\t"+configuration.BrokerBinding+"\t"+configuration.BrokerInstance);

            if (!phaseProtocol && !FixedEquals(preamble, expectedPreamble))

            {

                throw new NativeFailure(66);

            }

            VerifyConnectedPublicClient(

                publicPipe.SafePipeHandle.DangerousGetHandle(),

                ownerIdentity);

            WriteAsciiLine(

                publicPipe,

                (phaseProtocol?"KOVYA_NATIVE_ACK_V2":PublicAckTag) + "\t" + configuration.BrokerBinding + "\t" + configuration.BrokerInstance,

                exchangeDeadline);



#if KOVYA_PHASE_TEST && KOVYA_MANAGED_RUNTIME
            if(File.Exists(Path.Combine(RuntimeProfileChild.Home,"phase-never-frame"))){Thread.Sleep(configuration.TimeoutMilliseconds+50);return;}
#endif
            request = ReadFrame(publicPipe, exchangeDeadline);
#if KOVYA_PHASE_TEST && KOVYA_MANAGED_RUNTIME
            if(File.Exists(Path.Combine(RuntimeProfileChild.Home,"phase-delay")))Thread.Sleep(220);
#endif

            if(phaseProtocol) {

                PhaseEnvelope phase=PhaseEnvelope.Read(request,configuration);

                ulong tick=PhaseTicks();

                if(tick>=phase.Deadline){response=phase.RefuseArrival();return;}

                exchangeDeadline=Math.Min(exchangeDeadline,DeadlineAfter((int)(phase.Deadline-tick)));

                response=privateTransport.Exchange(request,exchangeDeadline,delegate(byte[] progress){phase.Accept(progress);WriteFrame(publicPipe,progress,exchangeDeadline);});

                phase.Accept(response);

            }else response = privateTransport.Exchange(request, exchangeDeadline);

            WriteFrame(publicPipe, response, exchangeDeadline);

        }

        catch

        {

            return;

        }

        finally

        {

            Clear(request);

            Clear(response);

        }

    }



    private static NamedPipeServerStream CreateOwnedPipe(

        string pipeLeaf,

        TokenIdentity ownerIdentity,

        int timeoutMilliseconds,

        int maximumInstances,

        bool firstInstance)

    {

        IntPtr securityDescriptor = IntPtr.Zero;

        uint securityDescriptorSize;

        string sddl = "O:" + ownerIdentity.UserSid

            + "G:" + ownerIdentity.LogonSid

            + "D:P(A;;GA;;;" + ownerIdentity.LogonSid + ")(A;;GA;;;SY)";

        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(

            sddl,

            SecurityDescriptorRevision,

            out securityDescriptor,

            out securityDescriptorSize))

        {

            throw new NativeFailure(66);

        }



        try

        {

            SecurityAttributes attributes = new SecurityAttributes();

            attributes.Length = Marshal.SizeOf(typeof(SecurityAttributes));

            attributes.SecurityDescriptor = securityDescriptor;

            attributes.InheritHandle = 0;



            string pipePath = "\\\\.\\pipe\\" + pipeLeaf;

            uint openMode = PipeAccessDuplex | FileFlagOverlapped;

            if (firstInstance)

            {

                openMode |= FileFlagFirstPipeInstance;

            }

            IntPtr rawHandle = CreateNamedPipe(

                pipePath,

                openMode,

                PipeTypeByte | PipeReadmodeByte | PipeWait | PipeRejectRemoteClients,

                unchecked((uint)maximumInstances),

                65536,

                65536,

                unchecked((uint)timeoutMilliseconds),

                ref attributes);

            if (rawHandle == InvalidHandleValue)

            {

                throw new NativeFailure(66);

            }



            SafePipeHandle safeHandle = new SafePipeHandle(rawHandle, true);

            try

            {

                return new NamedPipeServerStream(PipeDirection.InOut, true, false, safeHandle);

            }

            catch

            {

                safeHandle.Dispose();

                throw;

            }

        }

        finally

        {

            if (securityDescriptor != IntPtr.Zero)

            {

                LocalFree(securityDescriptor);

            }

        }

    }



    private static bool CompleteWaitForConnection(

        NamedPipeServerStream pipe,

        IAsyncResult pending,

        IntPtr parentHandle,

        long? deadline,

        PrivateMultiplexer requiredTransport)

    {

        try

        {

            while (!pending.AsyncWaitHandle.WaitOne(25))

            {

                if (!IsProcessAlive(parentHandle))

                {

                    pipe.Dispose();

                    return false;

                }

                if (requiredTransport != null && !requiredTransport.IsHealthy)

                {

                    pipe.Dispose();

                    return false;

                }

                if (deadline.HasValue && RemainingMillisecondsOrZero(deadline.Value) == 0)

                {

                    pipe.Dispose();

                    throw new NativeFailure(67);

                }

            }

            pipe.EndWaitForConnection(pending);

            return true;

        }

        finally

        {

            pending.AsyncWaitHandle.Close();

        }

    }



    private static void VerifyConnectedPublicClient(IntPtr pipeHandle, TokenIdentity ownerIdentity)

    {

        uint clientProcessId;

        uint clientSessionId;

        if (!GetNamedPipeClientProcessId(pipeHandle, out clientProcessId)

            || clientProcessId < 1

            || !GetNamedPipeClientSessionId(pipeHandle, out clientSessionId))

        {

            throw new NativeFailure(66);

        }



        if (!ImpersonateNamedPipeClient(pipeHandle))

        {

            throw new NativeFailure(66);

        }



        IntPtr token = IntPtr.Zero;

        try

        {

            if (!OpenThreadToken(GetCurrentThread(), TokenQuery, true, out token))

            {

                throw new NativeFailure(66);

            }

            TokenIdentity clientIdentity = ReadTokenIdentity(token);

            RequireSameIdentity(ownerIdentity, clientIdentity, 66);

            if (clientSessionId != clientIdentity.SessionId)

            {

                throw new NativeFailure(66);

            }

        }

        finally

        {

            if (token != IntPtr.Zero)

            {

                CloseHandle(token);

            }

            if (!RevertToSelf())

            {

                TerminateWithoutMessage(68);

            }

        }

    }



    private static void VerifyConnectedPublicServer(

        IntPtr pipeHandle,

        ClientEndpoint endpoint,

        TokenIdentity currentIdentity)

    {

        uint serverProcessId;

        uint serverSessionId;

        if (!GetNamedPipeServerProcessId(pipeHandle, out serverProcessId)

            || serverProcessId != unchecked((uint)endpoint.ServerProcessId)

            || !GetNamedPipeServerSessionId(pipeHandle, out serverSessionId)

            || serverSessionId != endpoint.SessionId)

        {

            throw new NativeFailure(66);

        }



        IntPtr serverHandle = OpenProcess(

            ProcessQueryLimitedInformation | Synchronize,

            false,

            serverProcessId);

        if (serverHandle == IntPtr.Zero)

        {

            throw new NativeFailure(66);

        }



        try

        {

            RequireProcessAlive(serverHandle, 66);

            ProcessProof proof = ReadProcessProof(serverHandle, endpoint.ServerProcessId);

            if (proof.CreationFileTime != endpoint.ServerCreationFileTime

                || !FixedEquals(proof.ImagePathHash, endpoint.ServerImagePathHash)

                || !FixedEquals(proof.Identity.UserSidHash, endpoint.OwnerSidHash)

                || !FixedEquals(proof.Identity.AuthenticationIdHash, endpoint.AuthenticationIdHash)

                || proof.Identity.SessionId != endpoint.SessionId)

            {

                throw new NativeFailure(66);

            }

            RequireSameIdentity(currentIdentity, proof.Identity, 66);

            RequireProcessAlive(serverHandle, 66);

        }

        finally

        {

            CloseHandle(serverHandle);

        }

    }



    private static void RequireEndpointIdentity(ClientEndpoint endpoint, TokenIdentity currentIdentity)

    {

        if (!FixedEquals(currentIdentity.UserSidHash, endpoint.OwnerSidHash)

            || !FixedEquals(currentIdentity.AuthenticationIdHash, endpoint.AuthenticationIdHash)

            || currentIdentity.SessionId != endpoint.SessionId)

        {

            throw new NativeFailure(66);

        }

    }



    private static void VerifyEndpointParent(

        TerminationEndpoint endpoint,

        TokenIdentity currentIdentity)

    {

        if (GetParentProcessId(endpoint.Server.ServerProcessId) != endpoint.ParentProcess.ProcessId)

        {

            throw new NativeFailure(66);

        }

        IntPtr parentHandle = OpenProcess(

            ProcessQueryLimitedInformation | Synchronize,

            false,

            unchecked((uint)endpoint.ParentProcess.ProcessId));

        if (parentHandle == IntPtr.Zero)

        {

            throw new NativeFailure(66);

        }

        try

        {

            RequireProcessAlive(parentHandle, 66);

            ProcessProof actual = ReadProcessProof(parentHandle, endpoint.ParentProcess.ProcessId);

            RequireSameProcessProof(endpoint.ParentProcess, actual, 66);

            RequireSameIdentity(currentIdentity, actual.Identity, 66);

            RequireProcessAlive(parentHandle, 66);

        }

        finally

        {

            CloseHandle(parentHandle);

        }

    }



    private static void RequireSameProcessProof(ProcessProof expected, ProcessProof actual, int exitCode)

    {

        if (expected == null || actual == null

            || expected.ProcessId != actual.ProcessId

            || expected.CreationFileTime != actual.CreationFileTime

            || !FixedEquals(expected.ImagePathHash, actual.ImagePathHash))

        {

            throw new NativeFailure(exitCode);

        }

    }



    private static ProcessProof ToProcessProof(ClientEndpoint endpoint)

    {

        ProcessProof proof = new ProcessProof();

        proof.ProcessId = endpoint.ServerProcessId;

        proof.CreationFileTime = endpoint.ServerCreationFileTime;

        proof.ImagePathHash = endpoint.ServerImagePathHash;

        return proof;

    }



    private static void WaitForExactProcessAbsent(ProcessProof expected, int timeoutMilliseconds)

    {

        long deadline = DeadlineAfter(timeoutMilliseconds);

        do

        {

            if (!IsExactProcessPresent(expected))

            {

                return;

            }

            Thread.Sleep(10);

        }

        while (RemainingMillisecondsOrZero(deadline) > 0);

        throw new NativeFailure(66);

    }



    private static void RequireExactProcessAbsent(ProcessProof expected)

    {

        if (IsExactProcessPresent(expected))

        {

            throw new NativeFailure(66);

        }

    }



    private static bool IsExactProcessPresent(ProcessProof expected)

    {

        IntPtr handle = OpenProcess(

            ProcessQueryLimitedInformation | Synchronize,

            false,

            unchecked((uint)expected.ProcessId));

        if (handle == IntPtr.Zero)

        {

            if (Marshal.GetLastWin32Error() == ErrorInvalidParameter)

            {

                return false;

            }

            throw new NativeFailure(66);

        }

        try

        {

            if (!IsProcessAlive(handle))

            {

                return false;

            }

            ProcessProof actual;

            try

            {

                actual = ReadProcessProof(handle, expected.ProcessId);

            }

            catch (NativeFailure)

            {

                if (!IsProcessAlive(handle))

                {

                    return false;

                }

                return true;

            }

            if (!IsProcessAlive(handle))

            {

                return false;

            }

            if (actual.CreationFileTime != expected.CreationFileTime)

            {

                return false;

            }

            if (!FixedEquals(actual.ImagePathHash, expected.ImagePathHash))

            {

                throw new NativeFailure(66);

            }

            return true;

        }

        finally

        {

            CloseHandle(handle);

        }

    }



    private static void RequireNoMatchingHelperProcess(

        string expectedImagePathHash,

        TokenIdentity currentIdentity)

    {

        int currentProcessId = Process.GetCurrentProcess().Id;

        IntPtr snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);

        if (snapshot == InvalidHandleValue)

        {

            throw new NativeFailure(66);

        }

        try

        {

            ProcessEntry32 entry = new ProcessEntry32();

            entry.Size = unchecked((uint)Marshal.SizeOf(typeof(ProcessEntry32)));

            if (!Process32First(snapshot, ref entry))

            {

                throw new NativeFailure(66);

            }

            do

            {

                int processId = entry.ProcessId <= Int32.MaxValue

                    ? unchecked((int)entry.ProcessId) : 0;

                if (processId > 0 && processId != currentProcessId

                    && String.Equals(

                        entry.ExeFile,

                        "kovya_windows_broker_native.exe",

                        StringComparison.OrdinalIgnoreCase))

                {

                    IntPtr handle = OpenProcess(

                        ProcessQueryLimitedInformation | Synchronize,

                        false,

                        entry.ProcessId);

                    if (handle != IntPtr.Zero)

                    {

                        try

                        {

                            if (IsProcessAlive(handle))

                            {

                                ProcessProof proof;

                                try

                                {

                                    proof = ReadProcessProof(handle, processId);

                                }

                                catch (NativeFailure)

                                {

                                    if (!IsProcessAlive(handle))

                                    {

                                        continue;

                                    }

                                    throw;

                                }

                                if (FixedEquals(proof.ImagePathHash, expectedImagePathHash)

                                    && FixedEquals(proof.Identity.UserSidHash, currentIdentity.UserSidHash))

                                {

                                    throw new NativeFailure(66);

                                }

                            }

                        }

                        catch (NativeFailure)

                        {

                            throw;

                        }

                        catch

                        {

                            if (IsProcessAlive(handle))

                            {

                                throw new NativeFailure(66);

                            }

                        }

                        finally

                        {

                            CloseHandle(handle);

                        }

                    }

                    else if (Marshal.GetLastWin32Error() != ErrorInvalidParameter)

                    {

                        throw new NativeFailure(66);

                    }

                }

                entry.Size = unchecked((uint)Marshal.SizeOf(typeof(ProcessEntry32)));

            }

            while (Process32Next(snapshot, ref entry));

            if (Marshal.GetLastWin32Error() != ErrorNoMoreFiles)

            {

                throw new NativeFailure(66);

            }

        }

        finally

        {

            CloseHandle(snapshot);

        }

    }



    private static void RequirePipeAbsent(string pipeLeaf, int timeoutMilliseconds)

    {

        long deadline = DeadlineAfter(timeoutMilliseconds);

        while (true)

        {

            IntPtr pipe = CreateFile(

                "\\\\.\\pipe\\" + pipeLeaf,

                GenericRead | GenericWrite,

                0,

                IntPtr.Zero,

                OpenExisting,

                SecuritySqosPresent | SecurityIdentification,

                IntPtr.Zero);

            if (pipe != InvalidHandleValue)

            {

                CloseHandle(pipe);

                throw new NativeFailure(66);

            }

            int error = Marshal.GetLastWin32Error();

            if (error == ErrorFileNotFound || error == ErrorPathNotFound)

            {

                return;

            }

            if (error != ErrorPipeBusy || RemainingMillisecondsOrZero(deadline) == 0)

            {

                throw new NativeFailure(66);

            }

            Thread.Sleep(10);

        }

    }



    private static void VerifyConnectedPrivateParentClient(

        IntPtr pipeHandle,

        IntPtr parentHandle,

        ProcessProof parentProof,

        TokenIdentity currentIdentity)

    {

        uint clientProcessId;

        uint clientSessionId;

        if (!GetNamedPipeClientProcessId(pipeHandle, out clientProcessId)

            || clientProcessId != unchecked((uint)parentProof.ProcessId)

            || !GetNamedPipeClientSessionId(pipeHandle, out clientSessionId)

            || clientSessionId != currentIdentity.SessionId)

        {

            throw new NativeFailure(65);

        }



        RequireProcessAlive(parentHandle, 65);

        ProcessProof currentProof = ReadProcessProof(parentHandle, parentProof.ProcessId);

        if (currentProof.CreationFileTime != parentProof.CreationFileTime

            || !FixedEquals(currentProof.ImagePathHash, parentProof.ImagePathHash))

        {

            throw new NativeFailure(65);

        }

        RequireSameIdentity(currentIdentity, currentProof.Identity, 65);



        if (!ImpersonateNamedPipeClient(pipeHandle))

        {

            throw new NativeFailure(65);

        }

        IntPtr token = IntPtr.Zero;

        try

        {

            if (!OpenThreadToken(GetCurrentThread(), TokenQuery, true, out token))

            {

                throw new NativeFailure(65);

            }

            TokenIdentity connectedIdentity = ReadTokenIdentity(token);

            RequireSameIdentity(currentIdentity, connectedIdentity, 65);

            if (connectedIdentity.SessionId != clientSessionId)

            {

                throw new NativeFailure(65);

            }

        }

        finally

        {

            if (token != IntPtr.Zero)

            {

                CloseHandle(token);

            }

            if (!RevertToSelf())

            {

                TerminateWithoutMessage(68);

            }

        }

    }



    private static string BuildIdentityLine(ProcessProof hostProof, ProcessProof parentProof)

    {

        return IdentityTag

            + "\t" + hostProof.ProcessId.ToString(CultureInfo.InvariantCulture)

            + "\t" + hostProof.CreationFileTime.ToString(CultureInfo.InvariantCulture)

            + "\t" + hostProof.ImagePathHash

            + "\t" + hostProof.Identity.UserSidHash

            + "\t" + hostProof.Identity.AuthenticationIdHash

            + "\t" + hostProof.Identity.SessionId.ToString(CultureInfo.InvariantCulture)

            + "\t" + parentProof.ProcessId.ToString(CultureInfo.InvariantCulture)

            + "\t" + parentProof.CreationFileTime.ToString(CultureInfo.InvariantCulture)

            + "\t" + parentProof.ImagePathHash

            + "\t" + CompiledRole;

    }



    private static string BuildReadyLine(

        ProcessProof hostProof,

        TokenIdentity currentIdentity,

        HostConfiguration configuration)

    {

        return ReadyTag

            + "\t" + configuration.PublicPipeLeaf

            + "\t" + hostProof.ProcessId.ToString(CultureInfo.InvariantCulture)

            + "\t" + hostProof.CreationFileTime.ToString(CultureInfo.InvariantCulture)

            + "\t" + hostProof.ImagePathHash

            + "\t" + currentIdentity.UserSidHash

            + "\t" + currentIdentity.AuthenticationIdHash

            + "\t" + currentIdentity.SessionId.ToString(CultureInfo.InvariantCulture)

            + "\t" + configuration.BrokerBinding

            + "\t" + configuration.BrokerInstance;

    }



    private static string BuildPrivateReadyLine(

        ProcessProof hostProof,

        TokenIdentity currentIdentity,

        HostConfiguration configuration)

    {

        return PrivateReadyTag

            + "\t" + configuration.PrivatePipeLeaf

            + "\t" + hostProof.ProcessId.ToString(CultureInfo.InvariantCulture)

            + "\t" + hostProof.CreationFileTime.ToString(CultureInfo.InvariantCulture)

            + "\t" + hostProof.ImagePathHash

            + "\t" + currentIdentity.UserSidHash

            + "\t" + currentIdentity.AuthenticationIdHash

            + "\t" + currentIdentity.SessionId.ToString(CultureInfo.InvariantCulture)

            + "\t" + configuration.BrokerBinding

            + "\t" + configuration.BrokerInstance;

    }



    private static HostConfiguration ParseHostConfiguration(string line)

    {

        string[] fields = SplitControlLine(line, 8);

        if (!FixedEquals(fields[0], ConfigTag)

            || !IsPublicPipeLeaf(fields[1])

            || !IsPrivatePipeLeaf(fields[2])

            || !IsLowerHex(fields[3], 64)

            || !IsLowerHex(fields[4], 32)

            || !IsLowerHex(fields[5], 64))

        {

            throw new NativeFailure(64);

        }



        int timeoutMilliseconds = ParseTimeout(fields[6]);

        if (!FixedEquals(fields[7], "END"))

        {

            throw new NativeFailure(64);

        }



        HostConfiguration configuration = new HostConfiguration();

        configuration.PublicPipeLeaf = fields[1];

        configuration.PrivatePipeLeaf = fields[2];

        configuration.BrokerBinding = fields[3];

        configuration.BrokerInstance = fields[4];

        configuration.InstallationRootHash = fields[5];

        configuration.TimeoutMilliseconds = timeoutMilliseconds;

        return configuration;

    }



    private static TerminationEndpoint ParseTerminationEndpoint(string line)

    {

        string[] fields = SplitControlLine(line, 16);

        if (!FixedEquals(fields[0], TerminationEndpointTag)

            || !IsPublicPipeLeaf(fields[1])

            || !IsLowerHex(fields[4], 64)

            || !IsLowerHex(fields[5], 64)

            || !IsLowerHex(fields[6], 64)

            || !IsLowerHex(fields[8], 64)

            || !IsLowerHex(fields[9], 32)

            || !IsLowerHex(fields[10], 64)

            || !IsLowerHex(fields[13], 64)

            || !FixedEquals(fields[1], "kovya-memory-v1-" + fields[8].Substring(0, 48))

            || !FixedEquals(fields[15], "END"))

        {

            throw new NativeFailure(64);

        }

        int serverProcessId;

        ulong serverCreation;

        uint sessionId;

        int parentProcessId;

        ulong parentCreation;

        if (!Int32.TryParse(fields[2], NumberStyles.None, CultureInfo.InvariantCulture, out serverProcessId)

            || serverProcessId < 1

            || !UInt64.TryParse(fields[3], NumberStyles.None, CultureInfo.InvariantCulture, out serverCreation)

            || serverCreation == 0

            || !UInt32.TryParse(fields[7], NumberStyles.None, CultureInfo.InvariantCulture, out sessionId)

            || !Int32.TryParse(fields[11], NumberStyles.None, CultureInfo.InvariantCulture, out parentProcessId)

            || parentProcessId < 1

            || parentProcessId == serverProcessId

            || !UInt64.TryParse(fields[12], NumberStyles.None, CultureInfo.InvariantCulture, out parentCreation)

            || parentCreation == 0)

        {

            throw new NativeFailure(64);

        }

        ClientEndpoint server = new ClientEndpoint();

        server.PublicPipeLeaf = fields[1];

        server.ServerProcessId = serverProcessId;

        server.ServerCreationFileTime = serverCreation;

        server.ServerImagePathHash = fields[4];

        server.OwnerSidHash = fields[5];

        server.AuthenticationIdHash = fields[6];

        server.SessionId = sessionId;

        server.BrokerBinding = fields[8];

        server.BrokerInstance = fields[9];

        server.TimeoutMilliseconds = ParseTimeout(fields[14]);

        ProcessProof parent = new ProcessProof();

        parent.ProcessId = parentProcessId;

        parent.CreationFileTime = parentCreation;

        parent.ImagePathHash = fields[13];

        TerminationEndpoint endpoint = new TerminationEndpoint();

        endpoint.Server = server;

        endpoint.InstallationRootHash = fields[10];

        endpoint.ParentProcess = parent;

        endpoint.TimeoutMilliseconds = server.TimeoutMilliseconds;

        return endpoint;

    }



    private static ClientEndpoint ParseClientEndpoint(string line)

    {

        string[] fields = SplitControlLine(line, 12);

        if (!FixedEquals(fields[0], EndpointTag)

            || !IsPublicPipeLeaf(fields[1])

            || !IsLowerHex(fields[4], 64)

            || !IsLowerHex(fields[5], 64)

            || !IsLowerHex(fields[6], 64)

            || !IsLowerHex(fields[8], 64)

            || !IsLowerHex(fields[9], 32)

            || !FixedEquals(fields[11], "END"))

        {

            throw new NativeFailure(64);

        }



        int serverProcessId;

        ulong serverCreationFileTime;

        uint sessionId;

        if (!Int32.TryParse(fields[2], NumberStyles.None, CultureInfo.InvariantCulture, out serverProcessId)

            || serverProcessId < 1

            || !UInt64.TryParse(fields[3], NumberStyles.None, CultureInfo.InvariantCulture, out serverCreationFileTime)

            || serverCreationFileTime == 0

            || !UInt32.TryParse(fields[7], NumberStyles.None, CultureInfo.InvariantCulture, out sessionId))

        {

            throw new NativeFailure(64);

        }



        ClientEndpoint endpoint = new ClientEndpoint();

        endpoint.PublicPipeLeaf = fields[1];

        endpoint.ServerProcessId = serverProcessId;

        endpoint.ServerCreationFileTime = serverCreationFileTime;

        endpoint.ServerImagePathHash = fields[4];

        endpoint.OwnerSidHash = fields[5];

        endpoint.AuthenticationIdHash = fields[6];

        endpoint.SessionId = sessionId;

        endpoint.BrokerBinding = fields[8];

        endpoint.BrokerInstance = fields[9];

        endpoint.TimeoutMilliseconds = ParseTimeout(fields[10]);

        return endpoint;

    }



    private static int ParseTimeout(string value)

    {

        int timeout;

        if (!Int32.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out timeout)

            || timeout < MinimumTimeoutMilliseconds

            || timeout > MaximumTimeoutMilliseconds)

        {

            throw new NativeFailure(64);

        }

        return timeout;

    }



    private static string[] SplitControlLine(string line, int expectedFields)

    {

        if (line == null || line.Length == 0 || line.Length > MaximumControlLineBytes)

        {

            throw new NativeFailure(64);

        }

        string[] fields = line.Split(new char[] { '\t' }, StringSplitOptions.None);

        if (fields.Length != expectedFields)

        {

            throw new NativeFailure(64);

        }

        for (int index = 0; index < fields.Length; index += 1)

        {

            if (fields[index].Length == 0 || fields[index].Length > 256)

            {

                throw new NativeFailure(64);

            }

        }

        return fields;

    }



    private static bool IsPublicPipeLeaf(string value)

    {

        const string prefix = "kovya-memory-v1-";

        return value != null

            && value.StartsWith(prefix, StringComparison.Ordinal)

            && IsLowerHex(value.Substring(prefix.Length), 48);

    }



    private static bool IsPrivatePipeLeaf(string value)

    {

        const string prefix = "kovya-memory-private-v1-";

        return value != null

            && value.StartsWith(prefix, StringComparison.Ordinal)

            && IsLowerHex(value.Substring(prefix.Length), 48);

    }



    private static bool IsLowerHex(string value, int exactLength)

    {

        if (value == null || value.Length != exactLength)

        {

            return false;

        }

        for (int index = 0; index < value.Length; index += 1)

        {

            char character = value[index];

            if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))

            {

                return false;

            }

        }

        return true;

    }



    private static TokenIdentity ReadCurrentIdentity()

    {

        IntPtr token;

        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out token))

        {

            throw new NativeFailure(65);

        }

        try

        {

            return ReadTokenIdentity(token);

        }

        finally

        {

            CloseHandle(token);

        }

    }



    private static TokenIdentity ReadTokenIdentity(IntPtr token)

    {

        string userSid;

        using (WindowsIdentity identity = new WindowsIdentity(token))

        {

            if (identity.User == null)

            {

                throw new NativeFailure(65);

            }

            userSid = identity.User.Value;

        }



        string logonSid = ReadLogonSid(token);

        TokenStatistics statistics = ReadTokenStatistics(token);

        uint sessionId = ReadTokenSessionId(token);

        string authenticationId = unchecked((uint)statistics.AuthenticationId.HighPart).ToString("x8", CultureInfo.InvariantCulture)

            + statistics.AuthenticationId.LowPart.ToString("x8", CultureInfo.InvariantCulture);



        TokenIdentity result = new TokenIdentity();

        result.UserSid = userSid;

        result.UserSidHash = Sha256Hex(userSid);

        result.LogonSid = logonSid;

        result.AuthenticationId = authenticationId;

        result.AuthenticationIdHash = Sha256Hex(authenticationId);

        result.SessionId = sessionId;

        result.IsElevated = ReadTokenElevation(token);

        result.IntegritySid = ReadTokenIntegritySid(token);

        return result;

    }



    private static string ReadLogonSid(IntPtr token)

    {

        int required;

        GetTokenInformation(token, TokenInformationClass.TokenGroups, IntPtr.Zero, 0, out required);

        if (required < 8 || required > 1024 * 1024)

        {

            throw new NativeFailure(65);

        }

        int allocatedLength = required;

        IntPtr buffer = Marshal.AllocHGlobal(allocatedLength);

        try

        {

            int returnedLength;

            if (!GetTokenInformation(

                token,

                TokenInformationClass.TokenGroups,

                buffer,

                allocatedLength,

                out returnedLength)

                || returnedLength < 8

                || returnedLength > allocatedLength)

            {

                throw new NativeFailure(65);

            }



            int groupCount = Marshal.ReadInt32(buffer);

            int firstGroupOffset = IntPtr.Size == 8 ? 8 : 4;

            int groupSize = Marshal.SizeOf(typeof(SidAndAttributes));

            if (groupCount < 1 || groupCount > 4096

                || firstGroupOffset + ((long)groupCount * groupSize) > returnedLength)

            {

                throw new NativeFailure(65);

            }



            string logonSid = null;

            for (int index = 0; index < groupCount; index += 1)

            {

                IntPtr groupPointer = IntPtr.Add(buffer, firstGroupOffset + (index * groupSize));

                SidAndAttributes group = (SidAndAttributes)Marshal.PtrToStructure(

                    groupPointer,

                    typeof(SidAndAttributes));

                if ((group.Attributes & SeGroupLogonId) != SeGroupLogonId)

                {

                    continue;

                }

                SecurityIdentifier sid = new SecurityIdentifier(group.Sid);

                if (logonSid != null && !String.Equals(logonSid, sid.Value, StringComparison.Ordinal))

                {

                    throw new NativeFailure(65);

                }

                logonSid = sid.Value;

            }

            if (logonSid == null)

            {

                throw new NativeFailure(65);

            }

            return logonSid;

        }

        finally

        {

            ZeroAndFree(buffer, allocatedLength);

        }

    }



    private static TokenStatistics ReadTokenStatistics(IntPtr token)

    {

        int required;

        GetTokenInformation(token, TokenInformationClass.TokenStatistics, IntPtr.Zero, 0, out required);

        if (required < Marshal.SizeOf(typeof(TokenStatistics)) || required > 4096)

        {

            throw new NativeFailure(65);

        }



        int allocatedLength = required;

        IntPtr buffer = Marshal.AllocHGlobal(allocatedLength);

        try

        {

            int returnedLength;

            if (!GetTokenInformation(

                token,

                TokenInformationClass.TokenStatistics,

                buffer,

                allocatedLength,

                out returnedLength)

                || returnedLength < Marshal.SizeOf(typeof(TokenStatistics))

                || returnedLength > allocatedLength)

            {

                throw new NativeFailure(65);

            }

            return (TokenStatistics)Marshal.PtrToStructure(buffer, typeof(TokenStatistics));

        }

        finally

        {

            ZeroAndFree(buffer, allocatedLength);

        }

    }



    private static uint ReadTokenSessionId(IntPtr token)

    {

        int required;

        GetTokenInformation(token, TokenInformationClass.TokenSessionId, IntPtr.Zero, 0, out required);

        if (required != sizeof(uint))

        {

            throw new NativeFailure(65);

        }



        int allocatedLength = required;

        IntPtr buffer = Marshal.AllocHGlobal(allocatedLength);

        try

        {

            int returnedLength;

            if (!GetTokenInformation(

                token,

                TokenInformationClass.TokenSessionId,

                buffer,

                allocatedLength,

                out returnedLength)

                || returnedLength != sizeof(uint))

            {

                throw new NativeFailure(65);

            }

            return unchecked((uint)Marshal.ReadInt32(buffer));

        }

        finally

        {

            ZeroAndFree(buffer, allocatedLength);

        }

    }



    private static bool ReadTokenElevation(IntPtr token)

    {

        int required;

        GetTokenInformation(token, TokenInformationClass.TokenElevation, IntPtr.Zero, 0, out required);

        if (required != sizeof(int))

        {

            throw new NativeFailure(65);

        }

        int allocatedLength = required;

        IntPtr buffer = Marshal.AllocHGlobal(allocatedLength);

        try

        {

            int returnedLength;

            if (!GetTokenInformation(

                token,

                TokenInformationClass.TokenElevation,

                buffer,

                allocatedLength,

                out returnedLength)

                || returnedLength != sizeof(int))

            {

                throw new NativeFailure(65);

            }

            return Marshal.ReadInt32(buffer) != 0;

        }

        finally

        {

            ZeroAndFree(buffer, allocatedLength);

        }

    }



    private static string ReadTokenIntegritySid(IntPtr token)

    {

        int required;

        GetTokenInformation(token, TokenInformationClass.TokenIntegrityLevel, IntPtr.Zero, 0, out required);

        if (required < Marshal.SizeOf(typeof(SidAndAttributes)) || required > 4096)

        {

            throw new NativeFailure(65);

        }

        int allocatedLength = required;

        IntPtr buffer = Marshal.AllocHGlobal(allocatedLength);

        try

        {

            int returnedLength;

            if (!GetTokenInformation(

                token,

                TokenInformationClass.TokenIntegrityLevel,

                buffer,

                allocatedLength,

                out returnedLength)

                || returnedLength < Marshal.SizeOf(typeof(SidAndAttributes))

                || returnedLength > allocatedLength)

            {

                throw new NativeFailure(65);

            }

            SidAndAttributes label = (SidAndAttributes)Marshal.PtrToStructure(

                buffer,

                typeof(SidAndAttributes));

            if (label.Sid == IntPtr.Zero)

            {

                throw new NativeFailure(65);

            }

            return new SecurityIdentifier(label.Sid).Value;

        }

        finally

        {

            ZeroAndFree(buffer, allocatedLength);

        }

    }



    private static ProcessProof ReadProcessProof(IntPtr processHandle, int processId)

    {

        NativeFileTime creation;

        NativeFileTime exit;

        NativeFileTime kernel;

        NativeFileTime user;

        if (!GetProcessTimes(processHandle, out creation, out exit, out kernel, out user))

        {

            throw new NativeFailure(65);

        }



        string normalizedImagePath = ReadNormalizedProcessImagePath(processHandle);

        IntPtr token;

        if (!OpenProcessToken(processHandle, TokenQuery, out token))

        {

            throw new NativeFailure(65);

        }



        TokenIdentity identity;

        try

        {

            identity = ReadTokenIdentity(token);

        }

        finally

        {

            CloseHandle(token);

        }



        ProcessProof proof = new ProcessProof();

        proof.ProcessId = processId;

        proof.CreationFileTime = CombineFileTime(creation);

        proof.ImagePathHash = Sha256Hex(normalizedImagePath);

        proof.Identity = identity;

        return proof;

    }



    private static string ReadNormalizedProcessImagePath(IntPtr processHandle)

    {

        StringBuilder imagePath = new StringBuilder(32768);

        uint imagePathLength = unchecked((uint)imagePath.Capacity);

        if (!QueryFullProcessImageName(processHandle, 0, imagePath, ref imagePathLength)

            || imagePathLength == 0

            || imagePathLength >= imagePath.Capacity)

        {

            throw new NativeFailure(65);

        }

        return NormalizeImagePath(imagePath.ToString());

    }



    private static string NormalizeImagePath(string imagePath)

    {

        if (String.IsNullOrWhiteSpace(imagePath) || imagePath.Length > 32767)

        {

            throw new NativeFailure(65);

        }

        string fullPath = Path.GetFullPath(imagePath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (!Path.IsPathRooted(fullPath) || fullPath.Length == 0)

        {

            throw new NativeFailure(65);

        }

        return fullPath.ToUpperInvariant();

    }



    private static ulong CombineFileTime(NativeFileTime value)

    {

        return (unchecked((ulong)value.HighDateTime) << 32) | value.LowDateTime;

    }



    private static void RequireSameIdentity(TokenIdentity expected, TokenIdentity actual, int exitCode)

    {

        if (!FixedEquals(expected.UserSid, actual.UserSid)

            || !FixedEquals(expected.LogonSid, actual.LogonSid)

            || !FixedEquals(expected.AuthenticationId, actual.AuthenticationId)

            || expected.SessionId != actual.SessionId

            || expected.IsElevated != actual.IsElevated

            || !FixedEquals(expected.IntegritySid, actual.IntegritySid))

        {

            throw new NativeFailure(exitCode);

        }

    }



    private static void RequireOrdinaryIdentity(TokenIdentity identity, int exitCode)

    {

        if (identity == null

            || identity.IsElevated

            || !(String.Equals(identity.IntegritySid, "S-1-16-8192", StringComparison.Ordinal)

                || String.Equals(identity.IntegritySid, "S-1-16-8448", StringComparison.Ordinal)))

        {

            throw new NativeFailure(exitCode);

        }

    }



    private static void RequireProcessAlive(IntPtr processHandle, int exitCode)

    {

        if (!IsProcessAlive(processHandle))

        {

            throw new NativeFailure(exitCode);

        }

    }



    private static bool IsProcessAlive(IntPtr processHandle)

    {

        uint result = WaitForSingleObject(processHandle, 0);

        if (result == WaitTimeout)

        {

            return true;

        }

        if (result == WaitObject0)

        {

            return false;

        }

        throw new NativeFailure(65);

    }



    private static void TerminateWithoutMessage(uint exitCode)

    {

        TerminateProcess(GetCurrentProcess(), exitCode);

        Environment.Exit(unchecked((int)exitCode));

    }



    private static long DeadlineAfter(int timeoutMilliseconds)

    {

        long now = Stopwatch.GetTimestamp();

        long delta = (long)Math.Ceiling(

            timeoutMilliseconds * (double)Stopwatch.Frequency / 1000.0);

        return checked(now + Math.Max(1L, delta));

    }



    private static int RemainingMilliseconds(long deadline, int exitCode)

    {

        int remaining = RemainingMillisecondsOrZero(deadline);

        if (remaining < 1)

        {

            throw new NativeFailure(exitCode);

        }

        return remaining;

    }



    private static int RemainingMillisecondsOrZero(long deadline)

    {

        long remainingTicks = deadline - Stopwatch.GetTimestamp();

        if (remainingTicks <= 0)

        {

            return 0;

        }

        double milliseconds = remainingTicks * 1000.0 / Stopwatch.Frequency;

        if (milliseconds >= Int32.MaxValue)

        {

            return Int32.MaxValue;

        }

        return Math.Max(1, (int)Math.Ceiling(milliseconds));

    }



    private static int GetParentProcessId(int processId)

    {

        IntPtr snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);

        if (snapshot == InvalidHandleValue)

        {

            throw new NativeFailure(65);

        }



        try

        {

            ProcessEntry32 entry = new ProcessEntry32();

            entry.Size = unchecked((uint)Marshal.SizeOf(typeof(ProcessEntry32)));

            if (!Process32First(snapshot, ref entry))

            {

                throw new NativeFailure(65);

            }

            do

            {

                if (entry.ProcessId == unchecked((uint)processId))

                {

                    if (entry.ParentProcessId < 1 || entry.ParentProcessId > Int32.MaxValue)

                    {

                        throw new NativeFailure(65);

                    }

                    return unchecked((int)entry.ParentProcessId);

                }

                entry.Size = unchecked((uint)Marshal.SizeOf(typeof(ProcessEntry32)));

            }

            while (Process32Next(snapshot, ref entry));



            if (Marshal.GetLastWin32Error() != ErrorNoMoreFiles)

            {

                throw new NativeFailure(65);

            }

            throw new NativeFailure(65);

        }

        finally

        {

            CloseHandle(snapshot);

        }

    }



    private static byte[] ReadFrame(Stream stream, long deadline)

    {

        byte[] header = null;

        byte[] payload = null;

        try

        {

            header = ReadExact(stream, 4, deadline);

            int length = header[0]

                | (header[1] << 8)

                | (header[2] << 16)

                | (header[3] << 24);

            if (length < 2 || length > MaximumFrameBytes)

            {

                throw new NativeFailure(67);

            }

            payload = ReadExact(stream, length, deadline);

            return payload;

        }

        finally

        {

            Clear(header);

        }

    }



    private static void WriteFrame(Stream stream, byte[] payload, long deadline)

    {

        WriteBoundedFrame(stream, payload, MaximumFrameBytes, deadline);

    }



    private static void WriteBoundedFrame(

        Stream stream,

        byte[] payload,

        int maximumBytes,

        long deadline)

    {

        if (payload == null || payload.Length < 2 || payload.Length > maximumBytes)

        {

            throw new NativeFailure(67);

        }

        byte[] frame = new byte[payload.Length + 4];

        int length = payload.Length;

        frame[0] = unchecked((byte)length);

        frame[1] = unchecked((byte)(length >> 8));

        frame[2] = unchecked((byte)(length >> 16));

        frame[3] = unchecked((byte)(length >> 24));

        Buffer.BlockCopy(payload, 0, frame, 4, payload.Length);

        try

        {

            RunTimed<object>(delegate

            {

                stream.Write(frame, 0, frame.Length);

                stream.Flush();

                return null;

            }, RemainingMilliseconds(deadline, 67), 67);

        }

        finally

        {

            Clear(frame);

        }

    }



    private static byte[] ReadBoundedFrameBlocking(Stream stream, int maximumBytes)

    {

        byte[] header = null;

        byte[] payload = null;

        try

        {

            header = ReadExactBlocking(stream, 4);

            int length = header[0]

                | (header[1] << 8)

                | (header[2] << 16)

                | (header[3] << 24);

            if (length < 2 || length > maximumBytes)

            {

                throw new NativeFailure(70);

            }

            payload = ReadExactBlocking(stream, length);

            return payload;

        }

        finally

        {

            Clear(header);

        }

    }



    private static byte[] ReadExactBlocking(Stream stream, int length)

    {

        byte[] buffer = new byte[length];

        int offset = 0;

        try

        {

            while (offset < buffer.Length)

            {

                int count = stream.Read(buffer, offset, buffer.Length - offset);

                if (count <= 0)

                {

                    throw new EndOfStreamException();

                }

                offset += count;

            }

            return buffer;

        }

        catch

        {

            Clear(buffer);

            throw;

        }

    }



    private static byte[] ReadExact(Stream stream, int length, long deadline)

    {

        return RunTimed<byte[]>(delegate

        {

            byte[] buffer = new byte[length];

            int offset = 0;

            try

            {

                while (offset < buffer.Length)

                {

                    int count = stream.Read(buffer, offset, buffer.Length - offset);

                    if (count <= 0)

                    {

                        throw new EndOfStreamException();

                    }

                    offset += count;

                }

                return buffer;

            }

            catch

            {

                Clear(buffer);

                throw;

            }

        }, RemainingMilliseconds(deadline, 67), 67);

    }



    private static string ReadAsciiLine(Stream stream, int maximumBytes, long deadline)

    {

        return RunTimed<string>(delegate

        {

            byte[] buffer = new byte[maximumBytes];

            int length = 0;

            try

            {

                while (length < buffer.Length)

                {

                    int value = stream.ReadByte();

                    if (value < 0)

                    {

                        throw new EndOfStreamException();

                    }

                    if (value == 10)

                    {

                        if (length == 0)

                        {

                            throw new InvalidDataException();

                        }

                        return Encoding.ASCII.GetString(buffer, 0, length);

                    }

                    if (value == 13 || value > 0x7f)

                    {

                        throw new InvalidDataException();

                    }

                    buffer[length] = unchecked((byte)value);

                    length += 1;

                }

                throw new InvalidDataException();

            }

            finally

            {

                Clear(buffer);

            }

        }, RemainingMilliseconds(deadline, 67), 67);

    }



    private static void WriteAsciiLine(Stream stream, string line, long deadline)

    {

        if (line == null || line.Length == 0 || line.Length > MaximumControlLineBytes)

        {

            throw new NativeFailure(67);

        }

        byte[] bytes = Encoding.ASCII.GetBytes(line + "\n");

        try

        {

            RunTimed<object>(delegate

            {

                stream.Write(bytes, 0, bytes.Length);

                stream.Flush();

                return null;

            }, RemainingMilliseconds(deadline, 67), 67);

        }

        finally

        {

            Clear(bytes);

        }

    }



    private static T RunTimed<T>(Func<T> operation, int timeoutMilliseconds, int exitCode)

    {

        TimedResult<T> result = new TimedResult<T>();

        Thread worker = new Thread(delegate()

        {

            try

            {

                result.Value = operation();

            }

            catch (Exception error)

            {

                result.Error = error;

            }

        });

        worker.IsBackground = true;

        worker.Start();

        if (!worker.Join(timeoutMilliseconds))

        {

            throw new NativeFailure(exitCode);

        }

        if (result.Error != null)

        {

            NativeFailure nativeFailure = result.Error as NativeFailure;

            if (nativeFailure != null)

            {

                throw nativeFailure;

            }

            throw new NativeFailure(exitCode);

        }

        return result.Value;

    }



    private static string Sha256Hex(string value)

    {

        byte[] input = Encoding.UTF8.GetBytes(value);

        byte[] digest = null;

        try

        {

            using (SHA256 sha = SHA256.Create())

            {

                digest = sha.ComputeHash(input);

            }

            StringBuilder text = new StringBuilder(64);

            for (int index = 0; index < digest.Length; index += 1)

            {

                text.Append(digest[index].ToString("x2", CultureInfo.InvariantCulture));

            }

            return text.ToString();

        }

        finally

        {

            Clear(input);

            Clear(digest);

        }

    }



    private static string NewCorrelationId()

    {

        byte[] random = new byte[CorrelationIdBytes / 2];

        try

        {

            using (RandomNumberGenerator generator = RandomNumberGenerator.Create())

            {

                generator.GetBytes(random);

            }

            StringBuilder text = new StringBuilder(CorrelationIdBytes);

            for (int index = 0; index < random.Length; index += 1)

            {

                text.Append(random[index].ToString("x2", CultureInfo.InvariantCulture));

            }

            return text.ToString();

        }

        finally

        {

            Clear(random);

        }

    }



    private static bool FixedEquals(string left, string right)

    {

        if (left == null || right == null || left.Length != right.Length)

        {

            return false;

        }

        int difference = 0;

        for (int index = 0; index < left.Length; index += 1)

        {

            difference |= left[index] ^ right[index];

        }

        return difference == 0;

    }



    private static void ZeroAndFree(IntPtr buffer, int length)

    {

        if (buffer == IntPtr.Zero)

        {

            return;

        }

        for (int index = 0; index < length; index += 1)

        {

            Marshal.WriteByte(buffer, index, 0);

        }

        Marshal.FreeHGlobal(buffer);

    }



    private static void Clear(byte[] value)

    {

        if (value != null)

        {

            Array.Clear(value, 0, value.Length);

        }

    }

}



// Opt-in observation fixture. No stdout/stderr, credentials, arbitrary payload,
// timer, custody or business-outcome changes. Sink is this diagnostic's fixed root.
internal static class KovyaStartupTrace {
    [DllImport("kernel32.dll")] internal static extern ulong GetTickCount64();
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] private static extern bool GetProcessTimes(IntPtr p,out long creation,out long exit,out long kernel,out long user);
    [DllImport("kernel32.dll")] private static extern void GetSystemTimePreciseAsFileTime(out long now);
    private static string attempt,command="other";private static int count;
    internal static ulong Tick(){return GetTickCount64();}
    private static string Attempt(){
        string value=Environment.GetEnvironmentVariable("KOVYA_STARTUP_ATTEMPT");
        return value!=null&&System.Text.RegularExpressions.Regex.IsMatch(value,"^[a-f0-9]{32}$")?value:null;
    }
    internal static void Forward(System.Collections.Specialized.StringDictionary env){var a=Attempt();if(a!=null)env["KOVYA_STARTUP_ATTEMPT"]=a;}
    internal static void Entry(ulong at,string[] args){
        attempt=Attempt();if(attempt==null)return;
        if(args!=null&&args.Length>0&&Array.IndexOf(new[]{"launch","start-broker","account-worker","host","identity","admit-runtime"},args[0])>=0)command=args[0];
        long c,e,k,u,now;GetSystemTimePreciseAsFileTime(out now);
        if(GetProcessTimes(GetCurrentProcess(),out c,out e,out k,out u)&&now>=c&&((ulong)((now-c)/10000))<=at)
            Emit("os_process_created",at-(ulong)((now-c)/10000),true);
        Emit("managed_entry",at,false);
        if(command=="start-broker")Mark("start_broker_request_received");
    }
    internal static void Mark(string stage){if(attempt==null)attempt=Attempt();Emit(stage,Tick(),false);}
    private static void Emit(string stage,ulong at,bool derived){
        if(attempt==null||Interlocked.Increment(ref count)>256)return;
        try {
            string row="{\"schema_version\":\"kovya.startup-timing.v1\",\"attempt_id\":\""+attempt+"\",\"source\":\"managed\",\"command\":\""+command+"\",\"stage\":\""+stage+"\",\"pid\":"+Process.GetCurrentProcess().Id+",\"monotonic_ms\":"+at+",\"derived_from_os_creation\":"+(derived?"true":"false")+"}\n";
            string file=Path.Combine(@"C:\Codex\eli\temp\st24data\trace",attempt+"-"+Process.GetCurrentProcess().Id+"-managed.jsonl");
            File.AppendAllText(file,row,new UTF8Encoding(false));
        } catch {} // A diagnostic sink cannot change the product outcome.
    }
}

// BEGIN GENERATED REQUEST BUDGET
// Derived from connector/plugin/request-budget.mjs. Do not edit by hand.
internal static class KovyaRequestBudget {
    internal const ulong ColdPathWorkMs = 3000UL;
    internal const ulong WarmWorkMs = 1000UL;
    internal const ulong OrdinaryStartupMs = 3000UL;
}
// END GENERATED REQUEST BUDGET
