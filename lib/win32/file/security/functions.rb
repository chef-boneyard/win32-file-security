require 'ffi'

module Windows
  module File
    module Functions

      # Make FFI functions private
      module FFI::Library
        def attach_pfunc(*args)
          attach_function(*args)
          private args[0]
        end
      end

      extend FFI::Library

      # For convenience
      typedef :pointer, :ptr
      typedef :buffer_in, :buf_in
      typedef :buffer_out, :buf_out
      typedef :string, :str
      typedef :ulong, :dword
      typedef :uintptr_t, :handle

      ffi_lib :advapi32

      attach_pfunc :AddAce, [:ptr, :dword, :dword, :ptr, :dword], :bool
      attach_pfunc :AdjustTokenPrivileges, [:handle, :bool, :ptr, :dword, :ptr, :ptr], :bool
      attach_pfunc :CopySid, [:dword, :ptr, :ptr], :bool
      attach_pfunc :EncryptFileW, [:buf_in], :bool
      attach_pfunc :DecryptFileW, [:buf_in, :dword], :bool
      attach_pfunc :FileEncryptionStatusW, [:buf_in, :ptr], :bool
      attach_pfunc :GetAce, [:ptr, :dword, :ptr], :bool
      attach_pfunc :GetFileSecurityW, [:buf_in, :dword, :ptr, :dword, :ptr], :bool
      attach_pfunc :GetLengthSid, [:ptr], :dword
      attach_pfunc :GetSecurityDescriptorControl, [:ptr, :ptr, :ptr], :bool
      attach_pfunc :GetSecurityDescriptorOwner, [:ptr, :ptr, :ptr], :bool
      attach_pfunc :GetSecurityDescriptorGroup, [:ptr, :ptr, :ptr], :bool
      attach_pfunc :GetSecurityDescriptorDacl, [:ptr, :ptr, :ptr, :ptr], :bool
      attach_pfunc :GetSecurityInfo, [:handle, :dword, :dword, :ptr, :ptr, :ptr, :ptr, :ptr], :dword
      attach_pfunc :GetTokenInformation, [:handle, :int, :ptr, :dword, :ptr], :bool
      attach_pfunc :InitializeAcl, [:ptr, :dword, :dword], :bool
      attach_pfunc :InitializeSecurityDescriptor, [:ptr, :dword], :bool
      attach_pfunc :LookupAccountNameW, [:buf_in, :buf_in, :ptr, :ptr, :ptr, :ptr, :ptr], :bool
      attach_pfunc :LookupAccountSidW, [:buf_in, :ptr, :ptr, :ptr, :ptr, :ptr, :ptr], :bool
      attach_pfunc :LookupPrivilegeValueA, [:str, :str, :ptr], :bool
      attach_pfunc :OpenProcessToken, [:handle, :dword, :ptr], :bool
      attach_pfunc :SetFileSecurityW, [:buf_in, :dword, :ptr], :bool
      attach_pfunc :SetSecurityDescriptorDacl, [:ptr, :bool, :ptr, :bool], :bool
      attach_pfunc :SetSecurityDescriptorOwner, [:ptr, :ptr, :bool], :bool

      ffi_lib :kernel32

      attach_pfunc :CloseHandle, [:handle], :bool
      attach_pfunc :GetCurrentProcess, [], :handle
      attach_pfunc :GetVolumeInformationW, [:buf_in, :buf_out, :dword, :ptr, :ptr, :ptr, :buf_out, :dword], :bool

      ffi_lib :shlwapi

      attach_pfunc :PathStripToRootW, [:buf_in], :bool
      attach_pfunc :PathIsRootW, [:buf_in], :bool
    end
  end
end
