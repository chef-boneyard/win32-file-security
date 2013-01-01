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


      ffi_lib :advapi32

      attach_pfunc :AddAce, [:ptr, :ulong, :ulong, :ptr, :ulong], :bool
      attach_pfunc :AdjustTokenPrivileges, [:ulong, :bool, :ptr, :ulong, :ptr, :ptr], :bool
      attach_pfunc :CopySid, [:ulong, :ptr, :ptr], :bool
      attach_pfunc :EncryptFileW, [:buf_in], :bool
      attach_pfunc :DecryptFileW, [:buf_in, :ulong], :bool
      attach_pfunc :FileEncryptionStatusW, [:buf_in, :ptr], :bool
      attach_pfunc :GetAce, [:ptr, :ulong, :ptr], :bool
      attach_pfunc :GetFileSecurityW, [:buf_in, :ulong, :ptr, :ulong, :ptr], :bool
      attach_pfunc :GetLengthSid, [:ptr], :ulong
      attach_pfunc :GetSecurityDescriptorControl, [:ptr, :ptr, :ptr], :bool
      attach_pfunc :GetSecurityDescriptorOwner, [:ptr, :ptr, :ptr], :bool
      attach_pfunc :GetSecurityDescriptorDacl, [:ptr, :ptr, :ptr, :ptr], :ulong
      attach_pfunc :GetSecurityInfo, [:ulong, :ulong, :ulong, :ptr, :ptr, :ptr, :ptr, :ptr], :ulong
      attach_pfunc :GetTokenInformation, [:ulong, :int, :ptr, :ulong, :ptr], :bool
      attach_pfunc :InitializeAcl, [:ptr, :ulong, :ulong], :bool
      attach_pfunc :InitializeSecurityDescriptor, [:ptr, :ulong], :bool
      attach_pfunc :LookupAccountNameW, [:buf_in, :buf_in, :ptr, :ptr, :ptr, :ptr, :ptr], :bool
      attach_pfunc :LookupAccountSidW, [:buf_in, :ptr, :ptr, :ptr, :ptr, :ptr, :ptr], :bool
      attach_pfunc :LookupPrivilegeValueA, [:str, :str, :ptr], :bool
      attach_pfunc :OpenProcessToken, [:ulong, :ulong, :ptr], :bool
      attach_pfunc :SetFileSecurityW, [:buf_in, :ulong, :ptr], :bool
      attach_pfunc :SetSecurityDescriptorDacl, [:ptr, :bool, :ptr, :bool], :bool
      attach_pfunc :SetSecurityDescriptorOwner, [:ptr, :ptr, :bool], :bool

      ffi_lib :kernel32

      attach_pfunc :CloseHandle, [:ulong], :bool
      attach_pfunc :GetCurrentProcess, [], :ulong
      attach_pfunc :GetVolumeInformationW, [:buf_in, :buf_out, :ulong, :ptr, :ptr, :ptr, :buf_out, :ulong], :bool

      ffi_lib :shlwapi

      attach_pfunc :PathStripToRootW, [:buf_in], :bool
      attach_pfunc :PathIsRootW, [:buf_in], :bool
    end
  end
end
