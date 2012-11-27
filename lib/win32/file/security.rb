require File.join(File.dirname(__FILE__), 'windows', 'constants')
require File.join(File.dirname(__FILE__), 'windows', 'structs')
require File.join(File.dirname(__FILE__), 'windows', 'functions')

class File
  include Windows::File::Constants
  include Windows::File::Functions
  extend Windows::File::Constants
  extend Windows::File::Structs
  extend Windows::File::Functions

  # The version of the win32-file library
  WIN32_FILE_SECURITY_VERSION = '1.0.0'

  class << self
    def get_permissions(file, host=nil)
      size_needed_ptr = FFI::MemoryPointer.new(:ulong)
      security_ptr    = FFI::MemoryPointer.new(:ulong)

      wide_file = file.wincode

      bool = GetFileSecurityW(
        wide_file,
        DACL_SECURITY_INFORMATION,
        security_ptr,
        security_ptr.size,
        size_needed_ptr
      )

      errno = FFI.errno

      if !bool && errno != ERROR_INSUFFICIENT_BUFFER
        raise SystemCallError.new("GetFileSecurity", errno)
      end

      size_needed = size_needed_ptr.read_ulong

      security_ptr = FFI::MemoryPointer.new(size_needed)

      bool = GetFileSecurityW(
        wide_file,
        DACL_SECURITY_INFORMATION,
        security_ptr,
        security_ptr.size,
        size_needed_ptr
      )

      unless bool
        raise SystemCallError.new("GetFileSecurity", FFI.errno)
      end

      control_ptr  = FFI::MemoryPointer.new(:ulong)
      revision_ptr = FFI::MemoryPointer.new(:ulong)

      unless GetSecurityDescriptorControl(security_ptr, control_ptr, revision_ptr)
        raise SystemCallError.new("GetSecurityDescriptorControl", FFI.errno)
      end

      control = control_ptr.read_ulong

      if control & SE_DACL_PRESENT == 0
        raise ArgumentError, "No DACL present: explicit deny all"
      end

      acl = ACL.new
      dacl_present_ptr   = FFI::MemoryPointer.new(:bool)
      dacl_defaulted_ptr = FFI::MemoryPointer.new(:ulong)

      # TODO: ACL struct is not getting filled with expected values. Fix.
      val = GetSecurityDescriptorDacl(
        security_ptr,
        dacl_present_ptr,
        acl,
        dacl_defaulted_ptr
      )

      if val == 0
        raise SystemCallError.new("GetSecurityDescriptorDacl", FFI.errno)
      end

      if acl[:AclRevision] == 0
        raise ArgumentError, "DACL is NULL: implicit access grant"
      end

      ace_count  = acl[:AceCount]
      perms_hash = {}
    end
  end
end
