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

    # Returns whether or not the root path is encryptable. If no root is
    # specified, it will check against the root of the current directory.
    # Be sure to include a trailing slash in the root path name.
    #
    # Examples:
    #
    #   p File.encryptable?
    #   p File.encryptable?("D:\\")
    #
    def encryptable?(file = nil)
      bool = false
      volume_buffer = 0.chr * 260
      flags_ptr = FFI::MemoryPointer.new(:ulong)

      file = file.wincode if file

      val = GetVolumeInformationW(
        file,
        volume_buffer,
        volume_buffer.size,
        nil,
        nil,
        flags_ptr,
        nil,
        0
      )

      unless val
        raise SystemCallError.new("GetVolumeInformation", FFI.errno)
      end

      flags = flags_ptr.read_ulong

      if flags & FILE_SUPPORTS_ENCRYPTION > 0
        bool = true
      end

      bool
    end

    # Encrypts a file or directory. All data streams in a file are encrypted.
    # All new files created in an encrypted directory are encrypted.
    #
    # The caller must have the FILE_READ_DATA, FILE_WRITE_DATA,
    # FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES, and SYNCHRONIZE access
    # rights.
    #
    # Requires exclusive access to the file being encrypted, and will fail if
    # another process is using the file or the file is marked read-only. If the
    # file is compressed the file will be decompressed before encrypting it.
    #
    def encrypt(file)
      unless EncryptFileW(file.wincode)
        raise SystemCallError.new("EncryptFile", FFI.errno)
      end
      self
    end

    # Decrypts an encrypted file or directory.
    #
    # The caller must have the FILE_READ_DATA, FILE_WRITE_DATA,
    # FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES, and SYNCHRONIZE access
    # rights.
    #
    # Requires exclusive access to the file being decrypted, and will fail if
    # another process is using the file. If the file is not encrypted an error
    # is NOT raised, it's simply a no-op.
    #
    def decrypt(file)
      unless DecryptFileW(file.wincode, 0)
        raise SystemCallError.new("DecryptFile", FFI.errno)
      end
      self
    end

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

p File.encryptable?
#File.encrypt('test.txt')
