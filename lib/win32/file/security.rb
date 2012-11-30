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
      flags_ptr = FFI::MemoryPointer.new(:ulong)

      file = file.wincode if file

      unless GetVolumeInformationW(file, nil, 0, nil, nil, flags_ptr, nil, 0)
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
      wide_host = host ? host.wincode : nil

      # First pass, get the size needed
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

      # Second pass, this time with the appropriately sized security pointer
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

      dacl_pptr          = FFI::MemoryPointer.new(:pointer)
      dacl_present_ptr   = FFI::MemoryPointer.new(:bool)
      dacl_defaulted_ptr = FFI::MemoryPointer.new(:ulong)

      val = GetSecurityDescriptorDacl(
        security_ptr,
        dacl_present_ptr,
        dacl_pptr,
        dacl_defaulted_ptr
      )

      if val == 0
        raise SystemCallError.new("GetSecurityDescriptorDacl", FFI.errno)
      end

      acl = ACL.new(dacl_pptr.read_pointer)

      if acl[:AclRevision] == 0
        raise ArgumentError, "DACL is NULL: implicit access grant"
      end

      ace_count  = acl[:AceCount]
      perms_hash = {}

      0.upto(ace_count - 1){ |i|
        ace_pptr = FFI::MemoryPointer.new(:pointer)
        next unless GetAce(acl, i, ace_pptr)

        access = ACCESS_ALLOWED_ACE.new(ace_pptr.read_pointer)

        if access[:Header][:AceType] == ACCESS_ALLOWED_ACE_TYPE
          name = FFI::MemoryPointer.new(:uchar, 260)
          name_size = FFI::MemoryPointer.new(:ulong)

          domain = FFI::MemoryPointer.new(:uchar, 260)
          domain_size = FFI::MemoryPointer.new(:ulong)

          use_ptr = FFI::MemoryPointer.new(:pointer)

          name_size.write_ulong(name.size)
          domain_size.write_ulong(domain.size)

          # TODO: Fix. Currently segfaults.
          val = LookupAccountSidW(
            wide_host,
            access[:SidStart],
            name,
            name_size,
            domain,
            domain_size,
            use_ptr
          )

          if val == 0
            raise SystemCallError.new("LookupAccountSid", FFI.errno)
          end
        end
      }
    end
  end
end

File.get_permissions('test.txt')
