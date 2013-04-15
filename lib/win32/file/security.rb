require File.join(File.dirname(__FILE__), 'security', 'constants')
require File.join(File.dirname(__FILE__), 'security', 'structs')
require File.join(File.dirname(__FILE__), 'security', 'functions')
require File.join(File.dirname(__FILE__), 'security', 'helper')
require 'socket'

class File
  include Windows::File::Constants
  include Windows::File::Functions
  extend Windows::File::Constants
  extend Windows::File::Structs
  extend Windows::File::Functions

  # The version of the win32-file library
  WIN32_FILE_SECURITY_VERSION = '1.0.2'

  class << self
    remove_method(:owned?)
    remove_method(:chown)

    # Returns the encryption status of a file as a string. Possible return
    # values are:
    #
    # * encryptable
    # * encrypted
    # * readonly
    # * root directory (i.e. not encryptable)
    # * system file (i.e. not encryptable)
    # * unsupported
    # * unknown
    #
    def encryption_status(file)
      wide_file  = file.wincode
      status_ptr = FFI::MemoryPointer.new(:ulong)

      unless FileEncryptionStatusW(wide_file, status_ptr)
        raise SystemCallError.new("FileEncryptionStatus", FFI.errno)
      end

      status = status_ptr.read_ulong

      rvalue = case status
        when FILE_ENCRYPTABLE
          "encryptable"
        when FILE_IS_ENCRYPTED
          "encrypted"
        when FILE_READ_ONLY
          "readonly"
        when FILE_ROOT_DIR
          "root directory"
        when FILE_SYSTEM_ATTR
          "system file"
        when FILE_SYSTEM_NOT_SUPPORTED
          "unsupported"
        else
          "unknown"
      end

      rvalue
    end

    # Returns whether or not the root path of the specified file is
    # encryptable. If a relative path is specified, it will check against
    # the root of the current directory.
    #
    # Be sure to include a trailing slash if specifying a root path.
    #
    # Examples:
    #
    #   p File.encryptable?
    #   p File.encryptable?("D:\\")
    #   p File.encryptable?("C:/foo/bar.txt") # Same as 'C:\'
    #
    def encryptable?(file = nil)
      bool = false
      flags_ptr = FFI::MemoryPointer.new(:ulong)

      if file
        file = File.expand_path(file)
        wide_file = file.wincode

        if !PathIsRootW(wide_file)
          unless PathStripToRootW(wide_file)
            raise SystemCallError.new("PathStripToRoot", FFI.errno)
          end
        end
      else
        wide_file = nil
      end

      unless GetVolumeInformationW(wide_file, nil, 0, nil, nil, flags_ptr, nil, 0)
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

    # Returns a hash describing the current file permissions for the given
    # file.  The account name is the key, and the value is an integer mask
    # that corresponds to the security permissions for that file.
    #
    # To get a human readable version of the permissions, pass the value to
    # the +File.securities+ method.
    #
    # You may optionally specify a host as the second argument. If no host is
    # specified then the current host is used.
    #
    # Examples:
    #
    #   hash = File.get_permissions('test.txt')
    #
    #   p hash # => {"NT AUTHORITY\\SYSTEM"=>2032127, "BUILTIN\\Administrators"=>2032127, ...}
    #
    #   hash.each{ |name, mask|
    #     p name
    #     p File.securities(mask)
    #   }
    #
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

      raise SystemCallError.new("GetFileSecurity", FFI.errno) unless bool

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

      bool = GetSecurityDescriptorDacl(
        security_ptr,
        dacl_present_ptr,
        dacl_pptr,
        dacl_defaulted_ptr
      )

      unless bool
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
          name_size.write_ulong(name.size)

          domain = FFI::MemoryPointer.new(:uchar, 260)
          domain_size = FFI::MemoryPointer.new(:ulong)
          domain_size.write_ulong(domain.size)

          use_ptr = FFI::MemoryPointer.new(:pointer)

          bool = LookupAccountSidW(
            wide_host,
            ace_pptr.read_pointer + 8,
            name,
            name_size,
            domain,
            domain_size,
            use_ptr
          )

          raise SystemCallError.new("LookupAccountSid", FFI.errno) unless bool

          # The x2 multiplier is necessary due to wide char strings.
          name = name.read_string(name_size.read_ulong * 2).delete(0.chr)
          domain = domain.read_string(domain_size.read_ulong * 2).delete(0.chr)

          unless domain.empty?
            name = domain + '\\' + name
          end

          perms_hash[name] = access[:Mask]
        end
      }

      perms_hash
    end

    # Sets the file permissions for the given file name.  The 'permissions'
    # argument is a hash with an account name as the key, and the various
    # permission constants as possible values. The possible constant values
    # are:
    #
    # * FILE_READ_DATA
    # * FILE_WRITE_DATA
    # * FILE_APPEND_DATA
    # * FILE_READ_EA
    # * FILE_WRITE_EA
    # * FILE_EXECUTE
    # * FILE_DELETE_CHILD
    # * FILE_READ_ATTRIBUTES
    # * FILE_WRITE_ATTRIBUTES
    # * FULL
    # * READ
    # * ADD
    # * CHANGE
    # * DELETE
    # * READ_CONTROL
    # * WRITE_DAC
    # * WRITE_OWNER
    # * SYNCHRONIZE
    # * STANDARD_RIGHTS_ALL
    # * STANDARD_RIGHTS_REQUIRED
    # * STANDARD_RIGHTS_READ
    # * STANDARD_RIGHTS_WRITE
    # * STANDARD_RIGHTS_EXECUTE
    # * SPECIFIC_RIGHTS_ALL
    # * ACCESS_SYSTEM_SECURITY
    # * MAXIMUM_ALLOWED
    # * GENERIC_READ
    # * GENERIC_WRITE
    # * GENERIC_EXECUTE
    # * GENERIC_ALL
    #
    # Example:
    #
    #   # Set locally
    #   File.set_permissions(file, "userid" => File::GENERIC_ALL)
    #
    #   # Set a remote system
    #   File.set_permissions(file, "host\\userid" => File::GENERIC_ALL)
    #
    def set_permissions(file, perms)
      raise TypeError unless file.is_a?(String)
      raise TypeError unless perms.kind_of?(Hash)

      wide_file = file.wincode

      account_rights = 0
      sec_desc = FFI::MemoryPointer.new(:pointer, SECURITY_DESCRIPTOR_MIN_LENGTH)

      unless InitializeSecurityDescriptor(sec_desc, 1)
        raise SystemCallError.new("InitializeSecurityDescriptor", FFI.errno)
      end

      acl_new = FFI::MemoryPointer.new(ACL, 100)

      unless InitializeAcl(acl_new, acl_new.size, ACL_REVISION2)
        raise SystemCallError.new("InitializeAcl", FFI.errno)
      end

      perms.each{ |account, mask|
        next if mask.nil?

        server, account = account.split("\\")

        if ['BUILTIN', 'NT AUTHORITY'].include?(server.upcase)
          wide_server = nil
        else
          wide_server = server.wincode
        end

        wide_account = account.wincode

        sid = FFI::MemoryPointer.new(:uchar, 1024)
        sid_size = FFI::MemoryPointer.new(:ulong)
        sid_size.write_ulong(sid.size)

        domain = FFI::MemoryPointer.new(:uchar, 260)
        domain_size = FFI::MemoryPointer.new(:ulong)
        domain_size.write_ulong(domain.size)

        use_ptr = FFI::MemoryPointer.new(:ulong)

        val = LookupAccountNameW(
           wide_server,
           wide_account,
           sid,
           sid_size,
           domain,
           domain_size,
           use_ptr
        )

        raise SystemCallError.new("LookupAccountName", FFI.errno) unless val

        all_ace = ACCESS_ALLOWED_ACE2.new

        val = CopySid(
          ALLOW_ACE_LENGTH - ACCESS_ALLOWED_ACE.size,
          all_ace.to_ptr+8,
          sid
        )

        raise SystemCallError.new("CopySid", FFI.errno) unless val

        if (GENERIC_ALL & mask).nonzero?
          account_rights = GENERIC_ALL & mask
        elsif (GENERIC_RIGHTS_CHK & mask).nonzero?
          account_rights = GENERIC_RIGHTS_MASK & mask
        else
          # Do nothing, leave it set to zero.
        end

        all_ace[:Header][:AceFlags] = INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE

        2.times{
          if account_rights != 0
            all_ace[:Header][:AceSize] = 8 + GetLengthSid(sid)
            all_ace[:Mask] = account_rights

            val = AddAce(
              acl_new,
              ACL_REVISION2,
              MAXDWORD,
              all_ace,
              all_ace[:Header][:AceSize]
            )

            raise SystemCallError.new("AddAce", FFI.errno) unless val

            all_ace[:Header][:AceFlags] = CONTAINER_INHERIT_ACE
          else
            all_ace[:Header][:AceFlags] = 0
          end

          account_rights = REST_RIGHTS_MASK & mask
        }
      }

      unless SetSecurityDescriptorDacl(sec_desc, true, acl_new, false)
        raise SystemCallError.new("SetSecurityDescriptorDacl", FFI.errno)
      end

      unless SetFileSecurityW(wide_file, DACL_SECURITY_INFORMATION, sec_desc)
        raise SystemCallError.new("SetFileSecurity", FFI.errno)
      end

      self
    end

    # Returns an array of human-readable strings that correspond to the
    # permission flags.
    #
    # Example:
    #
    #   File.get_permissions('test.txt').each{ |name, mask|
    #     puts name
    #     p File.securities(mask)
    #   }
    #
    def securities(mask)
      sec_array = []

      security_rights = {
        'FULL'    => FULL,
        'DELETE'  => DELETE,
        'READ'    => READ,
        'CHANGE'  => CHANGE,
        'ADD'     => ADD
      }

      if mask == 0
        sec_array.push('NONE')
      else
        if (mask & FULL) ^ FULL == 0
          sec_array.push('FULL')
        else
          security_rights.each{ |string, numeric|
            if (numeric & mask) ^ numeric == 0
              sec_array.push(string)
            end
          }
        end
      end

      sec_array
    end

    # Returns true if the effective user ID of the process is the same as the
    # owner of the named file.
    #
    # Example:
    #
    #   p File.owned?('some_file.txt') # => true
    #   p File.owned?('C:/Windows/regedit.ext') # => false
    #--
    # This method was redefined for MS Windows.
    #
    def owned?(file)
      return_value = false
      wide_file = file.wincode
      size_needed_ptr = FFI::MemoryPointer.new(:ulong)

      # First pass, get the size needed
      bool = GetFileSecurityW(
        wide_file,
        OWNER_SECURITY_INFORMATION,
        nil,
        0,
        size_needed_ptr
      )

      size_needed = size_needed_ptr.read_ulong

      security_ptr = FFI::MemoryPointer.new(size_needed)

      # Second pass, this time with the appropriately sized security pointer
      bool = GetFileSecurityW(
        wide_file,
        OWNER_SECURITY_INFORMATION,
        security_ptr,
        security_ptr.size,
        size_needed_ptr
      )

      raise SystemCallError.new("GetFileSecurity", FFI.errno) unless bool

      sid_ptr = FFI::MemoryPointer.new(:pointer)
      defaulted = FFI::MemoryPointer.new(:bool)

      unless GetSecurityDescriptorOwner(security_ptr, sid_ptr, defaulted)
        raise SystemCallError.new("GetFileSecurity", FFI.errno)
      end

      sid = sid_ptr.read_pointer

      token = FFI::MemoryPointer.new(:ulong)

      begin
        # Get the current process sid
        unless OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token)
          raise SystemCallError, FFI.errno, "OpenProcessToken"
        end

        token   = token.read_ulong
        rlength = FFI::MemoryPointer.new(:ulong)
        tuser   = 0.chr * 512

        bool = GetTokenInformation(
          token,
          TokenUser,
          tuser,
          tuser.size,
          rlength
        )

        unless bool
          raise SystemCallError, FFI.errno, "GetTokenInformation"
        end

        string_sid = tuser[8, (rlength.read_ulong - 8)]

        # Now compare the sid strings
        if string_sid == sid.read_string(string_sid.size)
          return_value = true
        end
      ensure
        CloseHandle(token)
      end

      return_value
    end

    # Changes the owner of the named file(s) to the given owner (userid).
    # It will typically require elevated privileges in order to change the
    # owner of a file.
    #
    # This group argument is currently ignored, but is included in the method
    # definition for compatibility with the current spec. Also note that the
    # owner should be a string, not a numeric ID.
    #
    # Example:
    #
    #   File.chown('some_user', nil, 'some_file.txt')
    #--
    # In the future we may allow the owner argument to be a SID or a RID and
    # simply adjust accordingly.
    #
    def chown(owner, group, *files)
      token = FFI::MemoryPointer.new(:ulong)

      begin
        bool = OpenProcessToken(
          GetCurrentProcess(),
          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
          token
        )

        raise SystemCallError.new("OpenProcessToken", FFI.errno) unless bool

        token_handle = token.read_ulong

        privs = [
          SE_SECURITY_NAME,
          SE_TAKE_OWNERSHIP_NAME,
          SE_BACKUP_NAME,
          SE_RESTORE_NAME,
          SE_CHANGE_NOTIFY_NAME
        ]

        privs.each{ |name|
          luid = LUID.new

          unless LookupPrivilegeValueA(nil, name, luid)
            raise SystemCallError.new("LookupPrivilegeValue", FFI.errno)
          end

          tp = TOKEN_PRIVILEGES.new
          tp[:PrivilegeCount] = 1
          tp[:Privileges][0][:Luid] = luid
          tp[:Privileges][0][:Attributes] = SE_PRIVILEGE_ENABLED

          unless AdjustTokenPrivileges(token_handle, false, tp, 0, nil, nil)
            raise SystemCallError.new("AdjustTokenPrivileges", FFI.errno)
          end
        }

        sid      = FFI::MemoryPointer.new(:uchar)
        sid_size = FFI::MemoryPointer.new(:ulong)
        dom      = FFI::MemoryPointer.new(:uchar)
        dom_size = FFI::MemoryPointer.new(:ulong)
        use      = FFI::MemoryPointer.new(:ulong)

        wowner = owner.wincode

        # First run, get needed sizes
        LookupAccountNameW(nil, wowner, sid, sid_size, dom, dom_size, use)

        sid = FFI::MemoryPointer.new(:uchar, sid_size.read_ulong * 2)
        dom = FFI::MemoryPointer.new(:uchar, dom_size.read_ulong * 2)

        # Second run with required sizes
        unless LookupAccountNameW(nil, wowner, sid, sid_size, dom, dom_size, use)
          raise SystemCallError.new("LookupAccountName", FFI.errno)
        end

        files.each{ |file|
          wfile = file.wincode

          size = FFI::MemoryPointer.new(:ulong)
          sec  = FFI::MemoryPointer.new(:ulong)

          # First pass, get the size needed
          GetFileSecurityW(wfile, OWNER_SECURITY_INFORMATION, sec, sec.size, size)

          security = FFI::MemoryPointer.new(size.read_ulong)

          # Second pass, this time with the appropriately sized security pointer
          bool = GetFileSecurityW(
            wfile,
            OWNER_SECURITY_INFORMATION,
            security,
            security.size,
            size
          )

          raise SystemCallError.new("GetFileSecurity", FFI.errno) unless bool

          unless InitializeSecurityDescriptor(security, SECURITY_DESCRIPTOR_REVISION)
            raise SystemCallError.new("InitializeSecurityDescriptor", FFI.errno)
          end

          unless SetSecurityDescriptorOwner(security, sid, false)
            raise SystemCallError.new("SetSecurityDescriptorOwner", FFI.errno)
          end

          unless SetFileSecurityW(wfile, OWNER_SECURITY_INFORMATION, security)
            raise SystemCallError.new("SetFileSecurity", FFI.errno)
          end
        }
      ensure
        CloseHandle(token.read_ulong)
      end

      files.size
    end

    # Returns the owner of the specified file in domain\\userid format.
    #
    # Example:
    #
    #   p File.owner('some_file.txt') # => "your_domain\\some_user"
    #
    def owner(file)
      size_needed = FFI::MemoryPointer.new(:ulong)

      # First pass, get the size needed
      bool = GetFileSecurityW(
        file.wincode,
        OWNER_SECURITY_INFORMATION,
        nil,
        0,
        size_needed
      )

      security = FFI::MemoryPointer.new(size_needed.read_ulong)

      # Second pass, this time with the appropriately sized security pointer
      bool = GetFileSecurityW(
        file.wincode,
        OWNER_SECURITY_INFORMATION,
        security,
        security.size,
        size_needed
      )

      raise SystemCallError.new("GetFileSecurity", FFI.errno) unless bool

      sid = FFI::MemoryPointer.new(:pointer)
      defaulted = FFI::MemoryPointer.new(:bool)

      unless GetSecurityDescriptorOwner(security, sid, defaulted)
        raise SystemCallError.new("GetFileSecurity", FFI.errno)
      end

      sid = sid.read_pointer

      name      = FFI::MemoryPointer.new(:uchar)
      name_size = FFI::MemoryPointer.new(:ulong)
      dom       = FFI::MemoryPointer.new(:uchar)
      dom_size  = FFI::MemoryPointer.new(:ulong)
      use       = FFI::MemoryPointer.new(:pointer)

      # First call, get sizes needed
      LookupAccountSidW(nil, sid, name, name_size, dom, dom_size, use)

      name = FFI::MemoryPointer.new(:uchar, name_size.read_ulong * 2)
      dom  = FFI::MemoryPointer.new(:uchar, dom_size.read_ulong * 2)

      # Second call, get desired information
      unless LookupAccountSidW(nil, sid, name, name_size, dom, dom_size, use)
        raise SystemCallError.new("LookupAccountSid", FFI.errno)
      end

      name = name.read_string(name.size).tr(0.chr, '').strip
      domain = dom.read_string(dom.size).tr(0.chr, '').strip

      domain << "\\" << name
    end

    # Returns the primary group of the specified file in domain\\userid format.
    #
    # Example:
    #
    #   p File.group('some_file.txt') # => "your_domain\\some_group"
    #
    def group(file)
      size_needed = FFI::MemoryPointer.new(:ulong)

      # First pass, get the size needed
      bool = GetFileSecurityW(
        file.wincode,
        GROUP_SECURITY_INFORMATION,
        nil,
        0,
        size_needed
      )

      security = FFI::MemoryPointer.new(size_needed.read_ulong)

      # Second pass, this time with the appropriately sized security pointer
      bool = GetFileSecurityW(
        file.wincode,
        GROUP_SECURITY_INFORMATION,
        security,
        security.size,
        size_needed
      )

      raise SystemCallError.new("GetFileSecurity", FFI.errno) unless bool

      sid = FFI::MemoryPointer.new(:pointer)
      defaulted = FFI::MemoryPointer.new(:bool)

      unless GetSecurityDescriptorGroup(security, sid, defaulted)
        raise SystemCallError.new("GetFileSecurity", FFI.errno)
      end

      sid = sid.read_pointer

      name      = FFI::MemoryPointer.new(:uchar)
      name_size = FFI::MemoryPointer.new(:ulong)
      dom       = FFI::MemoryPointer.new(:uchar)
      dom_size  = FFI::MemoryPointer.new(:ulong)
      use       = FFI::MemoryPointer.new(:int)

      # First call, get sizes needed
      LookupAccountSidW(nil, sid, name, name_size, dom, dom_size, use)

      name = FFI::MemoryPointer.new(:uchar, name_size.read_ulong * 2)
      dom  = FFI::MemoryPointer.new(:uchar, dom_size.read_ulong * 2)

      # Second call, get desired information
      unless LookupAccountSidW(nil, sid, name, name_size, dom, dom_size, use)
        raise SystemCallError.new("LookupAccountSid", FFI.errno)
      end

      name = name.read_string(name.size).tr(0.chr, '').strip
      domain = dom.read_string(dom.size).tr(0.chr, '').strip

      domain << "\\" << name
    end

    # Returns true if the primary group ID of the process is the same
    # as the owner of the named file.
    #
    # Example:
    #
    #   p File.grpowned?('some_file.txt') # => true
    #   p File.grpowned?('C:/Windows/regedit.ext') # => false
    #--
    # This method was redefined for MS Windows.
    #
    def grpowned?(file)
      return_value = false
      wide_file = file.wincode
      size_needed_ptr = FFI::MemoryPointer.new(:ulong)

      # First pass, get the size needed
      bool = GetFileSecurityW(
        wide_file,
        GROUP_SECURITY_INFORMATION,
        nil,
        0,
        size_needed_ptr
      )

      size_needed = size_needed_ptr.read_ulong

      security_ptr = FFI::MemoryPointer.new(size_needed)

      # Second pass, this time with the appropriately sized security pointer
      bool = GetFileSecurityW(
        wide_file,
        GROUP_SECURITY_INFORMATION,
        security_ptr,
        security_ptr.size,
        size_needed_ptr
      )

      raise SystemCallError.new("GetFileSecurity", FFI.errno) unless bool

      sid_ptr = FFI::MemoryPointer.new(:pointer)
      defaulted = FFI::MemoryPointer.new(:bool)

      unless GetSecurityDescriptorGroup(security_ptr, sid_ptr, defaulted)
        raise SystemCallError.new("GetFileSecurity", FFI.errno)
      end

      sid = sid_ptr.read_pointer

      token = FFI::MemoryPointer.new(:ulong)

      begin
        # Get the current process sid
        unless OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token)
          raise SystemCallError, FFI.errno, "OpenProcessToken"
        end

        token   = token.read_ulong
        rlength = FFI::MemoryPointer.new(:ulong)
        tgroup  = TOKEN_GROUP.new

        bool = GetTokenInformation(
          token,
          TokenGroups,
          tgroup,
          tgroup.size,
          rlength
        )

        unless bool
          raise SystemCallError.new("GetTokenInformation", FFI.errno)
        end

        #string_sid = tgroup[8, (rlength.read_ulong - 8)]

        # Now compare the sid strings
        #if string_sid == sid.read_string(string_sid.size)
        #  return_value = true
        #end
      ensure
        CloseHandle(token)
      end

      return_value
    end
  end
end
