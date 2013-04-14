module Windows
  module File
    module Constants
      SE_DACL_PRESENT            = 4
      OWNER_SECURITY_INFORMATION = 1
      GROUP_SECURITY_INFORMATION = 2
      DACL_SECURITY_INFORMATION  = 4
      ACCESS_ALLOWED_ACE_TYPE    = 0
      ERROR_INSUFFICIENT_BUFFER  = 122
      ACL_REVISION2              = 2
      ALLOW_ACE_LENGTH           = 62
      OBJECT_INHERIT_ACE         = 0x1
      CONTAINER_INHERIT_ACE      = 0x2
      INHERIT_ONLY_ACE           = 0x8
      MAXDWORD                   = 0xFFFFFFFF
      TOKEN_QUERY                = 0x00000008
      TOKEN_ADJUST_PRIVILEGES    = 0x0020
      TokenUser                  = 1

      SECURITY_DESCRIPTOR_REVISION   = 1
      SECURITY_DESCRIPTOR_MIN_LENGTH = 20

      SE_KERNEL_OBJECT       = 6
      SE_FILE_OBJECT         = 1
      SE_PRIVILEGE_ENABLED   = 0x00000002
      SE_SECURITY_NAME       = "SeSecurityPrivilege"
      SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege"
      SE_BACKUP_NAME         = "SeBackupPrivilege"
      SE_RESTORE_NAME        = "SeRestorePrivilege"
      SE_CHANGE_NOTIFY_NAME  = "SeChangeNotifyPrivilege"

      ## Security Rights

      SYNCHRONIZE                  = 0x100000
      STANDARD_RIGHTS_REQUIRED     = 0xf0000
      STANDARD_RIGHTS_READ         = 0x20000
      STANDARD_RIGHTS_WRITE        = 0x20000
      STANDARD_RIGHTS_EXECUTE      = 0x20000
      STANDARD_RIGHTS_ALL          = 0x1F0000
      SPECIFIC_RIGHTS_ALL          = 0xFFFF
      ACCESS_SYSTEM_SECURITY       = 0x1000000
      MAXIMUM_ALLOWED              = 0x2000000
      GENERIC_READ                 = 0x80000000
      GENERIC_WRITE                = 0x40000000
      GENERIC_EXECUTE              = 0x20000000
      GENERIC_ALL                  = 0x10000000
      GENERIC_RIGHTS_CHK           = 0xF0000000
      REST_RIGHTS_MASK             = 0x001FFFFF
      READ_CONTROL                 = 0x20000
      WRITE_DAC                    = 0x40000
      WRITE_OWNER                  = 0x80000

      FILE_READ_DATA               = 1
      FILE_LIST_DIRECTORY          = 1
      FILE_WRITE_DATA              = 2
      FILE_ADD_FILE                = 2
      FILE_APPEND_DATA             = 4
      FILE_ADD_SUBDIRECTORY        = 4
      FILE_CREATE_PIPE_INSTANCE    = 4
      FILE_READ_EA                 = 8
      FILE_READ_PROPERTIES         = 8
      FILE_WRITE_EA                = 16
      FILE_WRITE_PROPERTIES        = 16
      FILE_EXECUTE                 = 32
      FILE_TRAVERSE                = 32
      FILE_DELETE_CHILD            = 64
      FILE_READ_ATTRIBUTES         = 128
      FILE_WRITE_ATTRIBUTES        = 256

      FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF

      FILE_GENERIC_READ =
         STANDARD_RIGHTS_READ |
         FILE_READ_DATA |
         FILE_READ_ATTRIBUTES |
         FILE_READ_EA |
         SYNCHRONIZE

      FILE_GENERIC_WRITE =
         STANDARD_RIGHTS_WRITE |
         FILE_WRITE_DATA |
         FILE_WRITE_ATTRIBUTES |
         FILE_WRITE_EA |
         FILE_APPEND_DATA |
         SYNCHRONIZE

      FILE_GENERIC_EXECUTE =
         STANDARD_RIGHTS_EXECUTE |
         FILE_READ_ATTRIBUTES |
         FILE_EXECUTE |
         SYNCHRONIZE

      FILE_SHARE_READ                = 1
      FILE_SHARE_WRITE               = 2
      FILE_SHARE_DELETE              = 4
      FILE_NOTIFY_CHANGE_FILE_NAME   = 1
      FILE_NOTIFY_CHANGE_DIR_NAME    = 2
      FILE_NOTIFY_CHANGE_ATTRIBUTES  = 4
      FILE_NOTIFY_CHANGE_SIZE        = 8
      FILE_NOTIFY_CHANGE_LAST_WRITE  = 16
      FILE_NOTIFY_CHANGE_LAST_ACCESS = 32
      FILE_NOTIFY_CHANGE_CREATION    = 64
      FILE_NOTIFY_CHANGE_SECURITY    = 256
      FILE_CASE_SENSITIVE_SEARCH     = 1
      FILE_CASE_PRESERVED_NAMES      = 2
      FILE_UNICODE_ON_DISK           = 4
      FILE_PERSISTENT_ACLS           = 8
      FILE_FILE_COMPRESSION          = 16
      FILE_VOLUME_QUOTAS             = 32
      FILE_SUPPORTS_SPARSE_FILES     = 64
      FILE_SUPPORTS_REPARSE_POINTS   = 128
      FILE_SUPPORTS_REMOTE_STORAGE   = 256
      FILE_VOLUME_IS_COMPRESSED      = 0x8000
      FILE_SUPPORTS_OBJECT_IDS       = 0x10000
      FILE_SUPPORTS_ENCRYPTION       = 0x20000

      FILE_ENCRYPTABLE  = 0
      FILE_IS_ENCRYPTED = 1
      FILE_ROOT_DIR     = 3
      FILE_SYSTEM_ATTR  = 2
      FILE_SYSTEM_DIR   = 4
      FILE_UNKNOWN      = 5
      FILE_SYSTEM_NOT_SUPPORT = 6
      FILE_READ_ONLY    = 8

      # Read and execute privileges
      READ = FILE_GENERIC_READ | FILE_EXECUTE

      # Add privileges
      ADD = 0x001201bf

      # Delete privileges
      DELETE = 0x00010000

      # Generic write, generic read, execute and delete privileges
      CHANGE = FILE_GENERIC_WRITE | FILE_GENERIC_READ | FILE_EXECUTE | DELETE

      # Full security rights - read, write, append, execute, and delete.
      FULL = STANDARD_RIGHTS_ALL | FILE_READ_DATA | FILE_WRITE_DATA |
        FILE_APPEND_DATA | FILE_READ_EA | FILE_WRITE_EA | FILE_EXECUTE |
        FILE_DELETE_CHILD | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES
    end
  end
end
