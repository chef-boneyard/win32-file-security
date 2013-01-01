require 'ffi'

module Windows
  module File
    module Structs
      class ACE_HEADER < FFI::Struct
        layout(
          :AceType, :uchar,
          :AceFlags, :uchar,
          :AceSize, :ushort
        )
      end

      class ACCESS_ALLOWED_ACE < FFI::Struct
        layout(
          :Header, ACE_HEADER,
          :Mask, :ulong,
          :SidStart, :ulong
        )
      end

      class ACCESS_ALLOWED_ACE2 < FFI::Struct
        layout(
          :Header, ACE_HEADER,
          :Mask, :ulong,
          :SidStart, :ulong,
          :dummy, [:uchar, 40]
        )
      end

      class ACL < FFI::Struct
        layout(
          :AclRevision, :uchar,
          :Sbz1, :uchar,
          :AclSize, :ushort,
          :AceCount, :ushort,
          :Sbz2, :ushort
        )
      end

      class LUID < FFI::Struct
        layout(:LowPart, :ulong, :HighPart, :long)
      end

      class LUID_AND_ATTRIBUTES < FFI::Struct
        layout(:Luid, LUID, :Attributes, :ulong)
      end

      class TOKEN_PRIVILEGES < FFI::Struct
        layout(
          :PrivilegeCount, :ulong,
          :Privileges, [LUID_AND_ATTRIBUTES, 1]
        )
      end
    end
  end
end
