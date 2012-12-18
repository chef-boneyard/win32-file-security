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
    end
  end
end
