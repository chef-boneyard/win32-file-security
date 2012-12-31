########################################################################
# test_win32_file_security_constants.rb
#
# Tests to ensure that certain constants are defined for the
# win32-file-security library.
########################################################################
require 'test-unit'
require 'win32/file/security'

class TC_Win32_File_Constants < Test::Unit::TestCase
  test "file security rights constants are defined" do
    assert_not_nil(File::FILE_READ_DATA)
    assert_not_nil(File::FILE_WRITE_DATA)
    assert_not_nil(File::FILE_APPEND_DATA)
    assert_not_nil(File::FILE_READ_EA)
    assert_not_nil(File::FILE_EXECUTE)
    assert_not_nil(File::FILE_DELETE_CHILD)
    assert_not_nil(File::FILE_READ_ATTRIBUTES)
    assert_not_nil(File::FILE_WRITE_ATTRIBUTES)
  end

  test "standard security rights constants are defined" do
    assert_not_nil(File::STANDARD_RIGHTS_ALL)
    assert_not_nil(File::STANDARD_RIGHTS_REQUIRED)
    assert_not_nil(File::STANDARD_RIGHTS_READ)
    assert_not_nil(File::STANDARD_RIGHTS_WRITE)
    assert_not_nil(File::STANDARD_RIGHTS_EXECUTE)
  end

  test "generic security rights constants are defined" do
    assert_not_nil(File::GENERIC_READ)
    assert_not_nil(File::GENERIC_WRITE)
    assert_not_nil(File::GENERIC_EXECUTE)
    assert_not_nil(File::GENERIC_ALL)
  end

  test "combined security rights constants are defined" do
    assert_not_nil(File::FULL)
    assert_not_nil(File::READ)
    assert_not_nil(File::CHANGE)
    assert_not_nil(File::ADD)
    assert_not_nil(File::DELETE)
  end

  test "miscellaneous security rights constants are defined" do
    assert_not_nil(File::READ_CONTROL)
    assert_not_nil(File::WRITE_DAC)
    assert_not_nil(File::WRITE_OWNER)
    assert_not_nil(File::SYNCHRONIZE)
    assert_not_nil(File::SPECIFIC_RIGHTS_ALL)
    assert_not_nil(File::ACCESS_SYSTEM_SECURITY)
    assert_not_nil(File::MAXIMUM_ALLOWED)
  end
end
