#############################################################################
# test_win32_file_security_version.rb
#
# Just a test for the version of the library.
#############################################################################
require 'test-unit'
require 'win32/file/security'

class TC_Win32_File_Security_Version < Test::Unit::TestCase
  test "version is set to expected value" do
    assert_equal('1.0.3', File::WIN32_FILE_SECURITY_VERSION)
  end
end
