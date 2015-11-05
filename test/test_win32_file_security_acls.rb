##############################################################################
# test_win32_file_acls.rb
#
# Test case for the File.supports_acls? method.
##############################################################################
require 'test-unit'
require 'win32/file/security'
require 'socket'
require 'etc'

class TC_Win32_File_Security_ACLS < Test::Unit::TestCase
  def setup
    @dir = "C:/"
  end

  test "supports_acls? basic functionality" do
    assert_respond_to(File, :supports_acls?)
    assert_boolean(File.supports_acls?)
  end

  test "supports_acls? returns the expected results" do
    assert_true(File.supports_acls?)
    assert_true(File.supports_acls?(@dir))
  end

  test "supports_acls? takes an optional file name" do
    assert_nothing_raised{ File.supports_acls?(@dir) }
    assert_boolean(File.supports_acls?(@dir))
  end

  def teardown
    @perms = nil
  end
end
