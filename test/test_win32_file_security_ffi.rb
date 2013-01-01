#############################################################################
# test_win32_file_security_ffi.rb
#
# Tests to ensure that the FFI functions are private
#############################################################################
require 'test-unit'
require 'win32/file/security'

class TC_Win32_File_Security_FFI < Test::Unit::TestCase
  def setup
    @singleton_methods = File.methods.map{ |m| m.to_s }
    @instance_methods  = File.instance_methods.map{ |m| m.to_s }
  end

  test "internal ffi functions are not public as singleton methods" do
    assert_false(@singleton_methods.include?('AddAce'))
    assert_false(@singleton_methods.include?('CloseHandle'))
    assert_false(@singleton_methods.include?('GetFileSecurityW'))
    assert_false(@singleton_methods.include?('PathIsRootW'))
  end

  test "internal ffi functions are not public as instance methods" do
    assert_false(@instance_methods.include?('AddAce'))
    assert_false(@instance_methods.include?('CloseHandle'))
    assert_false(@instance_methods.include?('GetFileSecurityW'))
    assert_false(@instance_methods.include?('PathIsRootW'))
  end

  def teardown
    @singleton_methods = nil
    @instance_methods = nil
  end
end
