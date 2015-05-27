#############################################################################
# test_win32_file_ownership.rb
#
# Test case for the file ownership related methods
#############################################################################
require 'etc'
require 'socket'
require 'sys/admin'
require 'test-unit'
require 'win32/security'
require 'win32/file/security'
require 'pathname'

class TC_Win32_File_Security_Ownership < Test::Unit::TestCase
  extend FFI::Library
  ffi_lib :netapi32
  attach_function :NetGetDCName, [:pointer, :pointer, :buffer_out], :int
  attach_function :NetApiBufferFree, [:pointer], :int

  # Helper method to determine if we're on a domain controller
  def self.in_domain?
    bool = true
    buf = (0.chr * 256).encode('UTF-16LE')
    rv = NetGetDCName(nil, nil, buf)
    bool = false if rv != 0
    NetApiBufferFree(buf)
    bool
  end

  def self.startup
    Dir.chdir(File.dirname(File.expand_path(File.basename(__FILE__))))
    @@file = File.join(Dir.pwd, 'ownership_test.txt')

    @@host  = Socket.gethostname
    @@temp  = "Temp"
    @@login = Etc.getlogin
    @@domain = in_domain?

    if Win32::Security.elevated_security?
      Sys::Admin.add_user(:name => @@temp, :description => "Delete Me")
    end
  end

  def setup
    @elevated = Win32::Security.elevated_security?
    File.open(@@file, 'w'){ |fh| fh.puts "This is an ownership test." }
  end

  test "owned? method basic functionality" do
    assert_respond_to(File, :owned?)
    assert_nothing_raised{ File.owned?(@@file) }
    assert_boolean(File.owned?(@@file))
  end

  test "owned? method returns expected result" do
    if Win32::Security.elevated_security?
      assert_false(File.owned?(@@file))
    else
      assert_true(File.owned?(@@file))
    end
    assert_false(File.owned?("C:\\Windows\\regedit.exe"))
  end

  test "owned? requires a single argument" do
    assert_raise(ArgumentError){ File.owned? }
    assert_raise(ArgumentError){ File.owned?(@@file, @@file) }
  end

  test "owner method basic functionality" do
    assert_respond_to(File, :owner)
    assert_nothing_raised{ File.owner(@@file) }
    assert_kind_of(String, File.owner(@@file))
  end

  test "owner method returns the expected value" do
    if Win32::Security.elevated_security?
      expected = "BUILTIN\\Administrators"
    else
      expected = @@host + "\\" + @@login
    end
    assert_equal(expected, File.owner(@@file))
  end

  test "owner method requires a single argument" do
    assert_raise(ArgumentError){ File.owner }
    assert_raise(ArgumentError){ File.owner(@@file, @@file) }
  end

  test "owner allows a pathname object" do
    assert_nothing_raised{ File.owner(Pathname.new(@@file)) }
  end

  test "grpowned? method basic functionality" do
    assert_respond_to(File, :grpowned?)
    assert_nothing_raised{ File.grpowned?(@@file) }
    assert_boolean(File.grpowned?(@@file))
  end

  test "grpowned? method returns expected result" do
    if Win32::Security.elevated_security? && @@domain
      assert_false(File.grpowned?(@@file))
    else
      assert_true(File.grpowned?(@@file))
    end
    assert_false(File.grpowned?("C:\\Windows\\regedit.exe"))
  end

  test "grpowned? requires a single argument" do
    assert_raise(ArgumentError){ File.grpowned? }
    assert_raise(ArgumentError){ File.grpowned?(@@file, @@file) }
  end

  test "group method basic functionality" do
    assert_respond_to(File, :group)
    assert_nothing_raised{ File.group(@@file) }
    assert_kind_of(String, File.group(@@file))
  end

  test "group method returns the expected value" do
    if Win32::Security.elevated_security? && @@domain
      expected = "BUILTIN\\Administrators"
    else
      expected = @@host + "\\None"
    end
    assert_equal(expected, File.group(@@file))
  end

  test "group method allows a pathname object" do
    assert_nothing_raised{ File.group(Pathname.new(@@file)) }
  end

  test "group method requires a stringy argument" do
    assert_raise(TypeError){ File.group(nil) }
    assert_raise(TypeError){ File.group([]) }
  end

  test "chown method basic functionality" do
    assert_respond_to(File, :chown)
  end

  test "chown works as expected" do
    omit_unless(@elevated)
    original_owner = File.owner(@@file)
    expected_owner = @@host + "\\" + @@temp

    assert_nothing_raised{ File.chown(@@temp, nil, @@file) }
    assert_equal(expected_owner, File.owner(@@file))
    assert_nothing_raised{ File.chown(original_owner, nil, @@file) }
    assert_equal(original_owner, File.owner(@@file))
  end

  test "chown returns the number of files processed" do
    omit_unless(@elevated)
    assert_equal(1, File.chown(@@temp, nil, @@file))
  end

  test "chown requires at least two arguments" do
    assert_raise(ArgumentError){ File.chown }
    assert_raise(ArgumentError){ File.chown(@@temp) }
  end

  def teardown
    @elevated = nil
    File.delete(@@file) if File.exist?(@@file)
  end

  def self.shutdown
    Sys::Admin.delete_user(@@temp) if Win32::Security.elevated_security?
    @@file = nil
    @@login = nil
    @@host = nil
    @@domain = nil
  end
end
