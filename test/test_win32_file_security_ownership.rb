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

class TC_Win32_File_Security_Ownership < Test::Unit::TestCase
  def self.startup
    Dir.chdir(File.dirname(File.expand_path(File.basename(__FILE__))))
    @@file = File.join(Dir.pwd, 'ownership_test.txt')
    File.open(@@file, 'w'){ |fh| fh.puts "This is an ownership test." }

    @@host  = Socket.gethostname
    @@temp  = "Temp"
    @@login = Etc.getlogin

    if Win32::Security.elevated_security?
      Sys::Admin.add_user(:name => @@temp, :description => "Delete Me")
    end
  end

  def setup
    @elevated = Win32::Security.elevated_security?
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
  end

  def self.shutdown
    Sys::Admin.delete_user(@@temp) if Win32::Security.elevated_security?
    File.delete(@@file) if File.exists?(@@file)
    @@file = nil
    @@login = nil
    @@host = nil
  end
end
