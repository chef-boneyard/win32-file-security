#############################################################################
# test_win32_file_ownership.rb
#
# Test case for the file ownership related methods
#############################################################################
require 'etc'
require 'socket'
require 'test-unit'
require 'win32/security'
require 'win32/file/security'

class TC_Win32_File_Security_Ownership < Test::Unit::TestCase
  def self.startup
    Dir.chdir(File.dirname(File.expand_path(File.basename(__FILE__))))
    @@file = File.join(Dir.pwd, 'ownership_test.txt')
    File.open(@@file, 'w'){ |fh| fh.puts "This is an ownership test." }
  end

  def setup
    @elevated = Win32::Security.elevated_security?
    @login    = Etc.getlogin
    @host     = Socket.gethostname
  end

  test "owned? method basic functionality" do
    assert_respond_to(File, :owned?)
    assert_nothing_raised{ File.owned?(@@file) }
    assert_boolean(File.owned?(@@file))
  end

  test "owned? method returns expected result" do
    assert_true(File.owned?(@@file))
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
    expected = @host << "\\" << @login
    assert_equal(expected, File.owner(@@file))
  end

  test "owner method requires a single argument" do
    assert_raise(ArgumentError){ File.owner }
    assert_raise(ArgumentError){ File.owner(@@file, @@file) }
  end

  def teardown
    @elevated = nil
    @login = nil
    @host = nil
  end

  def self.shutdown
    File.delete(@@file) if File.exists?(@@file)
    @@file = nil
  end
end
