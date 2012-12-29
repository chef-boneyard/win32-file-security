#############################################################################
# test_win32_file_ownership.rb
#
# Test case for the file ownership related methods
#############################################################################
require 'etc'
require 'test-unit'
require 'win32/security'
require 'win32/file/security'

class TC_Win32_File_Security_Encryption < Test::Unit::TestCase
  def self.startup
    Dir.chdir(File.dirname(File.expand_path(File.basename(__FILE__))))
    @@file = File.join(Dir.pwd, 'ownership_test.txt')
    File.open(@@file, 'w'){ |fh| fh.puts "This is an ownership test." }
  end

  def setup
    @elevated = Win32::Security.elevated_security?
    @login = Etc.getlogin
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

  def teardown
    @statuses = nil
  end

  def self.shutdown
    File.delete(@@file) if File.exists?(@@file)
    @@file = nil
  end
end
