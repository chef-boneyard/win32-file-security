#############################################################################
# test_win32_file_encryption.rb
#
# Test case for the encryption related methods of win32-file. You should
# run this test via the 'rake test' or 'rake test_encryption' task.
#
# Note: These tests may fail based on the security setup of your system.
#############################################################################
require 'test-unit'
require 'win32/file/security'

class TC_Win32_File_Encryption < Test::Unit::TestCase
  def self.startup
    Dir.chdir(File.dirname(File.expand_path(File.basename(__FILE__))))
    @@file = File.join(Dir.pwd, 'encryption_test.txt')
    File.open(@@file, 'w'){ |fh| fh.puts "This is an encryption test." }
  end

  def setup
    @msg = '=> Ignore. May not work due to security setup of your system.'
  end

  test "encrypt method basic functionality" do
    assert_respond_to(File, :encrypt)
    assert_nothing_raised(@msg){ File.encrypt(@@file) }
  end

  test "encrypt accepts a single argument only" do
    assert_raise(ArgumentError){ File.encrypt }
  end

  test "encrypt requires a string argument" do
    assert_raise(TypeError){ File.encrypt(1) }
  end

  test "decrypt method basic functionality" do
    assert_respond_to(File, :decrypt)
    assert_nothing_raised(@msg){ File.decrypt(@@file) }
  end

  test "decrypt accepts a single argument only" do
    assert_raise(ArgumentError){ File.decrypt }
  end

  test "decrypt requires a string argument" do
    assert_raise(TypeError){ File.decrypt(1) }
  end

  def teardown
    @msg = nil
  end

  def self.shutdown
    File.delete(@@file) if File.exists?(@@file)
    @@file = nil
  end
end
