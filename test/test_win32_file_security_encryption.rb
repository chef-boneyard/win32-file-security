#############################################################################
# test_win32_file_encryption.rb
#
# Test case for the encryption related methods of win32-file. You should
# run this test via the 'rake test' or 'rake test_encryption' task.
#
# Note: These tests may fail based on the security setup of your system.
#############################################################################
require 'test-unit'
require 'win32/security'
require 'win32/file/security'
require 'socket'

class TC_Win32_File_Security_Encryption < Test::Unit::TestCase
  def self.startup
    Dir.chdir(File.dirname(File.expand_path(File.basename(__FILE__))))
    @@file = File.join(Dir.pwd, 'encryption_test.txt')
    File.open(@@file, 'w'){ |fh| fh.puts "This is an encryption test." }
    @@host = Socket.gethostname
  end

  def setup
    @msg = '=> Ignore. May not work due to security setup of your system.'
    @elevated = Win32::Security.elevated_security?
    @statuses = ['encrypted', 'encryptable', 'unknown']
  end

  test "encrypt method basic functionality" do
    omit_unless(@elevated)
    assert_respond_to(File, :encrypt)
    assert_nothing_raised(@msg){ File.encrypt(@@file) }
  end

  test "encrypt requires one argument" do
    omit_unless(@elevated)
    assert_raise(ArgumentError){ File.encrypt }
    assert_raise(ArgumentError){ File.encrypt(@@file, @@file) }
  end

  test "encrypt requires a string argument" do
    omit_unless(@elevated)
    assert_raise(TypeError, NoMethodError){ File.encrypt(1) }
  end

  test "decrypt method basic functionality" do
    omit_unless(@elevated)
    assert_respond_to(File, :decrypt)
    assert_nothing_raised(@msg){ File.decrypt(@@file) }
  end

  test "decrypt accepts a single argument only" do
    omit_unless(@elevated)
    assert_raise(ArgumentError){ File.decrypt }
  end

  test "decrypt requires a string argument" do
    omit_unless(@elevated)
    assert_raise(TypeError, NoMethodError){ File.decrypt(1) }
  end

  test "encryptable? basic functionality" do
    assert_respond_to(File, :encryptable?)
  end

  test "encryptable? returns a boolean value" do
    assert_boolean(File.encryptable?("C:\\"))
  end

  test "encryption_status basic functionality" do
    assert_respond_to(File, :encryption_status)
  end

  test "encryption_status returns the expected result" do
    status = File.encryption_status(@@file)
    assert_kind_of(String, status)
    assert_true(@statuses.include?(status))
  end

  def teardown
    @msg = nil
    @statuses = nil
    @elevated = nil
  end

  def self.shutdown
    File.delete(@@file) if File.exists?(@@file)
    @@file = nil
    @@host = nil
  end
end
