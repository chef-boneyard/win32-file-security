##############################################################################
# test_win32_file_permissions.rb
#
# Test case for permission related methods of win32-file-security. You should
# use the 'rake test' or 'rake test:perms' task to run this.
##############################################################################
require 'test-unit'
require 'test/unit'
require 'win32/file/security'
require 'socket'
require 'etc'

class TC_Win32_File_Permissions < Test::Unit::TestCase
  def self.startup
    @@user = Etc.getlogin
    @@host = Socket.gethostname
    @@file = File.join(Dir.pwd, 'security_test.txt')

    Dir.chdir(File.dirname(File.expand_path(File.basename(__FILE__))))
    File.open(@@file, 'w'){ |fh| fh.puts "This is a security test." }
  end

  def setup
    @perms = nil
  end

  test "get_permissions basic functionality" do
    assert_respond_to(File, :get_permissions)
    assert_nothing_raised{ File.get_permissions(@@file) }
  end

  test "get_permissions returns a hash" do
    assert_kind_of(Hash, File.get_permissions(@@file))
  end

  test "get_permissions accepts an optional hostname argument" do
    assert_nothing_raised{ File.get_permissions(@@file, @@host) }
  end

  test "get_permissions requires at least one argument" do
    assert_raise(ArgumentError){ File.get_permissions }
  end

  test "set_permissions basic functionality" do
    assert_respond_to(File, :set_permissions)
  end

  test "set_permissions works as expected" do
    assert_nothing_raised{ @perms = File.get_permissions(@@file) }
    assert_nothing_raised{ File.set_permissions(@@file, @perms) }
    assert_equal(@perms, File.get_permissions(@@file))
  end

  test "set_permissions works if host is specified" do
    @perms = {"#{@@host}\\#{@@user}" => File::GENERIC_ALL}
    assert_nothing_raised{ File.set_permissions(@@file, @perms) }
    assert_equal(@perms, File.get_permissions(@@file))
  end

  test "securities method basic functionality" do
    assert_respond_to(File, :securities)
  end

  test "securities method works as expected" do
    @perms = File.get_permissions(@@file)

    @perms.each{ |acct, mask|
      assert_nothing_raised{ File.securities(mask) }
      assert_kind_of(Array, File.securities(mask))
    }
  end

  test "securities method accepts a single argument only" do
    assert_raise(ArgumentError){ File.securities }
    assert_raise(ArgumentError){ File.securities({}, {}) }
  end

  def teardown
    @perms = nil
  end

  def self.shutdown
    File.delete(@@file) if File.exists?(@@file)
    @@file = nil
    @@host = nil
    @@user = nil
  end
end
