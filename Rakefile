require 'rake'
require 'rake/clean'
require 'rake/testtask'

CLEAN.include('**/*.gem', '**/*.rbc')

namespace :gem do
  desc 'Build the win32-file-security gem'
  task :create => [:clean] do
    require 'rubygems/package'
    spec = eval(IO.read('win32-file-security.gemspec'))
    spec.signing_key = File.join(Dir.home, '.ssh', 'gem-private_key.pem')
    Gem::Package.build(spec)
  end

  desc "Install the win32-file-security gem"
  task :install => [:create] do
    file = Dir["*.gem"].first
    sh "gem install -l #{file}"
  end
end

namespace 'test' do
  Rake::TestTask.new('all') do |t|
    task :test => :clean
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new('constants') do |t|
    task :test => :clean
    t.warning = true
    t.verbose = true
    t.test_files = FileList['test/test_win32_file_security_constants']
  end

  Rake::TestTask.new('encryption') do |t|
    task :test => :clean
    t.warning = true
    t.verbose = true
    t.test_files = FileList['test/test_win32_file_security_encryption']
  end

  Rake::TestTask.new('ffi') do |t|
    task :test => :clean
    t.warning = true
    t.verbose = true
    t.test_files = FileList['test/test_win32_file_security_ffi']
  end

  Rake::TestTask.new('ownership') do |t|
    task :test => :clean
    t.warning = true
    t.verbose = true
    t.test_files = FileList['test/test_win32_file_security_ownership']
  end

  Rake::TestTask.new('permissions') do |t|
    task :test => :clean
    t.warning = true
    t.verbose = true
    t.test_files = FileList['test/test_win32_file_security_permissions']
  end
end

task :default => 'test:all'
