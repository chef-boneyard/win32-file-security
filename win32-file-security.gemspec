require 'rubygems'

Gem::Specification.new do |spec|
  spec.name       = 'win32-file-security'
  spec.version    = '0.1.0'
  spec.authors    = ['Daniel J. Berger', 'Park Heesob']
  spec.license    = 'Artistic 2.0'
  spec.email      = 'djberg96@gmail.com'
  spec.homepage   = 'http://github.com/djberg96/win32-file-security'
  spec.summary    = 'File attribute methods for the File class on MS Windows'
  spec.test_files = Dir['test/test*']
  spec.files      = Dir['**/*'].reject{ |f| f.include?('git') }

  spec.rubyforge_project = 'win32utils'
  spec.extra_rdoc_files  = ['README', 'CHANGES', 'MANIFEST']

  spec.add_dependency('ffi')
  spec.add_development_dependency('test-unit')

  spec.description = <<-EOF
    The win32-file-security library adds security related methods to the
    core File class for MS Windows.
  EOF
end
