Gem::Specification.new do |spec|
  spec.name = "bulkping"
  spec.version = "0.1.1"
  spec.platform = Gem::Platform::RUBY
  spec.summary = "Bulk ping sender for Ruby"
  spec.files = Dir.glob('**/*')
  spec.extensions << "ext"

  spec.author = "Satoshi Ebisawa"
  spec.email = "ebisawa@gmail.com"
  spec.homepage = "http://github.com/ebisawa/ruby-bulkping"
end
