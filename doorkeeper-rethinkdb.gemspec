$:.push File.expand_path("../lib", __FILE__)

# Maintain your gem's version:
require "doorkeeper-rethinkdb/version"

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = "doorkeeper-rethinkdb"
  s.version     = DoorkeeperRethinkdb::VERSION
  s.authors     = ["Stephen von Takach"]
  s.email       = ["steve@aca.im"]
  s.homepage    = "http://github.com/aca-labs/doorkeeper-rethinkdb"
  s.summary     = "Doorkeeper RethinkDB ORMs"
  s.description = "Doorkeeper RethinkDB ORMs"
  s.license     = "MIT"

  s.files = Dir["lib/**/*", "MIT-LICENSE", "Rakefile", "README.md"]
  s.test_files = Dir["spec/**/*"]

  s.add_dependency "doorkeeper", ">= 4.0.0", "< 6"
  s.add_dependency "nobrainer", ">= 0.33.0", "< 1"

  s.add_development_dependency "sqlite3", '~> 0'
  s.add_development_dependency "capybara", '~> 0'
  s.add_development_dependency "database_cleaner", "~> 1.5"
  s.add_development_dependency "factory_girl", "~> 4.7"
  s.add_development_dependency "generator_spec", "~> 0.9"
  s.add_development_dependency "rake", ">= 12.3.3"
  s.add_development_dependency "rspec-rails", '~> 0'
  s.add_development_dependency "timecop", "~> 0.8"
end
