# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'wappalyzer/version'

Gem::Specification.new do |spec|
  spec.name          = "wappalyzer"
  spec.version       = Wappalyzer::VERSION
  spec.authors       = ["pulkit21"]
  spec.email         = ["pulkit.ag02@gmail.com"]

  spec.summary       = %q{Analyzes a provided url and returns any services it can detect}
  spec.description   = %q{This analyzes a url and tries to guess what software it uses (like server software, CMS, framework, programming language).}
  spec.homepage      = "https://github.com/pulkit21/wappalyzer"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "mini_racer", ">= 0.2.4"

  spec.add_development_dependency "bundler", "~> 1.11"
  spec.add_development_dependency "rake", ">= 12.3.3"
  spec.add_development_dependency "rspec", "~> 3.0"
end
