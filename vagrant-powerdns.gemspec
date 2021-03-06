# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'vagrant-powerdns/version'

Gem::Specification.new do |spec|
  spec.name          = "vagrant-powerdns"
  spec.version       = Vagrant::PowerDNS::VERSION
  spec.authors       = ["Sayid Munawar"]
  spec.email         = ["sayid.munawar@gmail.com"]

  spec.summary       = "Vagrant plugin to manage powerdns zone record"
  spec.description   = "This plugin will push changes to PowerDNS API after vagrant up / halt"
  spec.homepage      = "https://github.com/chenull/vagrant-powerdns"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.10"
  spec.add_development_dependency "rake", "~> 10.0"

  spec.add_runtime_dependency "httparty", "~> 0.13.7"
  spec.add_runtime_dependency "json"

end
