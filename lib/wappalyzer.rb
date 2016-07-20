#!/usr/bin/env ruby

require "wappalyzer/version"

require 'net/http'
require 'mini_racer'
require 'json'

Encoding.default_external = Encoding::UTF_8

module Wappalyzer
  class Detector
    def initialize
      @realdir = File.dirname(File.realpath(__FILE__))
      file = File.join(@realdir, 'apps.json')
      @json = JSON.parse(IO.read(file))
      @categories, @apps = @json['categories'], @json['apps']
    end

    def analyze(url)
      uri, body, headers = URI(url), nil, {}
      Net::HTTP.start(uri.host, uri.port, :use_ssl => uri.scheme == 'https', :open_timeout => 5) do |http|
        resp = http.get(uri.request_uri)
        resp.each_header{|k,v| headers[k.downcase] = v}
        body = resp.body.encode('UTF-8', :invalid => :replace, :undef => :replace)
      end

      cxt = MiniRacer::Context.new
      cxt.load File.join(@realdir, 'js', 'wappalyzer.js')
      cxt.load File.join(@realdir, 'js', 'driver.js')
      data = {'host' => uri.hostname, 'url' => url, 'html' => body, 'headers' => headers}
      output = cxt.eval("w.apps = #{@apps.to_json}; w.categories = #{@categories.to_json}; w.driver.data = #{data.to_json}; w.driver.init();")
      JSON.load(output)
    end
  end
end

if $0 == __FILE__
  url = ARGV[0]
  if url
    puts JSON.pretty_generate(Wappalyzer::Detector.new.analyze(ARGV[0]))
  else
    puts "Usage: #{__FILE__} http://example.com"
  end
end
