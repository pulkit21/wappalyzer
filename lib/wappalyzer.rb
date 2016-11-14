#!/usr/bin/env ruby

require "wappalyzer/version"

require 'net/http'
require 'mini_racer'
require 'json'
require 'zlib'

Encoding.default_external = Encoding::UTF_8

module Wappalyzer
  class Detector
    def initialize
      @realdir = File.dirname(File.realpath(__FILE__))
      file = File.join(@realdir, 'apps.json')
      @json = JSON.parse(IO.read(file))
      @categories, @apps = @json['categories'], @json['apps']
    end

    def utf8_encoding(str)
      str.encode('UTF-8', :invalid => :replace, :undef => :replace)
    end

    def analyze(url)
      uri, body, headers = URI(url), nil, {}
      Net::HTTP.start(uri.host, uri.port,
                      :use_ssl => uri.scheme == 'https',
                      :verify_mode => OpenSSL::SSL::VERIFY_NONE,
                      :open_timeout => 5) do |http|
        begin
          resp = http.get(uri.request_uri)
        rescue Zlib::DataError
          resp = http.get(uri.request_uri, "Accept-Encoding" => "none")
        end

        resp.each_header { |k,v| headers[k.downcase] = utf8_encoding(v) }
        body = utf8_encoding(resp.body)
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
