require 'uri'

module Vagrant
  module PowerDNS
    class Config < Vagrant.plugin("2", :config)

      attr_accessor :api_url
      attr_accessor :api_key
      attr_accessor :cidr
      attr_accessor :default_zone
      attr_accessor :disable
      attr_accessor :dns_server_ip 

      def initialize
        @api_url = UNSET_VALUE
        @api_key = UNSET_VALUE
        @cidr = UNSET_VALUE
        @default_zone = UNSET_VALUE
        @disable = UNSET_VALUE
        @dns_server_ip = UNSET_VALUE
      end

      def finalize!

        if @default_zone == UNSET_VALUE
          @default_zone = nil
        elsif !@default_zone.is_a?(Zone)
          @default_zone = Zone.new @default_zone;
        end

        @api_url = nil if @api_url == UNSET_VALUE
        @api_key = nil if @api_key == UNSET_VALUE
        @cidr = nil if @cidr == UNSET_VALUE
        @disable = false if @disable == UNSET_VALUE

        if @dns_server_ip == UNSET_VALUE
          uri = URI.parse(@api_url)
          @dns_server_ip = uri.host
        end
      end

      def enabled?
        @api_url.is_a?(String) or @api_key.is_a?(String) or @default_zone.is_a?(String)
      end

      def validate(machine)
        if enabled?
          #return if not @api_url.nil? and not @api_key.nil? and not @default_zone.nil?

          errors = []

          # verify @disable
          if @disable != true and @disable != false then errors << 'invalid disable setting' end

          # verify zone
          begin @default_zone = Zone.new @default_zone; rescue => e; errors << e.message end

          # verify api_url
          begin @api_url = String.new @api_url; rescue => e; errors << "powerdns.api_url: Invalid URL. It should be like `http://ns.example.com:8081'" end

          # verify api_key
          begin @api_key = String.new @api_key; rescue => e; errors << "powerdns.api_key: Invalid API Key. It should be like `api_key_of_powerdns'"  end

          # verify zone
          #begin @default_zone = Zone.new @default_zone; rescue => e; errors << "config.powerdns.default_zone: Invalid Zone #{@default_zone}. It should be like: `dev.example.com'" end

          if @cidr == nil
            errors << 'cidr not specified'
          end

          return { 'PowerDNS configuration' => errors }
        end
      end

    end
  end
end
