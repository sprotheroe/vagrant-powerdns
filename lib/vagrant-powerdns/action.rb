require 'netaddr'

module Vagrant
  module Action

    module Common
      def initialize(app, env)
        @app = app
        @machine = env[:machine]
        @zone = env[:machine].config.powerdns.default_zone
        @host = determine_hostname(@machine)

        # Identify who I am
        @myuser = Etc.getlogin.gsub(/\s+/, '')
        @myhost = Socket.gethostname
      end

      private

      def has_cidr?(env)
        !!env[:machine].config.powerdns.cidr
      end

      def domain
        @domain = @host.include?(@zone.name)? @host : @host + @zone.dotted
      end

      def create_dns_entry(env)
        hostname = determine_hostname(@machine)
        fqdn = determine_fqdn(hostname)
        all_ips = @machine.guest.capability(:get_ip_addresses)
        ip = ip_to_bind(all_ips)
        # add host record
        canonical_fqdn = fqdn + '.'
        add_host_record(env, canonical_fqdn, ip)
        # configure resolver
      end

      def determine_hostname(machine)
        hostname = machine.config.vm.hostname
        if hostname.nil? || hostname.empty?
          hostname = machine.guest.capability(:get_hostname)
        end
        hostname
      end

      def determine_fqdn(hostname)
        hostname_parts = hostname.split('.')
        if hostname_parts.size > 1
          hostname.strip
        else
          domain_parts = @zone.name.split('.')
          domain_parts.unshift(hostname)
          cleaned_domain_parts = domain_parts.map(&:strip).reject { |p| p.empty? }
          cleaned_domain_parts.join('.')
        end
      end

      def ip_to_bind(ips)
         cidr = NetAddr::CIDR.create @machine.config.powerdns.cidr
         ips.find { |ip| cidr.contains? ip }
      end

      def powerdns_client
        #config = env[:machine].config.powerdns
        config = @machine.config.powerdns
        PdnsRestApiClient.new(config.api_url, config.api_key)
      end

      def get_default_ip
        ip = nil
        # assume default gateway address
        @machine.communicate.sudo "ip route get to 8.8.8.8 | head -n 1" do |type,data|
          stdout = data.chomp if type == :stdout
          if !stdout.empty?
            re = /src ([0-9\.]+)/
            ip = stdout.match(re)[1]
          end
        end
        ip
      end

      def check_return(ret)
        error = nil
        if ret.is_a?(String)
          error = ret
        else
          if ret.is_a?(Hash)
            error = ret.values[0] if ret.keys[0] == "error"
          elsif ret.code == 204
            # no action here
            error = nil
          else
            puts ret.inspect
            raise "Unknown response from PowerDNS API"
          end
        end
        error
      end

      def get_A_record(p, zone, fqdn)
        # NOTE - this implementation assumes there is only one
        # matching resource record
        rrset = p.zone(zone)['rrsets']
        recs = rrset.select do |rec|
          rec['type'] == 'A' && rec['name'] == fqdn
        end
        recs.first
      end

      def add_host_record(env, fqdn, ip)
        zone = @zone.name
        p = powerdns_client

        # Only update if IP changed or inactive
        rec = get_A_record(p, zone, fqdn)
        record_not_found = rec.nil? || rec["records"].select {|r| r["content"] == fqdn }.empty?
        record_disabled = rec && rec["records"].find { |r| r["disabled"] }

        if record_not_found or record_disabled
          env[:ui].info "PowerDNS action..."
          # Append new comment
          new_comment = {
            content: "#{@myuser} added this record from #{@myhost}",
            account: @myuser,
          }
          comments = [ new_comment ]

          ret = p.modify_domain(domain: fqdn, ip: ip, zone_id: zone, comments: comments)
          error = check_return(ret)

          # Display ui
          if error.nil?
              configure_resolver
              env[:ui].detail "=> record #{fqdn}(#{ip}) in zone #{zone} added !"
          else
            env[:ui].detail "=> failed to add record #{fqdn}(#{ip}) in zone #{zone}. Error was: #{error}"
          end
        end
      end

      def disable_host_record(env, fqdn)
        p = powerdns_client
        zone = @zone.name

        rec = get_A_record(p, zone, fqdn)

        # Get A record
        record = rec["records"].first
        # Get comments for this domain
        comments = rec["comments"]

        # only disable if active
        if record && !record["disabled"]
          env[:ui].info "PowerDNS action..."

          # Prepare comment to be appended
          new_comment = {
            content: "#{@myuser} disabled this record from #{@myhost}",
            account: @myuser,
          }
          comments << new_comment

          # Get the old IP
          ip = record["content"]

          ret = p.disable_domain(domain: fqdn, ip: ip, zone_id: zone,
                                 comments: comments)

          error = check_return(ret)

          # Display ui
          if error.nil?
              env[:ui].detail "=> record #{fqdn}(#{ip}) in zone #{zone} disabled !"
          else
            env[:ui].detail "=> failed to disable record #{fqdn} in zone #{zone}. Error was: #{error}"
          end
        end
      end

      def configure_resolver
        script = <<-SCRIPT.gsub(/^ {8}/, '')
        #!/bin/bash
        line='nameserver #{@machine.config.powerdns.dns_server_ip}'
        file=/etc/resolvconf/resolv.conf.d/head
        if ! grep -q -e "'$line'" $file; then 
          echo $line >> $file
          resolvconf -u
        fi
        SCRIPT

        scriptfile = Tempfile.new('vagrant-unbound-configure-resolver', binmode: true)
        begin
          scriptfile.write(script)
          scriptfile.close
          @machine.communicate.tap do |comm|
            remote_script = "/tmp/configure-resolver"
            comm.upload(scriptfile.path, remote_script)
            comm.sudo("chmod +x #{remote_script}; #{remote_script}")
            #comm.sudo("chmod +x #{remote_script}; #{remote_script}; rm #{remote_script}")
          end
        ensure
          scriptfile.unlink
        end
      end

    end

    class Up
      include Common

      def call(env)
        @app.call(env)
        if @machine.config.powerdns.enabled?
          if has_cidr?(env)
            create_dns_entry(env)
          else
            ip = get_default_ip
            add_host_record(env, domain, ip)
          end
        end
      end
    end


    class Destroy
      include Common

      def call(env)
        if @machine.config.powerdns.enabled?
          hostname = determine_hostname(@machine)
          fqdn = determine_fqdn(hostname)
          disable_host_record(env, fqdn+'.')
        end
        @app.call(env)
      end
    end

  end
end
