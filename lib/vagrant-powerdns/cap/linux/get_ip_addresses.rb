module Vagrant
  module PowerDNS
    module Cap
      module Linux
        module GetIpAddresses

          # This function much return an array of IP addresses
          def self.get_ip_addresses(machine)
            ips = ""
            ipaddrs_cmd = "ip -4 addr | awk '/inet/ {print $2}' | cut -d/ -f1"
            machine.communicate.execute(ipaddrs_cmd) do |type, data|
              ips = data if type == :stdout
            end
            ips.split("\n")
          end

        end
      end
    end
  end
end
