module Vagrant
  module PowerDNS
    module Cap
      module Linux
        module GetHostname
          def self.get_hostname(machine)
            return @hostname if @hostname
            hostname_cmd = "hostname"
            machine.communicate.execute(hostname_cmd) do |type, data|
              if type == :stdout
                @hostname = data.chomp
              end
            end
            @hostname
          end
        end
      end
    end
  end
end
