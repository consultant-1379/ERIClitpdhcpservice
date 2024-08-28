#For LITPCDS-6548

define dhcpservice::config_server ($interfaces           = undef,
                                   $address              = undef,
                                   $peer_address         = undef,
                                   $nameservers          = undef,
                                   $domainsearch         = undef,
                                   $ntpservers           = undef,
                                   $default_lease_time   = undef,
                                   $max_lease_time       = undef,
                                   $role                 = 'primary',
                                   $port                 = 647,
                                   $ensure               = 'present'){
    if $ensure == 'absent' {
      include dhcp::params
      $servicename = $dhcp::params::servicename
      service { $servicename:
        enable => false,
        ensure => stopped,
      }
    }
    else {
      class { 'dhcp':
        default_lease_time => $default_lease_time,
        max_lease_time     => $max_lease_time,
        interfaces         => $interfaces,
        nameservers        => $nameservers,
        ntpservers         => $ntpservers,
        domainsearch       => $domainsearch,
      }

      if $peer_address {
        class { dhcp::failover:
          address      => $address,
          port         => $port,
          peer_address => $peer_address,
          role         => $role,
        }
      }
    }
}
