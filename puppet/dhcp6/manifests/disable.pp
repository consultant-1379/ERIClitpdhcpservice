# ----------
# Remove and Disable the DHCP6 server
# ----------
class dhcp6::disable {

  include dhcp6::params

  $packagename =  $dhcp6::params::packagename
  $servicename =  $dhcp6::params::servicename

  package { $packagename:
    ensure => absent,
  }

  service { $servicename:
    ensure    => stopped,
    enable    => false,
    hasstatus => true,
    require   => Package[$packagename],
  }

}

