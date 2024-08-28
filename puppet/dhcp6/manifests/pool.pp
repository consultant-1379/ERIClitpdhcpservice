define dhcp6::pool (
  $network,
  $range         = '',
  $ensure
) {

  include dhcp6::params

  $dhcp_dir = $dhcp6::params::dhcp_dir

  concat::fragment { "dhcp6_pool_${name}":
    target      => "${dhcp_dir}/dhcpd6.pools",
    content     => template('dhcp6/dhcpd6.pool.erb'),
    ensure      => $ensure,
  }

}

