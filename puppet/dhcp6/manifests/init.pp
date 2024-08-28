class dhcp6 (
  $nameservers         = undef,
  $ntpservers          = undef,
  $domainsearch        = undef,
  $dhcp_conf_header    = 'INTERNAL_TEMPLATE',
  $dhcp_conf_ntp       = 'INTERNAL_TEMPLATE',
  $interfaces          = undef,
  $logfacility         = 'daemon',
  $dhcp_conf_fragments = {},
  $default_lease_time  = undef,
  $max_lease_time      = undef,
  $preference          = undef,
) {

  if $nameservers {
     validate_array($nameservers)
  }
  if $ntpservers {
     validate_array($ntpservers)
  }
  if $domainsearch {
     validate_array($domainsearch)
  }

  $dhcp_dir    = '/etc/dhcp'
  $packagename = 'dhcp'
  $servicename = 'dhcpd6'

  $dhcp_interfaces = $interfaces

  $dhcp_conf_header_real = $dhcp_conf_header ? {
    INTERNAL_TEMPLATE => template('dhcp6/dhcpd6.conf-header.erb'),
    default           => $dhcp_conf_header,
  }
  $dhcp_conf_ntp_real = $dhcp_conf_ntp ? {
    INTERNAL_TEMPLATE => template('dhcp6/dhcpd6.conf.ntp.erb'),
    default           => $dhcp_conf_ntp,
  }

  if ! defined(Package[$packagename]) {

    package { $packagename:
      ensure   => installed,
      provider => $operatingsystem ? {
        default => undef,
      }
    }
  }

  if ! defined(File[$dhcp_dir]) {
  file { $dhcp_dir:
    mode    => '0755',
    require => Package[$packagename],
  }
  }

  # Only debian and ubuntu have this style of defaults for startup.
  case $operatingsystem {
    'redhat','centos','fedora','Scientific': {
      file{ '/etc/sysconfig/dhcpd6':
        ensure  => present,
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        before  => Package[$packagename],
        notify  => Service[$servicename],
        content => template('dhcp6/redhat/sysconfig-dhcpd'),
      }
    }
  }

  Concat { require => Package[$packagename] }

  # dhcpd.conf
  concat {  "${dhcp_dir}/dhcpd6.conf": }
  concat::fragment { 'dhcp6-conf-header':
    target  => "${dhcp_dir}/dhcpd6.conf",
    content => $dhcp_conf_header_real,
    order   => 01,
  }

  concat::fragment { 'dhcp6-conf-ntp':
    target  => "${dhcp_dir}/dhcpd6.conf",
    content => $dhcp_conf_ntp_real,
    order   => 02,
  }

  create_resources('concat::fragment', $dhcp_conf_fragments)

  # dhcpd.pool
  concat { "${dhcp_dir}/dhcpd6.pools": }
  concat::fragment { 'dhcp6-pools-header':
    target  => "${dhcp_dir}/dhcpd6.pools",
    content => "# DHCP6 Subnets\n",
    order   => 01,
  }

  service { $servicename:
    ensure    => running,
    enable    => true,
    hasstatus => true,
    subscribe => [Concat["${dhcp_dir}/dhcpd6.pools"], File["${dhcp_dir}/dhcpd6.conf"]],
    require   => Package[$packagename],
  }

}

