#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#
# Auto install Shadowsocks Server (all version)
# 
# System Required:  CentOS 6+, Debian7+, Ubuntu12+

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1

cur_dir=$(pwd)
software=(Shadowsocks-Python Shadowsocks-Go Shadowsocks-libev)

libsodium_file="libsodium-1.0.17"
libsodium_url="https://github.com/LinkCloudX/Shadowsocks-script/raw/master/src/pack/libsodium-1.0.17.tar.gz"

mbedtls_file="mbedtls-2.16.0"
mbedtls_url="https://github.com/LinkCloudX/Shadowsocks-script/raw/master/src/pack/mbedtls-2.16.0-gpl.tgz"

shadowsocks_python_file="shadowsocks-master"
shadowsocks_python_url="https://github.com/LinkCloudX/Shadowsocks-script/raw/master/src/pack/shadowsocks-master.zip"
shadowsocks_python_init="/etc/init.d/shadowsocks-python"
shadowsocks_python_config="/etc/shadowsocks-python/config.json"
shadowsocks_python_centos="https://raw.githubusercontent.com/LinkCloudX/Shadowsocks-script/master/src/ssr/shadowsocks"
shadowsocks_python_debian="https://raw.githubusercontent.com/LinkCloudX/Shadowsocks-script/master/src/ssr/shadowsocks-debian"

shadowsocks_go_file_64="shadowsocks-server-linux64-1.2.2"
shadowsocks_go_url_64="https://github.com/LinkCloudX/Shadowsocks-script/raw/master/src/pack/shadowsocks-server-linux64-1.2.2.gz"
shadowsocks_go_file_32="shadowsocks-server-linux32-1.2.2"
shadowsocks_go_url_32="https://github.com/LinkCloudX/Shadowsocks-script/raw/master/src/pack/shadowsocks-server-linux32-1.2.2.gz"
shadowsocks_go_init="/etc/init.d/shadowsocks-go"
shadowsocks_go_config="/etc/shadowsocks-go/config.json"
shadowsocks_go_centos="https://raw.githubusercontent.com/LinkCloudX/Shadowsocks-script/master/src/ssr/shadowsocks-go"
shadowsocks_go_debian="https://raw.githubusercontent.com/LinkCloudX/Shadowsocks-script/master/src/ssr/shadowsocks-go-debian"

shadowsocks_libev_init="/etc/init.d/shadowsocks-libev"
shadowsocks_libev_config="/etc/shadowsocks-libev/config.json"
shadowsocks_libev_centos="https://raw.githubusercontent.com/LinkCloudX/Shadowsocks-script/master/src/ssr/shadowsocks-libev"
shadowsocks_libev_debian="https://raw.githubusercontent.com/LinkCloudX/Shadowsocks-script/master/src/ssr/shadowsocks-libev-debian"

# Stream Ciphers
common_ciphers=(
  aes-256-gcm
  aes-192-gcm
  aes-128-gcm
  aes-256-ctr
  aes-192-ctr
  aes-128-ctr
  aes-256-cfb
  aes-192-cfb
  aes-128-cfb
  camellia-128-cfb
  camellia-192-cfb
  camellia-256-cfb
  xchacha20-ietf-poly1305
  chacha20-ietf-poly1305
  chacha20-ietf
  chacha20
  salsa20
  rc4-md5
)
go_ciphers=(
  aes-256-cfb
  aes-192-cfb
  aes-128-cfb
  aes-256-ctr
  aes-192-ctr
  aes-128-ctr
  chacha20-ietf
  chacha20
  salsa20
  rc4-md5
)

# libev obfuscating
obfs_libev=(http tls)
# initialization parameter
libev_obfs=""

disable_selinux() {
  if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
  fi
}

check_sys() {
  local checkType=\$1
  local value=\$2

  local release=''
  local systemPackage=''

  if [[ -f /etc/redhat-release ]]; then
    release="centos"
    systemPackage="yum"
  elif grep -Eqi "debian|raspbian" /etc/issue; then
    release="debian"
    systemPackage="apt"
  elif grep -Eqi "ubuntu" /etc/issue; then
    release="ubuntu"
    systemPackage="apt"
  elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
    release="centos"
    systemPackage="yum"
  elif grep -Eqi "debian|raspbian" /proc/version; then
    release="debian"
    systemPackage="apt"
  elif grep -Eqi "ubuntu" /proc/version; then
    release="ubuntu"
    systemPackage="apt"
  elif grep -Eqi "centos|red hat|redhat" /proc/version; then
    release="centos"
    systemPackage="yum"
  fi

  if [[ "${checkType}" == "sysRelease" ]]; then
    if [ "${value}" == "${release}" ]; then
      return 0
    else
      return 1
    fi
  elif [[ "${checkType}" == "packageManager" ]]; then
    if [ "${value}" == "${systemPackage}" ]; then
      return 0
    else
      return 1
    fi
  fi
}

version_ge() {
  test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "\$1"
}

version_gt() {
  test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "\$1"
}

check_kernel_version() {
  local kernel_version=$(uname -r | cut -d- -f1)
  if version_gt "${kernel_version}" 3.7.0; then
    return 0
  else
    return 1
  fi
}

check_kernel_headers() {
  if check_sys packageManager yum; then
    if rpm -qa | grep -q headers-$(uname -r); then
      return 0
    else
      return 1
    fi
  elif check_sys packageManager apt; then
    if dpkg -s linux-headers-$(uname -r) >/dev/null 2>&1; then
      return 0
    else
      return 1
    fi
  fi
  return 1
}

getversion() {
  if [[ -s /etc/redhat-release ]]; then
    grep -oE "[0-9.]+" /etc/redhat-release
  else
    grep -oE "[0-9.]+" /etc/issue
  fi
}

centosversion() {
  if check_sys sysRelease centos; then
    local code=\$1
    local version="$(getversion)"
    local main_ver=${version%%.*}
    if [ "$main_ver" == "$code" ]; then
      return 0
    else
      return 1
    fi
  else
    return 1
  fi
}

autoconf_version() {
  if [ ! "$(command -v autoconf)" ]; then
    echo -e "[${green}Info${plain}] Starting install package autoconf"
    if check_sys packageManager yum; then
      yum install -y autoconf >/dev/null 2>&1 || echo -e "[${red}Error:${plain}] Failed to install autoconf"
    elif check_sys packageManager apt; then
      apt-get -y update >/dev/null 2>&1
      apt-get -y install autoconf >/dev/null 2>&1 || echo -e "[${red}Error:${plain}] Failed to install autoconf"
    fi
  fi
  local autoconf_ver=$(autoconf --version | grep autoconf | grep -oE "[0-9.]+")
  if version_ge "${autoconf_ver}" 2.67; then
    return 0
  else
    return 1
  fi
}

get_ip() {
  local IP=$(ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
  [ -z ${IP} ] && IP=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
  [ -z ${IP} ] && IP=$(wget -qO- -t1 -T2 ipinfo.io/ip)
  echo ${IP}
}

get_ipv6() {
  local ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
  [ -z ${ipv6} ] && return 1 || return 0
}

get_libev_ver() {
  libev_ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep 'tag_name' | cut -d\" -f4)
  [ -z ${libev_ver} ] && echo -e "[${red}Error${plain}] Get shadowsocks-libev latest version failed" && exit 1
}

get_opsy() {
  [ -f /etc/redhat-release ] && awk '{print (\$1,\$3~/^[0-9]/?\$3:\$4)}' /etc/redhat-release && return
  [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print \$3,\$4,\$5}' /etc/os-release && return
  [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print \$2}' /etc/lsb-release && return
}

is_64bit() {
  if [ $(getconf WORD_BIT) = '32' ] && [ $(getconf LONG_BIT) = '64' ]; then
    return 0
  else
    return 1
  fi
}

debianversion() {
  if check_sys sysRelease debian; then
    local version=$(get_opsy)
    local code=${1}
    local main_ver=$(echo ${version} | sed 's/[^0-9]//g')
    if [ "${main_ver}" == "${code}" ]; then
      return 0
    else
      return 1
    fi
  else
    return 1
  fi
}

download() {
  local filename=$(basename \$1)
  if [ -f ${1} ]; then
    echo "${filename} [found]"
  else
    echo "${filename} not found, download now..."
    wget --no-check-certificate -c -t3 -T60 -O ${1} ${2}
    if [ $? -ne 0 ]; then
      echo -e "[${red}Error${plain}] Download ${filename} failed."
      exit 1
    fi
  fi
}

download_files() {
  cd ${cur_dir}

  if [ "${selected}" == "1" ]; then
    download "${shadowsocks_python_file}.zip" "${shadowsocks_python_url}"
    if check_sys packageManager yum; then
      download "${shadowsocks_python_init}" "${shadowsocks_python_centos}"
    elif check_sys packageManager apt; then
      download "${shadowsocks_python_init}" "${shadowsocks_python_debian}"
    fi
  elif [ "${selected}" == "2" ]; then
    if is_64bit; then
      download "${shadowsocks_go_file_64}.gz" "${shadowsocks_go_url_64}"
    else
      download "${shadowsocks_go_file_32}.gz" "${shadowsocks_go_url_32}"
    fi
    if check_sys packageManager yum; then
      download "${shadowsocks_go_init}" "${shadowsocks_go_centos}"
    elif check_sys packageManager apt; then
      download "${shadowsocks_go_init}" "${shadowsocks_go_debian}"
    fi
  elif [ "${selected}" == "3" ]; then
    get_libev_ver
    shadowsocks_libev_file="shadowsocks-libev-$(echo ${libev_ver} | sed -e 's/^[a-zA-Z]//g')"
    shadowsocks_libev_url="https://github.com/shadowsocks/shadowsocks-libev/releases/download/${libev_ver}/${shadowsocks_libev_file}.tar.gz"

    download "${shadowsocks_libev_file}.tar.gz" "${shadowsocks_libev_url}"
    if check_sys packageManager yum; then
      download "${shadowsocks_libev_init}" "${shadowsocks_libev_centos}"
    elif check_sys packageManager apt; then
      download "${shadowsocks_libev_init}" "${shadowsocks_libev_debian}"
    fi
  fi

}

get_char() {
  SAVEDSTTY=$(stty -g)
  stty -echo
  stty cbreak
  dd if=/dev/tty bs=1 count=1 2>/dev/null
  stty -raw
  stty echo
  stty $SAVEDSTTY
}

error_detect_depends() {
  local command=\$1
  local depend=$(echo "${command}" | awk '{print \$4}')
  echo -e "[${green}Info${plain}] Starting to install package ${depend}"
  ${command} >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    echo -e "[${red}Error${plain}] Failed to install ${red}${depend}${plain}"
    echo "Please visit: http://www.jpjny.xyz and contact."
    exit 1
  fi
}

config_firewall() {
  if centosversion 6; then
    /etc/init.d/iptables status >/dev/null 2>&1
    if [ $? -eq 0 ]; then
      iptables -L -n | grep -i ${shadowsocksport} >/dev/null 2>&1
      if [ $? -ne 0 ]; then
        iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
        iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
        /etc/init.d/iptables save
        /etc/init.d/iptables restart
      else
        echo -e "[${green}Info${plain}] port ${green}${shadowsocksport}${plain} already be enabled."
      fi
    else
      echo -e "[${yellow}Warning${plain}] iptables looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
    fi
  elif centosversion 7; then
    systemctl status firewalld >/dev/null 2>&1
    if [ $? -eq 0 ]; then
      default_zone=$(firewall-cmd --get-default-zone)
      firewall-cmd --permanent --zone=${default_zone} --add-port=${shadowsocksport}/tcp
      firewall-cmd --permanent --zone=${default_zone} --add-port=${shadowsocksport}/udp
      firewall-cmd --reload
    else
      echo -e "[${yellow}Warning${plain}] firewalld looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
    fi
  fi
}

config_shadowsocks() {

  if check_kernel_version && check_kernel_headers; then
    fast_open="true"
  else
    fast_open="false"
  fi

  if [ "${selected}" == "1" ]; then
    if [ ! -d "$(dirname ${shadowsocks_python_config})" ]; then
      mkdir -p $(dirname ${shadowsocks_python_config})
    fi
    cat >${shadowsocks_python_config} <<-EOF
{
    "server":"0.0.0.0",
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":300,
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open}
}
EOF
  elif [ "${selected}" == "2" ]; then
    if [ ! -d "$(dirname ${shadowsocks_go_config})" ]; then
      mkdir -p $(dirname ${shadowsocks_go_config})
    fi
    cat >${shadowsocks_go_config} <<-EOF
{
    "server":"0.0.0.0",
    "server_port":${shadowsocksport},
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "method":"${shadowsockscipher}",
    "timeout":300
}
EOF
  elif [ "${selected}" == "3" ]; then
    local server_value="\"0.0.0.0\""
    if get_ipv6; then
      server_value="[\"[::0]\",\"0.0.0.0\"]"
    fi

    if [ ! -d "$(dirname ${shadowsocks_libev_config})" ]; then
      mkdir -p $(dirname ${shadowsocks_libev_config})
    fi

    if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
      cat >${shadowsocks_libev_config} <<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "password":"${shadowsockspwd}",
    "timeout":300,
    "user":"nobody",
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=${shadowsocklibev_obfs}"
}
EOF
    else
      cat >${shadowsocks_libev_config} <<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "password":"${shadowsockspwd}",
    "timeout":300,
    "user":"nobody",
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp"
}
EOF
    fi
  fi
}

install_dependencies() {
  if check_sys packageManager yum; then
    echo -e "[${green}Info${plain}] Checking the EPEL repository..."
    if [ ! -f /etc/yum.repos.d/epel.repo ]; then
      yum install -y epel-release >/dev/null 2>&1
    fi
    [ ! -f /etc/yum.repos.d/epel.repo ] && echo -e "[${red}Error${plain}] Install EPEL repository failed, please check it." && exit 1
    [ ! "$(command -v yum-config-manager)" ] && yum install -y yum-utils >/dev/null 2>&1
    [ x"$(yum-config-manager epel | grep -w enabled | awk '{print \$3}')" != x"True" ] && yum-config-manager --enable epel >/dev/null 2>&1
    echo -e "[${green}Info${plain}] Checking the EPEL repository complete..."

    yum_depends=(
      unzip gzip openssl openssl-devel gcc python python-devel python-setuptools pcre pcre-devel libtool libevent
      autoconf automake make curl curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel
      libev-devel c-ares-devel git qrencode
    )
    for depend in ${yum_depends[@]}; do
      error_detect_depends "yum -y install ${depend}"
    done
  elif check_sys packageManager apt; then
    apt_depends=(
      gettext build-essential unzip gzip python python-dev python-setuptools curl openssl libssl-dev
      autoconf automake libtool gcc make perl cpio libpcre3 libpcre3-dev zlib1g-dev libev-dev libc-ares-dev git qrencode
    )

    apt-get -y update
    for depend in ${apt_depends[@]}; do
      error_detect_depends "apt-get -y install ${depend}"
    done
  fi
}

install_check() {
  if check_sys packageManager yum || check_sys packageManager apt; then
    if centosversion 5; then
      return 1
    fi
    return 0
  else
    return 1
  fi
}

install_select() {
  if ! install_check; then
    echo -e "[${red}Error${plain}] Your OS is not supported to run it!"
    echo "Please change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again."
    exit 1
  fi

  clear
  while true; do
    echo "Which Shadowsocks server you'd select:"
    for ((i = 1; i <= ${#software[@]}; i++)); do
      hint="${software[$i - 1]}"
      echo -e "${green}${i}${plain}) ${hint}"
    done
    read -e -p "Please enter a number (Default ${software[0]}):" selected
    [ -z "${selected}" ] && selected="1"
    case "${selected}" in
    1 | 2 | 3)
      echo
      echo "You choose = ${software[${selected} - 1]}"
      echo
      break
      ;;
    *)
      echo -e "[${red}Error${plain}] Please only enter a number [1-3]"
      ;;
    esac
  done
}

install_prepare_password() {
  echo "Please enter password for ${software[${selected} - 1]}"
  read -e -p "(Default password: 123456):" shadowsockspwd
  [ -z "${shadowsockspwd}" ] && shadowsockspwd="123456"
  echo
  echo "password = ${shadowsockspwd}"
  echo
}

install_prepare_port() {
  while true; do
    dport=$(shuf -i 9000-19999 -n 1)
    echo -e "Please enter a port for ${software[${selected} - 1]} [1-65535]"
    read -e -p "(Default port: ${dport}):" shadowsocksport
    [ -z "${shadowsocksport}" ] && shadowsocksport=${dport}
    expr ${shadowsocksport} + 1 &>/dev/null
    if [ $? -eq 0 ]; then
      if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ] && [ ${shadowsocksport:0:1} != 0 ]; then
        echo
        echo "port = ${shadowsocksport}"
        echo
        break
      fi
    fi
    echo -e "[${red}Error${plain}] Please enter a correct number [1-65535]"
  done
}

install_prepare_cipher() {
  while true; do
    echo -e "Please select stream cipher for ${software[${selected} - 1]}:"

    if [[ "${selected}" == "1" || "${selected}" == "3" ]]; then
      for ((i = 1; i <= ${#common_ciphers[@]}; i++)); do
        hint="${common_ciphers[$i - 1]}"
        echo -e "${green}${i}${plain}) ${hint}"
      done
      read -e -p "Which cipher you'd select(Default: ${common_ciphers[0]}):" pick
      [ -z "$pick" ] && pick=1
      expr ${pick} + 1 &>/dev/null
      if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Please enter a number"
        continue
      fi
      if [[ "$pick" -lt 1 || "$pick" -gt ${#common_ciphers[@]} ]]; then
        echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#common_ciphers[@]}"
        continue
      fi
      shadowsockscipher=${common_ciphers[$pick - 1]}
    elif [ "${selected}" == "2" ]; then
      for ((i = 1; i <= ${#go_ciphers[@]}; i++)); do
        hint="${go_ciphers[$i - 1]}"
        echo -e "${green}${i}${plain}) ${hint}"
      done
      read -e -p "Which cipher you'd select(Default: ${go_ciphers[0]}):" pick
      [ -z "$pick" ] && pick=1
      expr ${pick} + 1 &>/dev/null
      if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Please enter a number"
        continue
      fi
      if [[ "$pick" -lt 1 || "$pick" -gt ${#go_ciphers[@]} ]]; then
        echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#go_ciphers[@]}"
        continue
      fi
      shadowsockscipher=${go_ciphers[$pick - 1]}
    fi

    echo
    echo "cipher = ${shadowsockscipher}"
    echo
    break
  done
}

install_prepare_libev_obfs() {
  if autoconf_version || centosversion 6; then
    while true; do
      echo -e "Do you want install simple-obfs for ${software[${selected} - 1]}? [y/n]"
      read -e -p "(default: n):" libev_obfs
      [ -z "$libev_obfs" ] && libev_obfs=n
      case "${libev_obfs}" in
      y | Y | n | N)
        echo
        echo "You choose = ${libev_obfs}"
        echo
        break
        ;;
      *)
        echo -e "[${red}Error${plain}] Please only enter [y/n]"
        ;;
      esac
    done

    if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
      while true; do
        echo -e "Please select obfs for simple-obfs:"
        for ((i = 1; i <= ${#obfs_libev[@]}; i++)); do
          hint="${obfs_libev[$i - 1]}"
          echo -e "${green}${i}${plain}) ${hint}"
        done
        read -e -        -p "Which obfs you'd select (Default: ${obfs_libev[0]}):" pick
        [ -z "$pick" ] && pick=1
        expr ${pick} + 1 &>/dev/null
        if [ $? -ne 0 ]; then
          echo -e "[${red}Error${plain}] Please enter a number"
          continue
        fi
        if [[ "$pick" -lt 1 || "$pick" -gt ${#obfs_libev[@]} ]]; then
          echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#obfs_libev[@]}"
          continue
        fi
        shadowsocklibev_obfs=${obfs_libev[$pick - 1]}

        echo
        echo "obfs = ${shadowsocklibev_obfs}"
        echo
        break
      done
    fi
  fi
}

install_prepare() {
  disable_selinux
  install_select
  install_prepare_password
  install_prepare_port
  install_prepare_cipher
  install_prepare_libev_obfs
}

install_libsodium() {
  if [ ! -f /usr/lib/libsodium.a ]; then
    cd ${cur_dir}
    download "${libsodium_file}.tar.gz" "${libsodium_url}"
    tar zxf ${libsodium_file}.tar.gz
    cd ${libsodium_file}
    ./configure --prefix=/usr && make && make install
    if [ $? -ne 0 ]; then
      echo -e "[${red}Error:${plain}] libsodium install failed."
      install_cleanup
      exit 1
    fi
  else
    echo -e "[${green}Info${plain}] libsodium already installed."
  fi
}

install_mbedtls() {
  if [ ! -f /usr/lib/libmbedtls.a ]; then
    cd ${cur_dir}
    download "${mbedtls_file}-gpl.tgz" "${mbedtls_url}"
    tar xf ${mbedtls_file}-gpl.tgz
    cd ${mbedtls_file}
    make SHARED=1 CFLAGS=-fPIC
    make DESTDIR=/usr install
    if [ $? -ne 0 ]; then
      echo -e "[${red}Error:${plain}] mbedtls install failed."
      install_cleanup
      exit 1
    fi
  else
    echo -e "[${green}Info${plain}] mbedtls already installed."
  fi
}

install_shadowsocks() {
  if [ "${selected}" == "1" ]; then
    cd ${cur_dir}
    unzip -q ${shadowsocks_python_file}.zip
    mv ${shadowsocks_python_file} shadowsocks
    cd shadowsocks
    python setup.py install --record /usr/local/shadowsocks-python.log
    if [ $? -ne 0 ]; then
      echo -e "[${red}Error:${plain}] Shadowsocks install failed."
      install_cleanup
      exit 1
    fi
    if [ -f ${shadowsocks_python_init} ]; then
      mv ${shadowsocks_python_init} /etc/init.d/shadowsocks-python
      chmod +x /etc/init.d/shadowsocks-python
      update-rc.d -f shadowsocks-python defaults
    fi
    if check_sys packageManager yum; then
      chkconfig --add shadowsocks-python
    fi
    /etc/init.d/shadowsocks-python start
  elif [ "${selected}" == "2" ]; then
    cd ${cur_dir}
    if is_64bit; then
      gunzip -c ${shadowsocks_go_file_64}.gz >${shadowsocks_go_file_64}
      mv ${shadowsocks_go_file_64} /usr/local/bin/shadowsocks-go
    else
      gunzip -c ${shadowsocks_go_file_32}.gz >${shadowsocks_go_file_32}
      mv ${shadowsocks_go_file_32} /usr/local/bin/shadowsocks-go
    fi
    if [ $? -ne 0 ]; then
      echo -e "[${red}Error:${plain}] Shadowsocks install failed."
      install_cleanup
      exit 1
    fi
    if [ -f ${shadowsocks_go_init} ]; then
      mv ${shadowsocks_go_init} /etc/init.d/shadowsocks-go
      chmod +x /etc/init.d/shadowsocks-go
      update-rc.d -f shadowsocks-go defaults
    fi
    if check_sys packageManager yum; then
      chkconfig --add shadowsocks-go
    fi
    /etc/init.d/shadowsocks-go start
  elif [ "${selected}" == "3" ]; then
    cd ${cur_dir}
    tar zxf ${shadowsocks_libev_file}.tar.gz
    cd ${shadowsocks_libev_file}
    ./configure && make && make install
    if [ $? -ne 0 ]; then
      echo -e "[${red}Error:${plain}] Shadowsocks-libev install failed."
      install_cleanup
      exit 1
    fi
    if [ -f ${shadowsocks_libev_init} ]; then
      mv ${shadowsocks_libev_init} /etc/init.d/shadowsocks-libev
      chmod +x /etc/init.d/shadowsocks-libev
      update-rc.d -f shadowsocks-libev defaults
    fi
    if check_sys packageManager yum; then
      chkconfig --add shadowsocks-libev
    fi
    /etc/init.d/shadowsocks-libev start
  fi

  if [ $? -eq 0 ]; then
    echo -e "[${green}Info${plain}] Shadowsocks install success!"
  else
    echo -e "[${red}Error:${plain}] Shadowsocks install failed."
    install_cleanup
    exit 1
  fi
}

install_cleanup() {
  cd ${cur_dir}
  rm -rf ${shadowsocks_python_file}.zip ${shadowsocks_python_file} shadowsocks
  rm -rf ${shadowsocks_go_file_64}.gz ${shadowsocks_go_file_32}.gz
  rm -rf ${shadowsocks_libev_file}.tar.gz ${shadowsocks_libev_file}
}

install() {
  install_prepare
  install_dependencies
  install_libsodium
  install_mbedtls
  download_files
  config_shadowsocks
  install_shadowsocks
  install_cleanup
}

# Initialization steps
action=\$1
[ -z \$1 ] && action=install
case "$action" in
install | uninstall)
  ${action}
  ;;
*)
  echo "Usage: \$0 {install|uninstall}"
  ;;
esac

