#!/bin/bash

function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}


set_colors() {
    export RED="\e[31m"
    export BOLDRED="\e[1;31m"
    export GREEN="\e[32m"
	export CYAN="\e[36m"
    export ENDCOLOR="\e[0m"
}


function setVars() {
	## OpenVPN Variables
	export AUTO_INSTALL=y
	export APPROVE_INSTALL=y
	export APPROVE_IP=y
	export IPV6_SUPPORT=n
	export PORT_CHOICE=3  # Random port
	#export PORT_CHOICE=2  # Custom port, Define desire port in the next line
	#export PORT=23432
	export PROTOCOL_CHOICE=2  # TCP
	export DNS=3  # Cloudflare
	export COMPRESSION_ENABLED=n
	export CUSTOMIZE_ENC=n
	export CLIENT=clientname
	export PASS=1

	## FreeRadius
	# The UDP port for radius accounting.
	export FREERADIUS_ACCT_PORT=1813
	# The UDP port for radius authentication.
	export FREERADIUS_AUTH_PORT=1812
	export FREERADIUS_IP="127.0.0.1"
	#export FREERADIUS_SHARED_SECRET="testing123"

	# Daloradius home directory
    DALORADIUSVERSION="1.2"
    DALORADIUSDIR="/var/www/html/daloradius"

    # SQL Config
    #RADIUSDBPASS="s93N2BmM7Y2cqP0mA"

}


function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ $ID == "debian" || $ID == "raspbian" ]]; then
			if [[ $VERSION_ID -lt 9 ]]; then
				echo "⚠️ Your version of Debian is not supported."
				echo ""
				echo "However, if you're using Debian >= 9 or unstable/testing then you can continue, at your own risk."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
				echo "⚠️ Your version of Ubuntu is not supported."
				echo ""
				echo "However, if you're using Ubuntu >= 16.04 or beta, then you can continue, at your own risk."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/system-release ]]; then
		source /etc/os-release
		if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
			OS="centos"
			if [[ $VERSION_ID -lt 7 ]]; then
				echo "⚠️ Your version of CentOS is not supported."
				echo ""
				echo "The script only support CentOS 7 and CentOS 8."
				echo ""
				exit 1
			fi
		fi
		if [[ $ID == "ol" ]]; then
			OS="oracle"
			if [[ ! $VERSION_ID =~ (8) ]]; then
				echo "Your version of Oracle Linux is not supported."
				echo ""
				echo "The script only support Oracle Linux 8."
				exit 1
			fi
		fi
		if [[ $ID == "amzn" ]]; then
			OS="amzn"
			if [[ $VERSION_ID != "2" ]]; then
				echo "⚠️ Your version of Amazon Linux is not supported."
				echo ""
				echo "The script only support Amazon Linux 2."
				echo ""
				exit 1
			fi
		fi
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, Amazon Linux 2, Oracle Linux 8 or Arch Linux system"
		exit 1
	fi
}


function installOpenVPN() {
	curl -O https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh
	chmod +x openvpn-install.sh

	./openvpn-install.sh

    OPENVPN_PORT=$(grep -E "port.*\$" /etc/openvpn/server.conf | awk '{print $2}')
	echo "$OPENVPN_PORT"

	echo -e "${GREEN}Do you want to use domain instead of IP address${ENDCOLOR}"
    until [[ $CONTINUE =~ (y|n) ]]; do
        read -rp "Continue? [y/n]: " -e CONTINUE    
    done

    if [[ "$CONTINUE" == "y" ]]; then
        until [[ $DOMAIN != "" ]]; do
            read -rp "Enter a domain: " DOMAIN
        done

        sed -i "/^remote [0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+ [0-9]\+$/c\remote $DOMAIN $OPENVPN_PORT" /etc/openvpn/client-template.txt
    fi

    # installOpenvpnRadiusPlugin
    # configOpenVPNFreeRdius

    # systemctl restart openvpn@server.service


	
}


function installOpenvpnRadiusPlugin() {

	cd /tmp || return

	if [[ $OS =~ (debian|ubuntu) ]]; then
		apt install -y build-essential libgcrypt20-dev wget

	elif [[ $OS == 'centos' ]]; then
		yum install -y epel-release libgcrypt-devel wget 
		yum groupinstall -y 'Development Tools'
	fi

	wget -O "/tmp/openvpn-radiusplugin.tar.gz" https://github.com/ValdikSS/openvpn-radiusplugin/archive/master/latest.tar.gz

	mkdir /tmp/openvpn-radiusplugin-master
	tar xfz "/tmp/openvpn-radiusplugin.tar.gz" -C /tmp/openvpn-radiusplugin-master --strip-components=1
	

	sed -i 's/if (param == "client-cert-not-required")/if (param == "verify-client-cert")/g' /tmp/openvpn-radiusplugin-master/Config.cpp
	sed -i 's/if (line == "client-cert-not-required")/if (line == "verify-client-certoptional" \|\| line == "verify-client-certnone")/g' /tmp/openvpn-radiusplugin-master/Config.cpp

	cd /tmp/openvpn-radiusplugin-master/ || exit
	make

	chmod +x /tmp/openvpn-radiusplugin-master/radiusplugin.so

	mkdir -p /usr/lib/openvpn
	mv /tmp/openvpn-radiusplugin-master/radiusplugin.so /usr/lib/openvpn/radiusplugin.so

	rm -rf /tmp/openvpn-radiusplugin-master

}


function configOpenVPNFreeRdius() {
	cat > /etc/openvpn/radiusplugin.cnf <<EOF
NAS-Identifier=OpenVPN

# The service type which is sent to the RADIUS server
Service-Type=5

# The framed protocol which is sent to the RADIUS server
Framed-Protocol=1

# The NAS port type which is sent to the RADIUS server
NAS-Port-Type=5

# The NAS IP address which is sent to the RADIUS server
NAS-IP-Address=172.17.0.56

# Path to the OpenVPN configfile. The plugin searches there for
# client-config-dir PATH   (searches for the path)
# status FILE     		   (searches for the file, version must be 1)
# client-cert-not-required (if the option is used or not)
# username-as-common-name  (if the option is used or not)

# Path to our OpenVPN configuration file. Each OpenVPN configuration file needs its own radiusplugin configuration file as well
OpenVPNConfig=/etc/openvpn/server.conf


# Support for topology option in OpenVPN 2.1
# If you don't specify anything, option "net30" (default in OpenVPN) is used. 
# You can only use one of the options at the same time.
# If you use topology option "subnet", fill in the right netmask, e.g. from OpenVPN option "--server NETWORK NETMASK"  
subnet=255.255.255.0
# If you use topology option "p2p", fill in the right network, e.g. from OpenVPN option "--server NETWORK NETMASK"
# p2p=10.8.0.1


# Allows the plugin to overwrite the client config in client config file directory,
# default is true
overwriteccfiles=true

# Allows the plugin to use auth control files if OpenVPN (>= 2.1 rc8) provides them.
# default is false
# useauthcontrolfile=false

# Only the accouting functionality is used, if no user name to forwarded to the plugin, the common name of certificate is used
# as user name for radius accounting.
# default is false
# accountingonly=false


# If the accounting is non essential, nonfatalaccounting can be set to true. 
# If set to true all errors during the accounting procedure are ignored, which can be
# - radius accounting can fail
# - FramedRouted (if configured) maybe not configured correctly
# - errors during vendor specific attributes script execution are ignored
# But if set to true the performance is increased because OpenVPN does not block during the accounting procedure.
# default is false
nonfatalaccounting=false

# Path to a script for vendor specific attributes.
# Leave it out if you don't use an own script.
# vsascript=/root/workspace/radiusplugin_v2.0.5_beta/vsascript.pl

# Path to the pipe for communication with the vsascript.
# Leave it out if you don't use an own script.
# vsanamedpipe=/tmp/vsapipe

# A radius server definition, there could be more than one.
# The priority of the server depends on the order in this file. The first one has the highest priority.
server
{
	# The UDP port for radius accounting.
	acctport=$FREERADIUS_ACCT_PORT
	# The UDP port for radius authentication.
	authport=$FREERADIUS_AUTH_PORT
	# The name or ip address of the radius server.
	name=$FREERADIUS_IP
	# How many times should the plugin send the if there is no response?
	retry=1
	# How long should the plugin wait for a response?
	wait=1
	# The shared secret.
	sharedsecret=$FREERADIUS_SHARED_SECRET
}
EOF

	{
		echo ""
		echo "# Custom Config"
		echo "plugin /usr/lib/openvpn/radiusplugin.so /etc/openvpn/radiusplugin.cnf"
		echo "verify-client-cert none"
		echo "username-as-common-name"
        echo "duplicate-cn"
	} >>/etc/openvpn/server.conf

    systemctl restart openvpn@server.service

}


function generateClientConf() {
	#perl -i~ -0777 -pe 's/a([\s\S]*?)b/text = ""/g' file.txt  # multi-line replace

	# Determine if we use tls-auth or tls-crypt
	if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
		TLS_SIG="1"
	elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
		TLS_SIG="2"
	fi

    homeDir="."  #TODO: Change this
	# Generates the custom client.ovpn
	cp /etc/openvpn/client-template.txt "$homeDir/$CLIENT.ovpn"
	{
        echo "setenv CLIENT_CERT 0"
        echo "auth-user-pass"
        echo ""
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		case $TLS_SIG in
		1)
			echo "<tls-crypt>"
			cat /etc/openvpn/tls-crypt.key
			echo "</tls-crypt>"
			;;
		2)
			echo "key-direction 1"
			echo "<tls-auth>"
			cat /etc/openvpn/tls-auth.key
			echo "</tls-auth>"
			;;
		esac
	} >>"$homeDir/$CLIENT.ovpn"

	echo ""
	echo "The configuration file has been written to $homeDir/$CLIENT.ovpn."
	echo "Download the .ovpn file and import it in your OpenVPN client."
}


function enableTCPBBR() {
	# enable TCP BBR algorithm to boost TCP speed
    echo "net.core.default_qdisc=fq" | tee -a /etc/sysctl.d/60-custom.conf
    echo "net.ipv4.tcp_congestion_control=bbr" | tee -a /etc/sysctl.d/60-custom.conf

    sysctl -p /etc/sysctl.d/60-custom.conf
}


INSTALL_APACHE() {
    echo -e "${CYAN}Installing Apache...${ENDCOLOR}"

	if [[ $OS =~ (debian|ubuntu) ]]; then
		apt install -y apache2

	elif [[ $OS == 'centos' ]]; then
    	dnf install -y httpd
	fi
    if [[ "$?" = "0" ]];then
        echo -e "${GREEN}Apache Installation Was Successful.${ENDCOLOR}"
    else
        echo -e "${RED}Apache Installation Is Failed${ENDCOLOR}"
        exit 1
    fi

	if [[ $OS =~ (debian|ubuntu) ]]; then
		systemctl start apache2
    	systemctl enable apache2
	elif [[ $OS == 'centos' ]]; then
    	systemctl start httpd
    	systemctl enable httpd
	fi

    # firewall-cmd --permanent --add-service={http,https}
    # firewall-cmd --reload
}



CHECK_MARIADB() {
	if mysql --version >/dev/null 2>&1; then
		echo -e "${GREEN}MariDB is already installed.${ENDCOLOR}"
		echo -e "${BOLDRED}Mariadb has root password, you should enter that.${ENDCOLOR}"
	else
		echo -e "${CYAN}MariaDb is not installed.${ENDCOLOR}"
	fi


	if (mysql -u root -e "quit" >/dev/null 2>&1) || ! (mysql --version >/dev/null 2>&1); then  # mariadb has not password or is not installed
		until [[ $MARIADB_PASSWORD != "" ]]; do
			read -s -r -p "Enter a new password for mariadb root user: " MARIADB_PASSWORD
		done
	else  # mariadb is installed
		status_code=1
		while [[ $status_code -ne 0 ]]; do
			echo ""
			read -s -r -p "Enter password for mariadb root user: " MARIADB_PASSWORD
			if [[ "$MARIADB_PASSWORD" != "" ]]; then
                mysql -u root -p"$MARIADB_PASSWORD" -e "quit" >/dev/null 2>&1
                status_code=$?
			fi
		done
	fi

	if mysql --version >/dev/null 2>&1; then
		export MARIADB_PASSWORD_PARAM="-p${MARIADB_PASSWORD}"
	fi

    echo ""

}

INSTALL_MARIADB() {
    echo -e "${CYAN}Installing MariaDB...${ENDCOLOR}"

	if [[ $OS =~ (debian|ubuntu) ]]; then
		apt install -y mariadb-server

	elif [[ $OS == 'centos' ]]; then
    	dnf install -y mariadb-server
	fi

    if [[ "$?" = "0" ]];then
        echo -e "${GREEN}MariaDB Installation Was Successful.${ENDCOLOR}"
    else
        echo -e "${RED}MariaDB Installation Is Failed${ENDCOLOR}"
        exit 1
    fi

    systemctl start mariadb
    systemctl enable mariadb

    # mysql_secure_installation

	if [[ -z "$MARIADB_PASSWORD" ]]; then
		echo -e "${BOLDRED}Mariadb password has not been entered${ENDCOLOR}"
		exit 10
	fi

	# Delete anonymous MySQL user
	mysql -u root "${MARIADB_PASSWORD_PARAM}" -e "DROP USER ''@'localhost.localdomain';" mysql # >/dev/null 2>&1
	# Disallow the Remote Root Login 
	mysql -u root "${MARIADB_PASSWORD_PARAM}" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');FLUSH PRIVILEGES;" # >/dev/null 2>&1
	# change root password
	mysql -u root "${MARIADB_PASSWORD_PARAM}" -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MARIADB_PASSWORD}';FLUSH PRIVILEGES;" # >/dev/null 2>&1

}


INSTALL_PHP() {
    echo -e "${CYAN}Installing PHP...${ENDCOLOR}"

	if [[ $OS =~ (debian|ubuntu) ]]; then
		apt install -y php libapache2-mod-php php-{gd,common,mail,mail-mime,mysql,pear,db,mbstring,xml,curl}
	elif [[ $OS == 'centos' ]]; then
		dnf install -y dnf-utils http://rpms.remirepo.net/enterprise/remi-release-9.rpm

		dnf -y module list php
		dnf -y module reset php

		#sudo dnf module enable php:remi-7.3
		dnf -y module enable php:remi-7.4
		dnf -y config-manager --set-enabled PowerTools

		dnf install -y @php
		dnf install -y php-{common,opcache,cli,gd,curl,mysqlnd,devel,pear,mbstring,xml}
		systemctl enable --now php-fpm

		dnf install -y php-pear
		pear install DB MDB2
	fi
}


INSTALL_FREERADIUS() {
    echo -e "${CYAN}Installing Freeradius...${ENDCOLOR}"
    #sudo dnf module list freeradius

	if [[ $OS =~ (debian|ubuntu) ]]; then
		export RADIUSDIR="/etc/freeradius/3.0"
		apt install -y freeradius freeradius-mysql freeradius-utils
	elif [[ $OS == 'centos' ]]; then
		export RADIUSDIR="/etc/raddb"
		dnf install -y freeradius freeradius-utils freeradius-mysql freeradius-perl
	fi

    if [[ "$?" = "0" ]];then
        echo -e "\e[0;32m"Freeradius Installation Was Successful."\e[0m"
    else
        echo -e "\e[0;31m"Freeradius Installation Is Failed"\e[0m"
        exit 1
    fi


    # sudo firewall-cmd --add-service=radius --permanent
    # sudo firewall-cmd --reload

	if [[ $OS =~ (debian|ubuntu) ]]; then
		systemctl start freeradius.service
    	systemctl enable freeradius.service
	elif [[ $OS == 'centos' ]]; then
    	systemctl start radiusd.service
    	systemctl enable radiusd.service
	fi
}


INSTALL_DALORADIUS() {
	if [[ -z "$DALORADIUSVERSION" ]]; then
		echo -e "${RED}DaloRadius version is not set.${ENDCOLOR}"
		exit 11
	fi

	if [[ $OS =~ (debian|ubuntu) ]]; then
		apt install -y wget unzip
	elif [[ $OS == 'centos' ]]; then
    	dnf install -y wget unzip
	fi

    # cd /tmp || exit

	wget -O "/tmp/daloradius-${DALORADIUSVERSION}.zip" "https://github.com/lirantal/daloradius/archive/refs/tags/${DALORADIUSVERSION}.zip"
	if [[ "$?" != "0" ]]; then
		echo -e "${BOLDRED}Error downloading file.${ENDCOLOR}"
		exit 20
	fi
    unzip -o -qq -d /tmp/ "/tmp/daloradius-${DALORADIUSVERSION}.zip"

    sudo mv -f "/tmp/daloradius-${DALORADIUSVERSION}/" "$DALORADIUSDIR"
	rm -rf "/tmp/daloradius-${DALORADIUSVERSION}.zip" "/tmp/daloradius-${DALORADIUSVERSION}/"
}


function FIX_RADACCT_TABLE() {
	mysql -u root -p"${MARIADB_PASSWORD}" -e "DROP TABLE radacct;" radius
    mysql -u root -p"${MARIADB_PASSWORD}" radius <<EOF
CREATE TABLE radacct (
radacctid bigint(21) NOT NULL auto_increment,
acctsessionid varchar(64) NOT NULL default '',
acctuniqueid varchar(32) NOT NULL default '',
username varchar(64) NOT NULL default '',
groupname varchar(64) NOT NULL default '',
realm varchar(64) default '',
nasipaddress varchar(15) NOT NULL default '',
nasportid varchar(15) default NULL,
nasporttype varchar(32) default NULL,
acctstarttime datetime NULL default NULL,
acctupdatetime datetime NULL default NULL,
acctstoptime datetime NULL default NULL,
acctinterval int(12) default NULL,
acctsessiontime int(12) unsigned default NULL,
acctauthentic varchar(32) default NULL,
connectinfo_start varchar(50) default NULL,
connectinfo_stop varchar(50) default NULL,
acctinputoctets bigint(20) default NULL,
acctoutputoctets bigint(20) default NULL,
calledstationid varchar(50) NOT NULL default '',
callingstationid varchar(50) NOT NULL default '',
acctterminatecause varchar(32) NOT NULL default '',
servicetype varchar(32) default NULL,
framedprotocol varchar(32) default NULL,
framedipv6address varchar(32) default NULL,
framedipv6prefix varchar(32) default NULL,
framedinterfaceid varchar(32) default NULL,
delegatedipv6prefix varchar(32) default NULL,
framedipaddress varchar(15) NOT NULL default '',
PRIMARY KEY (radacctid),
UNIQUE KEY acctuniqueid (acctuniqueid),
KEY username (username),
KEY framedipaddress (framedipaddress),
KEY acctsessionid (acctsessionid),
KEY acctsessiontime (acctsessiontime),
KEY acctstarttime (acctstarttime),
KEY acctinterval (acctinterval),
KEY acctstoptime (acctstoptime),
KEY nasipaddress (nasipaddress)
) ENGINE = INNODB;
EOF
}


function EDIT_FREERADIUS_CONFIGS() {

	cd /tmp || exit

	wget -O find_block.py https://raw.githubusercontent.com/ahhajlou/OpenVPN-Tunnel/master/find_block.py
	chmod +x find_block.py

	# Bandwidth limit
    ln -s "$RADIUSDIR"/mods-available/sqlcounter "$RADIUSDIR"/mods-enabled/sqlcounter

    cat <<- EOF >"$RADIUSDIR"/mods-enabled/sqlcounter
	#define a new sqlcounter
	sqlcounter monthly_limit{ 
	counter_name = 'Max-Total-Bandwidth'
	
	#define an attribute name. we will add this in daloRadius Profile
	check_name = 'Monthly-Bandwidth'
	
	sql_module_instance = sql
	key = 'User-Name'
	dialect = mysql
	reset = 30
	
	query = "SELECT SUM(acctinputoctets) + SUM(acctoutputoctets) FROM radacct WHERE UserName='%{\${key}}'"
	}
	EOF

	
	sed -i 's/${modules.sql.dialect}/mysql/g' "$RADIUSDIR"/mods-enabled/sqlcounter



    #TODO: Download and chmod 'find_block.py' script
    chmod +x ./find_block.py
    
    # Uncomment sql in 'sites-enabled/default'
    sections=('authorize' 'accounting' 'post-auth' 'session')

    for section in "${sections[@]}"; do
        ./find_block.py \
            -p "$RADIUSDIR"/sites-enabled/default \
            --block-start "$section {" \
            --block-end "}" \
            --uncomment \
            --str-to-uncomment "sql"
    done


    # Choose accounting update interval
	./find_block.py \
		-p "$RADIUSDIR"/sites-enabled/default \
		--block-start "post-auth {" \
		--block-end "}" \
		--insert --find-str "sql" \
		--insert-position "after" \
		--insert-str-stdin <<- EOF
		update reply {
                Acct-Interim-Interval = 60
        }
		EOF


    if [[ -z $FREERADIUS_SHARED_SECRET ]]; then
        echo -e "${CYAN}The radius shared secret not defined, random secret will be generated${ENDCOLOR}"
        FREERADIUS_SHARED_SECRET=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
    fi

    ./find_block.py \
    -p "$RADIUSDIR"/clients.conf \
    --block-start "client localhost {" \
    --block-end "}" \
    --replace \
    --old-str "secret = testing123" \
    --new-str "secret = $FREERADIUS_SHARED_SECRET"

}


CONFIG_MYSQL() {
	if [[ -z "$RADIUSDIR" ]]; then
		echo -e "${BOLDRED}Radius directory path not set.${ENDCOLOR}"
		exit 5
	fi

	if [[ -z "$DALORADIUSDIR" ]]; then
		echo -e "${BOLDRED}DaloRadius directory path not set.${ENDCOLOR}"
		exit 6
	fi

	if [[ -z "$RADIUSDBPASS" ]]; then
		echo -e "${CYAN}The radius database password not defined, random password will be generated${ENDCOLOR}"
		RADIUSDBPASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
	fi

    # freeradius
	if mysql -u root -p"${MARIADB_PASSWORD}" -e "USE radius;" >/dev/null 2>&1
	then
		echo -e "${BOLDRED}Radius database exists.${ENDCOLOR}"
		
		until [[ $CONTINUE =~ (y|n) ]]; do
			read -rp "Delete it? [y/n]: " -e CONTINUE
		done
		if [[ $CONTINUE == "n" ]]; then
			exit 1
		fi
		 mysql -u root -p"${MARIADB_PASSWORD}" -e "DROP DATABASE radius;"
	
	fi

    mysql -u root -p"${MARIADB_PASSWORD}" -e "CREATE DATABASE radius;GRANT ALL ON radius.* TO radius@localhost IDENTIFIED BY \"${RADIUSDBPASS}\";FLUSH PRIVILEGES;"
    mysql -u root -p"${MARIADB_PASSWORD}" radius < "${RADIUSDIR}"/mods-config/sql/main/mysql/schema.sql

    ln -s "${RADIUSDIR}/mods-available/sql" "${RADIUSDIR}/mods-enabled/"

    # Comment out tls for mysql in freeradius
    sed -i '/tls {/{:a;s/.*/#\0/;/\}[[:space:]]*$/!{n;ba}}' "${RADIUSDIR}/mods-available/sql"

    sed -i 's/dialect = "sqlite"/dialect = "mysql"/g' "${RADIUSDIR}/mods-available/sql"
    sed -i 's/driver = "rlm_sql_null"/#driver = "rlm_sql_null"/g' "${RADIUSDIR}/mods-available/sql"
    sed -i 's/#.*driver = "rlm_sql_${dialect}"/driver = "rlm_sql_${dialect}"/g' "${RADIUSDIR}/mods-available/sql"
    sed -i 's/#.*server = "localhost"/server = "localhost"/g' "${RADIUSDIR}/mods-available/sql"
    sed -i 's/#.*port = 3306/port = 3306/g' "${RADIUSDIR}/mods-available/sql"
    sed -i 's/#.*login = "radius"/login = "radius"/g' "${RADIUSDIR}/mods-available/sql"
    sed -i "s/#.*password = \"radpass\"/password = \"${RADIUSDBPASS}\"/g" "${RADIUSDIR}/mods-available/sql"
    sed -i 's/#.*read_clients = yes/read_clients = yes/g' "${RADIUSDIR}/mods-available/sql"


	if [[ $OS =~ (debian|ubuntu) ]]; then
		chgrp -h freerad "${RADIUSDIR}/mods-available/sql"
		chown -R freerad:freerad "${RADIUSDIR}/mods-available/sql"
	elif [[ $OS == 'centos' ]]; then
    	chgrp -h radiusd "${RADIUSDIR}/mods-available/sql"
	fi

	if [[ ! -f "${RADIUSDIR}/certs/client.key" || ! -f "${RADIUSDIR}/certs/client.p12" ]]; then
		cd "${RADIUSDIR}/certs" || return
		make
	fi


    # daloradius
    cd "$DALORADIUSDIR" || return
    mysql -u root -p"${MARIADB_PASSWORD}" radius < "$DALORADIUSDIR/contrib/db/fr2-mysql-daloradius-and-freeradius.sql"
    mysql -u root -p"${MARIADB_PASSWORD}" radius < "$DALORADIUSDIR/contrib/db/mysql-daloradius.sql"
	FIX_RADACCT_TABLE

    cp "${DALORADIUSDIR}/library/daloradius.conf.php.sample" "${DALORADIUSDIR}/library/daloradius.conf.php"
    sed -i "s/\$configValues\['CONFIG_DB_USER'\] = 'root';/\$configValues\['CONFIG_DB_USER'\] = 'radius';/g" "${DALORADIUSDIR}/library/daloradius.conf.php"
    sed -i "s/\$configValues\['CONFIG_DB_PASS'\] = '';/\$configValues\['CONFIG_DB_PASS'\] = '${RADIUSDBPASS}';/g" "${DALORADIUSDIR}/library/daloradius.conf.php"
    
	if [[ $OS =~ (debian|ubuntu) ]]; then
		chown -R www-data:www-data "$DALORADIUSDIR"
	elif [[ $OS == 'centos' ]]; then
    	chown -R apache:apache "$DALORADIUSDIR"
	fi
	chmod 664 "${DALORADIUSDIR}/library/daloradius.conf.php"

	if [[ $OS =~ (debian|ubuntu) ]]; then
		systemctl restart freeradius.service apache2.service
    	systemctl status freeradius.service apache2.service
	elif [[ $OS == 'centos' ]]; then
    	systemctl restart radiusd.service httpd
    	systemctl status radiusd.service httpd
	fi
    
}


function remove_all() {
	if [[ -e /etc/openvpn/server.conf ]]; then
		export MENU_OPTION="3"
        export AUTO_INSTALL=n

		curl -O https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh
		chmod +x openvpn-install.sh

		./openvpn-install.sh
	fi

	if [[ $OS =~ (debian|ubuntu) ]]; then
		apt autoremove --purge -y mariadb-server #libmariadb* mysql-common libmysql* libdbd-mysql
        apt autoremove --purge -y freeradius*
        apt autoremove --purge -y php php*
        apt autoremove --purge -y apache2* libapache*


        rm -rf /etc/mysql/
        rm -rf /var/log/mysql
        rm -rf /var/lib/mysql
        rm -rf /usr/lib/mysql

        rm -rf /etc/php/
        rm -rf /usr/lib/php
        rm -rf /usr/share/php
        rm -rf /var/lib/php

        rm -rf /etc/apache2
        rm -rf /usr/lib/apache2
        rm -rf /usr/share/apache2
        rm -rf /usr/share/doc/apache2
        rm -rf /var/log/apache2
        rm -rf /var/lib/apache2
        
        rm -rf /etc/freeradius/
        rm -rf /var/log/freeradius
        rm -rf /usr/lib/freeradius
        rm -rf /usr/share/freeradius
        rm -rf /usr/share/doc/freeradius

        rm -rf /var/www/html/daloradius/

	elif [[ $OS == 'centos' ]]; then
		dnf remove -y freeradius freeradius-utils freeradius-mysql freeradius-perl  #TODO: Not completed
	fi



}

function manageMenu() {
	echo ""
	echo "What do you want to do?"
	echo "   1) Install OpenVPN + Utility"
	echo "   2) Remove OpenVPN + Utility"
	echo "   3) Generate OpenVPN client config file"
    echo "   4) Enable TCP BBR"
    echo "   5) Only install freeradius + utility"
	echo "   6) Exit"
	until [[ $MENU_OPTION =~ ^[1-6]$ ]]; do
		read -rp "Select an option [1-6]: " MENU_OPTION
	done

	case $MENU_OPTION in
	1)
        CHECK_MARIADB
        installOpenVPN
        INSTALL_APACHE

        INSTALL_MARIADB
        INSTALL_PHP
        INSTALL_FREERADIUS
		if [[ $DALORADIUS_INSTALL_SOURCE == "true" ]]; then
        	INSTALL_DALORADIUS_SOURCE
		else
			INSTALL_DALORADIUS
		fi

        EDIT_FREERADIUS_CONFIGS
        CONFIG_MYSQL

        installOpenvpnRadiusPlugin
        configOpenVPNFreeRdius 
		;;
	2)
		remove_all
		;;
    3)
        generateClientConf
        ;;
    4)
        enableTCPBBR
        ;;
    5)
        CHECK_MARIADB
        INSTALL_APACHE

        INSTALL_MARIADB
        INSTALL_PHP
        INSTALL_FREERADIUS
		if [[ $DALORADIUS_INSTALL_SOURCE == "true" ]]; then
        	INSTALL_DALORADIUS_SOURCE
		else
			INSTALL_DALORADIUS
		fi

        EDIT_FREERADIUS_CONFIGS
        CONFIG_MYSQL
        ;;
	6)
		exit 0
		;;
	esac
}


if ! isRoot; then
	echo "Sorry, you need to run this as root"
	exit 1
fi

set_colors
checkOS
setVars


manageMenu
