#!/bin/bash

function set_colors() {
    export RED="\e[31m"
    export BOLDRED="\e[1;31m"
    export GREEN="\e[32m"
	export CYAN="\e[36m"
    export ENDCOLOR="\e[0m"
}


function set_vars() {
    export IPV4_REGEX='^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
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

function Detect_Country() {
	# Source: https://github.com/adamalbers/asn-lookup
	local ip_address
	local whois_res
	
	if [[ $OS =~ (debian|ubuntu) ]]; then
		apt install -y whois
	elif [[ $OS == 'centos' ]]; then
		dnf install -y whois
	fi

	# Detect public IPv4 address and pre-fill for the user
	ip_address=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	# WHOIS lookup for IP.
	whois_res=$(whois -h whois.cymru.com " -v $ip_address")


	COUNTRY=$(echo "$whois_res" | awk -F ' *[|] *' 'NR==1{for(i=1;i<=NF;i++)if($i=="CC"){c=i;break}} NR==2{print $c}')

	if [[ -z "$COUNTRY" ]]; then
		echo -e "${RED}No country was found.${ENDCOLOR}"
		return 30
	fi

	echo -e "${CYAN}Country: $COUNTRY${ENDCOLOR}"
}


function Port_Prompt() {
	echo ""
	echo "What port do you want to listen to?"
	echo "   1) Custom"
	echo "   2) Random [49152-65535]"
	until [[ $PORT_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "Port choice [1-2]: " -e -i 1 PORT_CHOICE
	done


	case $PORT_CHOICE in
	1)
		until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
			read -rp "Custom port [1-65535]: " -e PORT
			if lsof -i:"$PORT" >/dev/null 2>&1; then
				echo -E "${BOLDRED}The port is not open.${ENDCOLOR}"
				PORT="-1"
			fi
		done
		;;
	2)
		# Generate random number within private ports range
		PORT=$(shuf -i49152-65535 -n1)
		echo "Random Port: $PORT"
		;;
	esac
}


function Ip_Port_Prompt() {
	# IPV4_REGEX='^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
	echo ""
	echo "Main server IP V4?"
	until [[ $MAIN_SERVER_IP =~ $IPV4_REGEX ]]; do
		read -rp "IP V4: " MAIN_SERVER_IP
	done

	echo ""
	echo "Main server proxy listening port"
	until [[ $MAIN_SERVER_PROXY_PORT =~ ^[0-9]+$ ]] && [ "$MAIN_SERVER_PROXY_PORT" -ge 1 ] && [ "$MAIN_SERVER_PROXY_PORT" -le 65535 ]; do
		read -rp "Custom port [1-65535]: " -e MAIN_SERVER_PROXY_PORT
	done

	echo ""
	echo "Main server local port"
	until [[ $LOCAL_PORT_ON_MAIN_SERVER =~ ^[0-9]+$ ]] && [ "$LOCAL_PORT_ON_MAIN_SERVER" -ge 1 ] && [ "$LOCAL_PORT_ON_MAIN_SERVER" -le 65535 ]; do
		read -rp "Custom port [1-65535]: " -e LOCAL_PORT_ON_MAIN_SERVER
	done
}


function Setup_Tunnel() {
	if ! Detect_Country; then
		echo -e "${CYAN}The country is not detected. you have to choose server manually.${ENDCOLOR}"
	fi


	echo ""
	echo "Tunnel type"
	echo "   1) gost + kcp"
    echo "   2) Forward ssh tunnel (Bridge Server)"
    echo "   3) Reverse ssh tunnel (Main Server)"
    echo "   4) Ghostunnel"
	until [[ $TUNNEL_TYPE =~ ^[1-4]$ ]]; do
		read -r -p "Choose one option: " TUNNEL_TYPE
	done


    if [[ $TUNNEL_TYPE -eq 2 ]]; then
        SERVER_TYPE="2"
    elif [[ $TUNNEL_TYPE -eq 3 ]]; then
        SERVER_TYPE="1"
    else
        echo ""
        echo "Server type"
        echo "   1) Main server"
        echo "   2) Bridge server"
        until [[ $SERVER_TYPE =~ (1|2) ]]; do
            read -r -p "Choose one option:  " SERVER_TYPE
        done
    fi


	case $SERVER_TYPE in
		# Main server
		1)
			case $TUNNEL_TYPE in
			1)
                if [[ $OS =~ (debian|ubuntu) ]]; then
                    apt install -y wget
                elif [[ $OS == 'centos' ]]; then
                    yum install -y wget
                fi

                cd /tmp/ || exit
                wget -O gost-linux-amd64-2.11.5.gz https://github.com/ginuerzh/gost/releases/download/v2.11.5/gost-linux-amd64-2.11.5.gz
                if [[ "$?" != 0 ]]; then
                    echo -e "${RED}Download was not successfull.${ENDCOLOR}"
                    exit 1
                fi

                gunzip -qq gost-linux-amd64-2.11.5.gz
                
                chmod +x gost-linux-amd64-2.11.5

                mv gost-linux-amd64-2.11.5 /usr/bin/gost



				Port_Prompt

				cat <<- EOF >/etc/systemd/system/gost-server.service
					[Unit]
					Description=Gost with kcp Tunnel - Server
					After=network.target
					Wants=network.target

					[Service]
					Type=simple
					ExecStart=/usr/bin/gost -L relay+kcp://:$PORT

					[Install]
					WantedBy=multi-user.target
					EOF

				systemctl daemon-reload
				systemctl start gost-server.service
				systemctl enable gost-server.service
				;;

            3)
                echo ""
                echo "Bridge server IP V4?"
                until [[ $IPV4_REV_SSH =~ $IPV4_REGEX ]]; do
                    read -rp "IP V4: " IPV4_REV_SSH
                done

                echo ""
                echo "Bridge server username?"
                until [[ "$USERNAME_REV_SSH" != "" ]]; do
                    read -rp "Username: " USERNAME_REV_SSH
                done

                ssh-keygen -b 2048 -t rsa -f ~/.ssh/id_rsa_"$IPV4_REV_SSH" -q -N ""

                ssh-copy-id -i ~/.ssh/id_rsa_"$IPV4_REV_SSH".pub -o "StrictHostKeyChecking no" "$USERNAME_REV_SSH"@"$IPV4_REV_SSH"
                if [[ "$?" = "0" ]];then
                    echo -e "${GREEN}SSH key successfully copied.${ENDCOLOR}"
                else
                    echo -e "${RED}SSH key copy failed${ENDCOLOR}"
                    exit 1
                fi

                # Only this line will be run on the bridge server
                ssh -i ~/.ssh/id_rsa_"$IPV4_REV_SSH" "$USERNAME_REV_SSH"@"$IPV4_REV_SSH" "echo \"GatewayPorts yes\" >> /etc/ssh/sshd_config;systemctl restart sshd.service"

                cat <<- EOF >/etc/systemd/system/reverse-ssh-tunnel@.service
					[Unit]
					Description=Reverse SSH Tunnel Port %I
					After=network-online.target

					[Service]
					Type=simple
					ExecStart=ssh -i ~/.ssh/id_rsa_$IPV4_REV_SSH -N -R 0.0.0.0:%i:localhost:%i $USERNAME_REV_SSH@$IPV4_REV_SSH
					Restart=on-failure
					RestartSec=10

					[Install]
					WantedBy=multi-user.target
					EOF

                Port_Prompt
                systemctl daemon-reload
                systemctl start reverse-ssh-tunnel@"$PORT"
                systemctl enable reverse-ssh-tunnel@"$PORT"
                ;;
			
                4)
                    if [[ $OS =~ (debian|ubuntu) ]]; then
                        apt install -y wget openjdk-11-jre-headless
                    elif [[ $OS == 'centos' ]]; then
                        dnf install -y wget java-11-openjdk-devel  #TODO: Check jdk installation
                    fi

                    cd /tmp || exit
                    wget https://github.com/ghostunnel/ghostunnel/releases/download/v1.7.1/ghostunnel-linux-amd64
                    
                    chmod +x ghostunnel-linux-amd64
                    mv ghostunnel-linux-amd64 /usr/bin/ghostunnel

                    mkdir /etc/ghostunnel
                    cd /etc/ghostunnel || exit

                    mkdir /etc/ghostunnel/certs




                    cd /etc/ghostunnel/certs || exit

                    IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
                    if [[ -z "$IP" ]]; then
                        echo -e "${RED}Can not detect ip address${ENDCOLOR}"
                        exit 50
                    fi

                    keytool \
                        -keystore server.jks  -storepass protected  -deststoretype pkcs12 \
                        -genkeypair -keyalg RSA -validity 365 \
                        -dname "CN=$IP" \
                        -ext "SAN=IP:$IP"
                    
                    openssl pkcs12 -in server.jks -nodes -nocerts -out serverkey.pem -password pass:protected

                    openssl pkcs12 -in server.jks -nokeys -out servercert.pem -password pass:protected

                    Port_Prompt

					cat <<- EOF >>/etc/ghostunnel/ghostunnel.conf
						LISTEN_IP=0.0.0.0
						LISTEN_PORT=$PORT
						TARGET_IP=localhost
						TARGET_PORT=$PORT
						KEY_PATH=/etc/ghostunnel/certs/serverkey.pem
						CERT_PATH=/etc/ghostunnel/certs/servercert.pem
						CACERT_PATH=/etc/ghostunnel/certs/clientcert.pem
						EOF

                    # TODO: may change port at '--listen 0.0.0.0:$PORT' argument
                    cat <<- EOF >/etc/systemd/system/ghostunnel-server.service
						[Unit]
						Description=Ghostunnel - Server
						After=network.target
						Wants=network.target

						[Service]
						Type=simple
						EnvironmentFile=/etc/ghostunnel/ghostunnel.conf
						ExecStart=/usr/bin/ghostunnel server \
						--listen \${LISTEN_IP}:\${LISTEN_PORT} \
						--target \${TARGET_IP}:\${TARGET_PORT} \
						--key=\${KEY_PATH} \
						--cert=\${CERT_PATH} \
						--cacert=\${CACERT_PATH} --allow-all
						Restart=on-failure
						RestartSec=10

						[Install]
						WantedBy=multi-user.target
						EOF

					echo ""
					echo -e "${BOLDRED}Now you need to copy 'clientcert.pem' from bridge server to this server.${ENDCOLOR}"
					
					systemctl daemon-reload
					systemctl start ghostunnel-server.service
					systemctl enable ghostunnel-server.service

                    ;;
			esac
			;;
		





		#Bridge Server
		2)
			case $TUNNEL_TYPE in
			1)
                if [[ $OS =~ (debian|ubuntu) ]]; then
                    apt install -y wget
                elif [[ $OS == 'centos' ]]; then
                    yum install -y wget
                fi

                cd /tmp/ || exit
                wget -O gost-linux-amd64-2.11.5.gz https://github.com/ginuerzh/gost/releases/download/v2.11.5/gost-linux-amd64-2.11.5.gz
                if [[ "$?" != 0 ]]; then
                    echo -e "${RED}Download was not successfull.${ENDCOLOR}"
                    exit 1
                fi

                gunzip -qq gost-linux-amd64-2.11.5.gz
                
                chmod +x gost-linux-amd64-2.11.5

                mv gost-linux-amd64-2.11.5 /usr/bin/gost

                
				Ip_Port_Prompt

				cat <<- EOF >/etc/systemd/system/gost-client.service
					[Unit]
					Description=Gost with kcp Tunnel - Client
					After=network.target
					Wants=network.target

					[Service]
					Type=simple
					ExecStart=/usr/bin/gost -L tcp://:$LOCAL_PORT_ON_MAIN_SERVER/127.0.0.1:$LOCAL_PORT_ON_MAIN_SERVER -F relay+kcp://$MAIN_SERVER_IP:$MAIN_SERVER_PROXY_PORT

					[Install]
					WantedBy=multi-user.target
					EOF

				systemctl daemon-reload
				systemctl start gost-client.service
				systemctl enable gost-client.service

				;;
			

            2)
				echo ""
                echo "Main server IP V4?"
                until [[ $IPV4_FORWARD_SSH =~ $IPV4_REGEX ]]; do
                    read -rp "IP V4: " IPV4_FORWARD_SSH
                done

                echo ""
                echo "Main server username?"
                until [[ "$USERNAME_FORWARD_SSH" != "" ]]; do
                    read -rp "Username: " USERNAME_FORWARD_SSH
                done

                ssh-keygen -b 2048 -t rsa -f ~/.ssh/id_rsa_"$IPV4_FORWARD_SSH" -q -N ""

                ssh-copy-id -i ~/.ssh/id_rsa_"$IPV4_FORWARD_SSH".pub -o "StrictHostKeyChecking no" "$USERNAME_FORWARD_SSH"@"$IPV4_FORWARD_SSH"
                if [[ "$?" = "0" ]];then
                    echo -e "${GREEN}SSH key successfully copied.${ENDCOLOR}"
                else
                    echo -e "${RED}SSH key copy failed${ENDCOLOR}"
                    exit 1
                fi

				cat <<- EOF >/etc/systemd/system/forward-ssh-tunnel@.service
					[Unit]
					Description=Forward SSH Tunnel Port %I
					After=network-online.target

					[Service]
					Type=simple
					ExecStart=ssh -i ~/.ssh/id_rsa_$IPV4_FORWARD_SSH -N -L 0.0.0.0:%i:localhost:%i $USERNAME_FORWARD_SSH@$IPV4_FORWARD_SSH
					Restart=on-failure
					RestartSec=10

					[Install]
					WantedBy=multi-user.target
					EOF

                Port_Prompt
                systemctl daemon-reload
                systemctl start forward-ssh-tunnel@"$PORT"
                systemctl enable forward-ssh-tunnel@"$PORT"             

                ;;
            
            4)
                if [[ $OS =~ (debian|ubuntu) ]]; then
                    apt install -y wget openjdk-11-jre-headless
                elif [[ $OS == 'centos' ]]; then
                    dnf install -y wget java-11-openjdk-devel  #TODO: Check jdk installation
                fi

                cd /tmp || exit
                wget https://github.com/ghostunnel/ghostunnel/releases/download/v1.7.1/ghostunnel-linux-amd64
                
                chmod +x ghostunnel-linux-amd64
                mv ghostunnel-linux-amd64 /usr/bin/ghostunnel

                mkdir /etc/ghostunnel
                cd /etc/ghostunnel || exit

                mkdir /etc/ghostunnel/certs




                cd /etc/ghostunnel/certs || exit

                IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
                if [[ -z "$IP" ]]; then
                    echo -e "${RED}Can not detect ip address${ENDCOLOR}"
                    exit 50
                fi

                keytool \
                    -keystore client.jks  -storepass protected  -deststoretype pkcs12 \
                    -genkeypair -keyalg RSA -validity 365 \
                    -dname "CN=$IP" \
                    -ext "SAN=IP:$IP"

                openssl pkcs12 -in client.jks -nodes -nocerts -out clientkey.pem -password pass:protected

                openssl pkcs12 -in client.jks -nokeys -out clientcert.pem -password pass:protected

                Ip_Port_Prompt

				cat <<- EOF >>/etc/ghostunnel/ghostunnel.conf
					LISTEN_IP=localhost
					LISTEN_PORT=$LOCAL_PORT_ON_MAIN_SERVER
					TARGET_IP=$MAIN_SERVER_IP
					TARGET_PORT=$MAIN_SERVER_PROXY_PORT
					KEY_PATH=/etc/ghostunnel/certs/clientkey.pem
					CERT_PATH=/etc/ghostunnel/certs/clientcert.pem
					CACERT_PATH=/etc/ghostunnel/certs/servercert.pem
					EOF

                cat <<- EOF >/etc/systemd/system/ghostunnel-client.service
					[Unit]
					Description=Ghostunnel - Client
					After=network.target
					Wants=network.target

					[Service]
					Type=simple
					ExecStart=/usr/bin/ghostunnel client \
					--listen \${LISTEN_IP}:\${LISTEN_PORT} \
					--target \${TARGET_IP}:\${TARGET_PORT} \
					--key=\${KEY_PATH} \
					--cert=\${CERT_PATH} \
					--cacert=\${CACERT_PATH}

					Restart=on-failure
					RestartSec=10

					[Install]
					WantedBy=multi-user.target
					EOF

                systemctl daemon-reload
				systemctl start ghostunnel-client.service
				systemctl enable ghostunnel-client.service
                ;;
            
            esac
            ;;

	esac
}


set_colors
set_vars

checkOS
Detect_Country
Setup_Tunnel