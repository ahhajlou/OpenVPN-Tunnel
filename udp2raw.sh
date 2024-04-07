#!/bin/bash


function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function DownloadUDP2RAW() {
	cd /tmp || exit
	mkdir udp2raw
	cd udp2raw || exit

	wget https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz
	tar xfz udp2raw_binaries.tar.gz

	chmod +x udp2raw_amd64
	mv udp2raw_amd64 /usr/bin/udp2raw
}


function ServerConfig() {
	until [[ "$MAIN_SERVER_U2R_PORT" != "" ]]; do
		read -r -p "Enter UDP2RAW listening port: " MAIN_SERVER_U2R_PORT
	done

	until [[ "$MAIN_SERVER_LOCAL_PORT" != "" ]]; do
		read -r -p "Enter local port you want to forward to: " MAIN_SERVER_LOCAL_PORT
	done

	until [[ "$UDP2RAW_SECRET" != "" ]]; do
		read -r -p "Enter UDP2RAW secret: " UDP2RAW_SECRET
	done


	cat <<- EOF > /etc/systemd/system/udp2raw-server@.service
	[Unit]
	Description=udp2raw Server
	After=network.target

	[Service]
	Type=simple
	ExecStart=/usr/bin/udp2raw --conf-file /etc/udp2raw/server-%i.conf
	Restart=on-failure

	[Install]
	WantedBy=multi-user.target
	EOF

	mkdir /etc/udp2raw


	cat <<-EOF > /etc/udp2raw/server-"$MAIN_SERVER_LOCAL_PORT".conf
	-s
	# You can add comments like this
	# Comments MUST occupy an entire line
	# Or they will not work as expected
	# Listen address
	-l 0.0.0.0:$MAIN_SERVER_U2R_PORT
	# Remote address
	-r 127.0.0.1:$MAIN_SERVER_LOCAL_PORT
	-a
	-k $UDP2RAW_SECRET
	--raw-mode faketcp
	EOF

	systemctl daemon-reload
	systemctl start udp2raw-server@"$MAIN_SERVER_LOCAL_PORT".service
	systemctl enable udp2raw-server@"$MAIN_SERVER_LOCAL_PORT".service

}

function ClientConfig() {
	until [[ "$MAIN_SERVER_IP" != "" ]]; do
		read -r -p "Enter main server UDP2RAW listening IP: " MAIN_SERVER_IP
	done

	until [[ "$MAIN_SERVER_U2R_PORT" != "" ]]; do
		read -r -p "Enter UDP2RAW listening port: " MAIN_SERVER_U2R_PORT
	done

	until [[ "$UDP2RAW_SECRET" != "" ]]; do
		read -r -p "Enter UDP2RAW secret: " UDP2RAW_SECRET
	done


	until [[ "$CLIENT_LOCAL_PORT" != "" ]]; do
		read -r -p "Enter local port you want to listen and forward to main server: " CLIENT_LOCAL_PORT
	done


	cat <<- EOF > /etc/systemd/system/udp2raw-client@.service
    [Unit]
	Description=udp2raw Client
	After=network.target

	[Service]
	Type=simple
	ExecStart=/usr/bin/udp2raw --conf-file /etc/udp2raw/client-%i.conf
	Restart=on-failure

	[Install]
	WantedBy=multi-user.target
	EOF

	mkdir /etc/udp2raw

	cat <<- EOF > /etc/udp2raw/client-"$CLIENT_LOCAL_PORT".conf
	-c
	# You can add comments like this
	# Comments MUST occupy an entire line
	# Or they will not work as expected
	# Listen address
	-l 127.0.0.1:$CLIENT_LOCAL_PORT
	# Remote address
	-r $MAIN_SERVER_IP:$MAIN_SERVER_U2R_PORT
	-a
	-k $UDP2RAW_SECRET
	--raw-mode faketcp
	EOF

	systemctl daemon-reload
	systemctl start udp2raw-client@"$CLIENT_LOCAL_PORT".service
	systemctl enable udp2raw-client@"$CLIENT_LOCAL_PORT".service
}




function Main() {
	if ! isRoot; then
		echo "Sorry, you need to run this as root"
		exit 1
	fi

	echo ""
	echo "Tunnel type"
	echo "   1) UDP2RAW - Server"
    echo "   2) UDP2RAW - Client"

	until [[ $TUNNEL_TYPE =~ ^[1-2]$ ]]; do
		read -r -p "Choose one option: " TUNNEL_TYPE
	done

	DownloadUDP2RAW

	case $TUNNEL_TYPE in
		1)
			ServerConfig
			;;
		2)
			ClientConfig
			;;
	esac
}


Main