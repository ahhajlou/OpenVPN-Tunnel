#!/bin/bash

apt update

apt dist-upgrade -y

apt install -y apache2

a2dissite 000-default.conf

systemctl stop apache2

apt install -y mariadb-server

mysql_secure_installation

systemctl stop mariadb

apt install -y php libapache2-mod-php php-mysql php-zip php-mbstring php-cli php-common php-curl

apt install -y php-gd php-db php-mail php-mail-mime



apt install -y git
cd /var/www/ || exit
git clone https://github.com/lirantal/daloradius.git

cat <<EOF > /etc/apache2/ports.conf
Listen 80
Listen 8000

<IfModule ssl_module>
    Listen 443
</IfModule>

<IfModule mod_gnutls.c>
    Listen 443
</IfModule>
EOF

cat <<EOF > /etc/apache2/sites-available/operators.conf
<VirtualHost *:8000>
    ServerAdmin operators@localhost
    DocumentRoot /var/www/daloradius/app/operators

    <Directory /var/www/daloradius/app/operators>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    <Directory /var/www/daloradius>
        Require all denied
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/daloradius/operators/error.log
    CustomLog \${APACHE_LOG_DIR}/daloradius/operators/access.log combined
</VirtualHost>
EOF

cat <<EOF > /etc/apache2/sites-available/users.conf
<VirtualHost *:80>
    ServerAdmin users@localhost
    DocumentRoot /var/www/daloradius/app/users

    <Directory /var/www/daloradius/app/users>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    <Directory /var/www/daloradius>
        Require all denied
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/daloradius/users/error.log
    CustomLog \${APACHE_LOG_DIR}/daloradius/users/access.log combined
</VirtualHost>
EOF

mkdir -p /var/log/apache2/daloradius/{operators,users}

a2ensite users.conf operators.conf

systemctl enable mariadb
systemctl restart mariadb

mysql -u root -p -e "CREATE DATABASE raddb;"
mysql -u root -p -e "CREATE USER 'raduser'@'localhost' IDENTIFIED BY 'radpass';"
mysql -u root -p -e "GRANT ALL PRIVILEGES ON raddb.* TO 'raduser'@'localhost'";

mysql -u root -p raddb < /var/www/daloradius/contrib/db/fr3-mysql-freeradius.sql
mysql -u root -p raddb < /var/www/daloradius/contrib/db/mysql-daloradius.sql

cd /var/www/daloradius/app/common/includes/ || exit
cp daloradius.conf.php.sample daloradius.conf.php
chown www-data:www-data daloradius.conf.php


cd /var/www/daloradius/ || exit
mkdir -p var/{log,backup}
chown -R www-data:www-data var

systemctl enable apache2
systemctl restart apache2