# To begin with, update and upgrade your system packages;
apt update
apt upgrade

# create gvm system user account.
useradd -r -d /opt/gvm -c "GVM User" -s /bin/bash gvm

# Create the GVM user directory as specified by option -d in the command above and set the user and group ownership to gvm.
mkdir /opt/gvm

chown gvm: /opt/gvm

# Install Required Build Tools

apt install gcc g++ make bison flex libksba-dev curl redis libpcap-dev \
cmake git pkg-config libglib2.0-dev libgpgme-dev nmap libgnutls28-dev uuid-dev \
libssh-gcrypt-dev libldap2-dev gnutls-bin libmicrohttpd-dev libhiredis-dev \
zlib1g-dev libxml2-dev libradcli-dev clang-format libldap2-dev doxygen \
gcc-mingw-w64 xml-twig-tools libical-dev perl-base heimdal-dev libpopt-dev \
libsnmp-dev python3-setuptools python3-paramiko python3-lxml python3-defusedxml python3-dev gettext python3-polib xmltoman \
python3-pip texlive-fonts-recommended texlive-latex-extra --no-install-recommends xsltproc libunistring-dev

# Yarn JavaScript package manager
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
apt update
apt install yarn -y

# Install PostgreSQL on Ubuntu 20.04
apt install postgresql postgresql-contrib postgresql-server-dev-all

# Create PostgreSQL User and Database
sudo -Hiu postgres
createuser gvm
createdb -O gvm gvmd

# Grant PostgreSQL User DBA Roles
psql gvmd
create role dba with superuser noinherit;
grant dba to gvm;
create extension "uuid-ossp";
create extension "pgcrypto";
\q
exit

# restart PostgreSQL
systemctl restart postgresql
systemctl enable postgresql

# Update the PATH environment variable on /etc/environment, to include the GVM binary path such that it looks like;
nano /etc/environment
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin"
# Add GVM library path to /etc/ld.so.conf.d
echo "/opt/gvm/lib" > /etc/ld.so.conf.d/gvm.conf

# Switch to GVM user, gvm and create a temporary directory to store GVM source files.
su - gvm
mkdir gvm-source

# Download GVM 20.08 Source Files
cd gvm-source

git clone -b stable https://github.com/greenbone/gvm-libs.git &&
git clone -b main https://github.com/greenbone/openvas-smb.git &&
git clone -b stable https://github.com/greenbone/openvas.git &&
git clone -b stable https://github.com/greenbone/ospd.git &&
git clone -b stable https://github.com/greenbone/ospd-openvas.git &&
git clone -b stable https://github.com/greenbone/gvmd.git &&
git clone -b stable https://github.com/greenbone/gsa.git

# Note the current working directory;
pwd
/opt/gvm/gvm-source
ls -1
gsa
gvmd
gvm-libs
openvas
openvas-smb
ospd
ospd-openvas

# Note that we will install all GVM 20.08 files and libraries to a non-standard location, /opt/gvm.
# As such, you need to set the PKG_CONFIG_PATH environment variable to the location of your pkg-config
# files before configuring:
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH
# Be sure to replace the path, /opt/gvm, accordingly.

# Build and Install GVM 11 Libraries
# From within the source directory, /opt/gvm/gvm-source, in this setup, change to GVM libraries directory;
cd gvm-libs
# Make and change to build directory
mkdir build
cd build

# Configure the build;
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/gvm

# compile and install GVM libraries
make
make install

# Build and Install OpenVAS scanner and OpenVAS SMB
# OpenVAS SMB provides modules for the OpenVAS Scanner to interface with Microsoft Windows Systems through the Windows
# Management Instrumentation API and a winexe binary to execute processes remotely on that system.
# Build and install openvas-smb
cd ../../openvas-smb/
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/gvm
make
make install

cd ../../openvas

# Proceed to build and install openvas.
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/gvm
make
make install

# Configuring OpenVAS Scanner
# The host scan information is stored temporarily on Redis server.
# The default configuration of Redis server is /etc/redis/redis.conf.

# Switch back to privileged user and proceed.
exit

# To begin run the command below to create the cache to the installed shared libraries;
ldconfig

# Next, copy OpenVAS scanner Redis configuration file, redis-openvas.conf, to the same Redis config directory;
cp /opt/gvm/gvm-source/openvas/config/redis-openvas.conf /etc/redis/

# Update the ownership of the configuration.
chown redis:redis /etc/redis/redis-openvas.conf

# Update the path to Redis unix socket on the /opt/gvm/etc/openvas/openvas.conf using the db_address parameter as follows;
echo "db_address = /run/redis-openvas/redis.sock" > /opt/gvm/etc/openvas/openvas.conf

# Note, the Unix socket path is defined on /etc/redis/redis-openvas.conf file.
chown gvm:gvm /opt/gvm/etc/openvas/openvas.conf

# Add gvm user to redis group;
usermod -aG redis gvm

# You can also optimize Redis server itself improve the performance by making the following adjustments;
# Increase the value of somaxconn in order to avoid slow clients connections issues.
echo "net.core.somaxconn = 1024" >> /etc/sysctl.conf

# Redis background save may fail under low memory condition. To avoid this, enable memory overcommit (man 5 proc).
echo 'vm.overcommit_memory = 1' >> /etc/sysctl.conf

# Reload sysctl variables created above.
sysctl -p

# To avoid creation of latencies and memory usage issues with Redis, disable Linux Kernel’s support for
# Transparent Huge Pages (THP). To easily work around this, create a systemd service unit for this purpose.
nano /etc/systemd/system/disable_thp.service

[Unit]
Description=Disable Kernel Support for Transparent Huge Pages (THP)

[Service]
Type=simple
ExecStart=/bin/sh -c "echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled && echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag"

[Install]
WantedBy=multi-user.target

# Reload systemd configurations;
systemctl daemon-reload

#Start and enable this service to run on system boot.
systemctl enable --now disable_thp

# Restart OpenVAS Redis server
systemctl enable --now redis-server@openvas

# A number of Network Vulnerability Tests (NVTs) require root privileges to perform certain operations.
# Since openvas is launched from an ospd-openvas process, via sudo, add the line below to sudoers file to ensure
# that the gvm user used in this demo can run the openvas with elevated rights using passwordless sudo.
echo "gvm ALL = NOPASSWD: /opt/gvm/sbin/openvas" > /etc/sudoers.d/gvm

# Also, update the secure_path to include the GVM /sbin paths, /opt/gvm/sbin.
visudo
Defaults
secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin:/opt/gvm/sbin"

# Also, enable gvm user to run GSA web application daemon, gsad, with passwordless sudo.
echo "gvm ALL = NOPASSWD: /opt/gvm/sbin/gsad" >> /etc/sudoers.d/gvm

Update NVTs
Update Network Vulnerability Tests feed from Greenbone Security Feed/Community Feed using the greenbone-nvt-sync command.

The greenbone-nvt-sync command must not be executed as privileged user root, hence switch back to GVM user we created above and update the NVTs.

su - gvm

# Next, update the NVTs as openvas user;
greenbone-nvt-sync

# Once the update is done, you need to update Redis server with the same VT info from VT files;
sudo openvas --update-vt-info

# Build and Install Greenbone Vulnerability Manager
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH

cd gvm-source/gvmd
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/gvm
make
make install

# Build and Install Greenbone Security Assistant
cd ../../gsa
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/gvm
make
make install


# Keeping the feeds up-to-date
# The gvmd Data, SCAP and CERT Feeds should be kept up-to-date by calling the greenbone-feed-sync script regularly (e.g. via a cron entry):
sudo -Hiu gvm greenbone-feed-sync --type GVMD_DATA
sudo -Hiu gvm greenbone-feed-sync --type SCAP
sudo -Hiu gvm greenbone-feed-sync --type CERT

# Please note: The CERT feed sync depends on data provided by the SCAP feed and
# should be called after syncing the later.
# Consider setting cron jobs to run the nvts, cert and scap data update scripts at your preferred frequency to pull
# updates from the feed servers.
# Next, run the command below to generate certificates gvmd. Server certificates are used for authentication while
# client certificates are primarily used for authorization. More on man gvm-manage-certs.
gvm-manage-certs -a

# Build and Install OSPd and OSPd-OpenVAS
# Open Scanner Protocol (OSP) creates a unified interface for different security scanners and makes their control
# flow and scan results consistently available under the central Greenbone Vulnerability Manager service.
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH
cd /opt/gvm/gvm-source/ospd
python3 setup.py install --prefix=/opt/gvm
cd /opt/gvm/gvm-source/ospd-openvas
python3 setup.py install --prefix=/opt/gvm

# Running OpenVAS Scanner, GSA and GVM services
# In order to make the management of OpenVAS scanner, GSA (WebUI service) and GVM daemon, create systemd service unit files for each of them as follows.

# Log out as gvm user and execute the commands below as a privileged user.
exit

# Creating Systemd Service units for GVM services
# Create OpenVAS systemd service
cat > /etc/systemd/system/openvas.service << 'EOL'
[Unit]
Description=Control the OpenVAS service
After=redis.service
After=postgresql.service

[Service]
ExecStartPre=-rm -rf /opt/gvm/var/run/ospd-openvas.pid /opt/gvm/var/run/ospd.sock /opt/gvm/var/run/gvmd.sock
Type=simple
User=gvm
Group=gvm
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin
Environment=PYTHONPATH=/opt/gvm/lib/python3.8/site-packages
ExecStart=/usr/bin/python3 /opt/gvm/bin/ospd-openvas \
--pid-file /opt/gvm/var/run/ospd-openvas.pid \
--log-file /opt/gvm/var/log/gvm/ospd-openvas.log \
--lock-file-dir /opt/gvm/var/run -u /opt/gvm/var/run/ospd.sock
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd service unit configurations.
systemctl daemon-reload
systemctl start openvas

# Check the status of the service;
systemctl status openvas
● openvas.service - Control the OpenVAS service
     Loaded: loaded (/etc/systemd/system/openvas.service; disabled; vendor preset: enabled)
     Active: active (exited) since Mon 2021-02-08 18:26:16 UTC; 5s ago
    Process: 9395 ExecStartPre=/usr/bin/rm -rf /opt/gvm/var/run/ospd-openvas.pid /opt/gvm/var/run/ospd.sock /opt/gvm/var/run/gvmd.sock (code=exited, status=0/SUCCESS)
    Process: 9402 ExecStart=/usr/bin/python3 /opt/gvm/bin/ospd-openvas --pid-file /opt/gvm/var/run/ospd-openvas.pid --log-file /opt/gvm/var/log/gvm/ospd-openvas.log --lock>
   Main PID: 9402 (code=exited, status=0/SUCCESS)
      Tasks: 4 (limit: 3486)
     Memory: 25.1M
     CGroup: /system.slice/openvas.service
             ├─9406 /usr/bin/python3 /opt/gvm/bin/ospd-openvas --pid-file /opt/gvm/var/run/ospd-openvas.pid --log-file /opt/gvm/var/log/gvm/ospd-openvas.log --lock-file-di>
             └─9408 /usr/bin/python3 /opt/gvm/bin/ospd-openvas --pid-file /opt/gvm/var/run/ospd-openvas.pid --log-file /opt/gvm/var/log/gvm/ospd-openvas.log --lock-file-di>

Feb 08 18:26:16 ubuntu20 systemd[1]: Starting Control the OpenVAS service...
Feb 08 18:26:16 ubuntu20 systemd[1]: Started Control the OpenVAS service.

# Enable OpenVAS scanner to run on system boot;
systemctl enable openvas

# Create GSA systemd service Unit file
cat > /etc/systemd/system/gsa.service << 'EOL'
[Unit]
Description=Control the OpenVAS GSA service
After=openvas.service

[Service]
Type=simple
User=gvm
Group=gvm
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin
Environment=PYTHONPATH=/opt/gvm/lib/python3.8/site-packages
ExecStart=/usr/bin/sudo /opt/gvm/sbin/gsad
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOL

cat >  /etc/systemd/system/gsa.path << 'EOL'
[Unit]
Description=Start the OpenVAS GSA service when gvmd.sock is available

[Path]
PathChanged=/opt/gvm/var/run/gvmd.sock
Unit=gsa.service

[Install]
WantedBy=multi-user.target
EOL

# Create GVM Systemd Service unit file
cat > /etc/systemd/system/gvm.service << 'EOL'
[Unit]
Description=Control the OpenVAS GVM service
After=openvas.service

[Service]
Type=simple
User=gvm
Group=gvm
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin
Environment=PYTHONPATH=/opt/gvm/lib/python3.8/site-packages
ExecStart=/opt/gvm/sbin/gvmd --osp-vt-update=/opt/gvm/var/run/ospd.sock
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOL
cat > /etc/systemd/system/gvm.path << 'EOL'
[Unit]
Description=Start the OpenVAS GVM service when opsd.sock is available

[Path]
PathChanged=/opt/gvm/var/run/ospd.sock
Unit=gvm.service

[Install]
WantedBy=multi-user.target
EOL

# Reload system unit configs and start the services;
systemctl daemon-reload
systemctl enable --now gvm.{path,service}
systemctl enable --now gsa.{path,service}

# Checking the status;
systemctl status gvm.{path,service}

● gvm.path - Start the OpenVAS GVM service when opsd.sock is available
     Loaded: loaded (/etc/systemd/system/gvm.path; enabled; vendor preset: enabled)
     Active: active (waiting) since Mon 2021-02-08 18:35:51 UTC; 1min 50s ago
   Triggers: ● gvm.service

# Feb 08 18:35:51 ubuntu20 systemd[1]: Started Start the OpenVAS GVM service when opsd.sock is available.

● gvm.service - Control the OpenVAS GVM service
     Loaded: loaded (/etc/systemd/system/gvm.service; enabled; vendor preset: enabled)
     Active: active (exited) since Mon 2021-02-08 18:35:51 UTC; 1min 50s ago
TriggeredBy: ● gvm.path
   Main PID: 9717 (code=exited, status=0/SUCCESS)
      Tasks: 5 (limit: 3486)
     Memory: 1.1G
     CGroup: /system.slice/gvm.service
             ├─9745 gvmd: Waiting for incoming connections
             ├─9807 gpg-agent --homedir /opt/gvm/var/lib/gvm/gvmd/gnupg --use-standard-socket --daemon
             ├─9816 gvmd: Reloading NVTs
             ├─9817 gvmd: Syncing SCAP: Updating CPEs
             └─9818 gvmd: OSP: Updating NVT cache

# Feb 08 18:35:51 ubuntu20 systemd[1]: Started Control the OpenVAS GVM service.
systemctl status gsa.{path,service}
● gsa.path - Start the OpenVAS GSA service when gvmd.sock is available
     Loaded: loaded (/etc/systemd/system/gsa.path; enabled; vendor preset: enabled)
     Active: active (running) since Mon 2021-02-08 18:35:52 UTC; 1min 53s ago
   Triggers: ● gsa.service

# Feb 08 18:35:52 ubuntu20 systemd[1]: Started Start the OpenVAS GSA service when gvmd.sock is available.
● gsa.service - Control the OpenVAS GSA service
     Loaded: loaded (/etc/systemd/system/gsa.service; enabled; vendor preset: enabled)
     Active: active (exited) since Mon 2021-02-08 18:30:37 UTC; 7min ago
TriggeredBy: ● gsa.path
   Main PID: 9533 (code=exited, status=0/SUCCESS)
      Tasks: 4 (limit: 3486)
     Memory: 3.2M
     CGroup: /system.slice/gsa.service
             ├─9552 /opt/gvm/sbin/gsad
             └─9553 /opt/gvm/sbin/gsad

# Feb 08 18:30:37 ubuntu20 systemd[1]: Started Control the OpenVAS GSA service.
# Feb 08 18:30:37 ubuntu20 sudo[9533]:      gvm : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/opt/gvm/sbin/gsad
# Feb 08 18:30:37 ubuntu20 sudo[9533]: pam_unix(sudo:session): session opened for user root by (uid=0)
# Feb 08 18:30:37 ubuntu20 sudo[9544]: Oops, secure memory pool already initialized
# Feb 08 18:30:37 ubuntu20 sudo[9533]: pam_unix(sudo:session): session closed for user root

# Create GVM Scanner
  #Since we launched the scanner and set it to use our non-standard scanner host path (/opt/gvm/var/run/ospd.sock),
  # we need to create and register our scanner;
sudo -Hiu gvm gvmd --create-scanner="Kifarunix-demo OpenVAS Scanner" --scanner-type="OpenVAS" --scanner-host=/opt/gvm/var/run/ospd.sock

# Next, you need to verify your scanner. For this, you first need to get the scanner identifier;
sudo -Hiu gvm gvmd --get-scanners
08b69003-5fc2-4037-a479-93b440211c73  OpenVAS  /var/run/ospd/ospd.sock  0  OpenVAS Default
6acd0832-df90-11e4-b9d5-28d24461215b  CVE    0  CVE
50afbf2b-d854-4b6d-879f-c62aa62254d2  OpenVAS  /opt/gvm/var/run/ospd.sock  9390  Kifarunix-demo OpenVAS Scanner

# Based on the output above, our scanner UUID is, 50afbf2b-d854-4b6d-879f-c62aa62254d2
# Verify the scanner;
sudo -Hiu gvm gvmd --verify-scanner=50afbf2b-d854-4b6d-879f-c62aa62254d2

# Command output;
Scanner version: OpenVAS 20.8.2.

# Create OpenVAS (GVM) Admin User
# Create OpenVAS administrative user by running the command below;
sudo -Hiu gvm gvmd --create-user admin

# This command generates a random password for the user. See sample output below;
User created with password 'fee42e66-117c-42f8-9b48-429e51194a13'.

# If you want to create a user and at the same time create your own password;
sudo -Hiu gvm gvmd --create-user gvmadmin --password=StronGP@SS
# Otherwise, you can reset the password of an already existing user;
sudo -Hiu gvm gvmd --user=<USERNAME> --new-password=<PASSWORD>

# An administrator user can later create further users or administrators via clients like the Greenbone Security Assistant (GSA).

# Set the Feed Import Owner
# According to gvmd/INSTALL.md, certain resources that were previously part of the gvmd source code are now
# shipped via the feed. An example is the config “Full and Fast”.
# gvmd will only create these resources if a “Feed Import Owner” is configured:
sudo -Hiu gvm gvmd --modify-setting 78eceaec-3385-11ea-b237-28d24461215b --value <uuid_of_user>

# The UUIDs of all created users can be found using
sudo -Hiu gvm gvmd --get-users --verbose

# Sample output;
admin 9a9e5070-d2f0-4802-971e-c9d61e682c21

# Then modify the gvmd settings with the user UUID.
sudo -Hiu gvm gvmd --modify-setting 78eceaec-3385-11ea-b237-28d24461215b --value 9a9e5070-d2f0-4802-971e-c9d61e682c21

# GVM Log Files
# Various Log files are located under the /opt/gvm/var/log/gvm directory.
ls /opt/gvm/var/log/gvm
gsad.log  gvmd.log  openvas.log  ospd-openvas.log

# Accessing GVM 20.08 (OpenVAS)
# Greenbone Security Assistant (GSA) WebUI daemon opens port 443 and listens on all interfaces.
# If firewall is running, open this port to allow external access.
ufw allow 443/tcp
# You can now access GSA via the url https:<serverIP-OR-hostname>. Accept the self-signed SSL warning and proceed.
# Ref: https://kifarunix.com/install-and-setup-gvm-20-08-on-ubuntu/
