#!/bin/bash
set -e
source ~/.openrc
admin_id=`keystone user-list |grep admin |awk '{print $2}'`
keystone user-password-update --pass infoblox $admin_id
sed -i "s/OS_PASSWORD=.*/export OS_PASSWORD=infoblox/" ~/.openrc
source ~/.openrc

cd /root/
Tempest_Master=/root/tempest-infoblox/
Tempest_dir=/root/tempest/

if [ ! -d $Tempest_Master ]; then
    git clone http://10.35.144.201:8080/tempest-infoblox
fi

if [ ! -d $Tempest_dir ]; then
     git clone https://github.com/openstack/tempest.git
     ## latest code has issue with floating IP scenario8
     ## creating of admin netowrk with admin privileges not allowing inside the scenarios tests
     ## hence as a work around using the oct-14 commit branch
     cd $Tempest_dir
     git checkout 308640c1121f5a4ca33c7723397457e2288c212e
fi
cp $Tempest_Master/infoblox_tempest.conf $Tempest_dir/etc/tempest.conf

source ~/.openrc
IP=`ifconfig br-fixed | sed -n 2p |cut -d ':' -f2|awk '{print $1}'`
image_ref=`glance image-list 2> /dev/null  |grep cirros | awk '{print $2}'`
echo $image_ref
Tempest_Conf=/root/tempest/etc/tempest.conf
#IP=10.39.12.190
echo $Tempest_Conf
##Update urls
sed -i '/ec2_url=/c\ec2_url=http://'$IP'/services/Cloud' $Tempest_Conf
sed -i '/s3_url=/c\s3_url=http://'$IP':8080'  $Tempest_Conf
sed -i '/dashboard_url=/c\dashboard_url=http://'$IP'/'  $Tempest_Conf
sed -i '/login_url=/c\login_url=http://'$IP'/auth/login/'  $Tempest_Conf
sed -i '/uri=/c\uri=http://'$IP':5000/v2.0/'  $Tempest_Conf
sed -i '/uri_v3=/c\uri_v3=http://'$IP':5000/v3/'  $Tempest_Conf
sed -i 's/image_ref=.*-.*/image_ref='$image_ref'/' $Tempest_Conf

### copy infoblox tempest into thirdparty 

mkdir -p $Tempest_dir/tempest/thirdparty/infoblox
touch $Tempest_dir/tempest/thirdparty/infoblox/__init__.py
cp -a $Tempest_Master/scenarios $Tempest_dir/tempest/thirdparty/infoblox/
mv $Tempest_dir/tempest/thirdparty/infoblox/scenarios/base_suse.py $Tempest_dir/tempest/thirdparty/infoblox/scenarios/base.py

## Installing Dependencies to run tempest
zypper --non-interactive install python-testtools
zypper --non-interactive install python-unittest2
zypper --non-interactive install python-fixtures
zypper --non-interactive install python-testscenarios
easy_install discover
easy_install testresources
easy_install nose
